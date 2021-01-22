//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include "PmtuValidator.h"

namespace inet {
namespace sctp {

PmtuValidator::PmtuValidator(SctpPathVariables *path) {
    this->path = path;
    timeLastPmtuInvalid = SimTime::ZERO;
}

PmtuValidator::~PmtuValidator() {
    clearTsnPacketMap();
}

void PmtuValidator::onDataPacketSent(const Ptr<SctpHeader>& sctpPacket)
{
    std::vector<uint32_t> containedTsns;
    for (int i = 0; i < sctpPacket->getSctpChunksArraySize(); i++) {
        const SctpChunk *chunk = sctpPacket->getSctpChunks(i);
        if (chunk->getSctpChunkType() == DATA) {
            const SctpDataChunk *dataChunk = check_and_cast<const SctpDataChunk *>(chunk);
            containedTsns.push_back(dataChunk->getTsn());
        }
    }
    if (containedTsns.empty()) {
        // no DATA chunks found
        return;
    }
    int sctpPacketSize = sctpPacket->getHeaderLength();
    onDataPacketSent(sctpPacketSize, containedTsns);
}

void PmtuValidator::onDataPacketSent(int sctpPacketSize, std::vector<uint32_t> containedTsns)
{
    struct packetInfo *pktInfo = new struct packetInfo;
    pktInfo->sentTime = simTime();
    pktInfo->size = sctpPacketSize;
    pktInfo->containedTsns = containedTsns;

    for (uint32_t tsn : containedTsns) {
        tsnPacketMap.insert({tsn, pktInfo});
    }
}

void PmtuValidator::onChunkAcked(uint32_t tsn)
{
    auto it = tsnPacketMap.find(tsn);
    if (it == tsnPacketMap.end()) {
        // not found
        return;
    }
    struct packetInfo *pktInfo = it->second;
    for (uint32_t otherTsn : pktInfo->containedTsns) {
        tsnPacketMap.erase(otherTsn);
    }
    onPacketAcked(pktInfo->sentTime, pktInfo->size);
    delete pktInfo;
}

void PmtuValidator::onChunkLost(uint32_t tsn)
{
    removeTsnInPacketMap(tsn, true);
}

void PmtuValidator::onChunkAbandoned(uint32_t tsn)
{
    removeTsnInPacketMap(tsn, false);
}

void PmtuValidator::removeTsnInPacketMap(uint32_t tsn, bool lost) {
    auto mapIt = tsnPacketMap.find(tsn);
    if (mapIt == tsnPacketMap.end()) {
        // not found
        return;
    }
    struct packetInfo *pktInfo = mapIt->second;
    tsnPacketMap.erase(tsn);
    for (auto tsnIt = pktInfo->containedTsns.begin(); tsnIt != pktInfo->containedTsns.end(); ++tsnIt) {
        if (tsn == *tsnIt) {
            pktInfo->containedTsns.erase(tsnIt);
            break;
        }
    }
    if (pktInfo->containedTsns.empty()) {
        if (lost) {
            onPacketLost(pktInfo->sentTime, pktInfo->size);
        }
        delete pktInfo;
    }
}

void PmtuValidator::clearTsnPacketMap()
{
    std::set<struct packetInfo *> pktInfos;
    for (auto it = tsnPacketMap.begin(); it != tsnPacketMap.end(); ++it) {
        pktInfos.insert(it->second);
    }
    for (auto it = pktInfos.begin(); it != pktInfos.end(); ++it) {
        delete *it;
    }
    tsnPacketMap.clear();
}

void PmtuValidator::onPacketAcked(SimTime sentTime, int sctpPacketSize)
{
    // the acknowledgement of the packet shows that the current PMTU is at least of the size of the acked packet
    // delete all lost packets that are smaller and sent earlier than the acked packet
    deleteEarlierAndSmallerEntries(&lostPacketsBySize, sentTime, sctpPacketSize);

    // to determine the largestAckedSince, information about acked packets sent earlier with a smaller size are unnecessary
    // delete them
    auto it = deleteEarlierAndSmallerEntries(&largestPacketSizeAcked, sentTime, sctpPacketSize);
    // add the current acked packet if there is not already a larger acked packet sent later in the list
    if (it == largestPacketSizeAcked.end() || it->size < sctpPacketSize) {
        // add the current acked packet before it
        struct timeSize ts;
        ts.at = sentTime;
        ts.size = sctpPacketSize;
        largestPacketSizeAcked.insert(it, ts);
    }
}

void PmtuValidator::onPacketLost(SimTime sentTime, int sctpPacketSize)
{
    if (sentTime < timeLastPmtuInvalid) {
        // this lost packet was sent before the last time we invalidated the PMTU -> ignore
        return;
    }

    auto it = lostPacketsBySize.begin();
    // for each other lost packet sent pmtuInvalidTimeThreshold earlier...
    for (; it != lostPacketsBySize.end() && (sentTime - it->at) > getPmtuInvalidTimeThreshold(); it++) {
        if (sctpPacketSize > largestAckedSince(it->at)) {
            // no other packet with a size of one of the two lost packets were acked in the meantime
            // assume that the current PMTU is invalid
            EV_DEBUG << "PmtuValidator: PMTU seems invalid due to the two lost packets sent at " << sentTime << " and " << it->at << endl;
            pmtuInvalid();
            return;
        }
    }

    // find the correct position to add the current lost packet
    for (; it != lostPacketsBySize.end() && it->at < sentTime; it++);
    if (it != lostPacketsBySize.end() && it->at == sentTime) {
        // there is another lost packet sent at the same time, use the larger size of both packets
        if (it->size < sctpPacketSize) {
            it->size = sctpPacketSize;
        }
    } else {
        // add information about this lost packet before it
        struct timeSize ts;
        ts.at = sentTime;
        ts.size = sctpPacketSize;
        lostPacketsBySize.insert(it, ts);
    }
}

void PmtuValidator::onRtxTimeout(SimTime oldestLostSendTime)
{
    if (oldestLostSendTime < timeLastPmtuInvalid) {
        // the expired rtx timer started for a packet sent before the last time we invalidated the PMTU -> ignore
        return;
    }
    EV_DEBUG << "PmtuValidator: PMTU seems invalid due to an expired retransmission timer" << endl;
    pmtuInvalid();
}

simtime_t PmtuValidator::getPmtuInvalidTimeThreshold()
{
    return path->srtt;
}

void PmtuValidator::pmtuInvalid()
{
    clearTsnPacketMap();
    lostPacketsBySize.clear();
    timeLastPmtuInvalid = simTime();
    path->dplpmtud->onPmtuInvalid();
}

/**
 * Delete all entries in list with an earlier sent time and a smaller packet size
 * \param list The list to delete entries from
 * \param packet The reference packet
 * \return The iterator to the first entry with a later time sent
 */
std::list<struct timeSize>::iterator PmtuValidator::deleteEarlierAndSmallerEntries(std::list<struct timeSize> *list, SimTime sentTime, int sctpPacketSize)
{
    auto it = list->begin();
    while (it != list->end() && it->at <= sentTime) {
        if (it->size <= sctpPacketSize) {
            it = list->erase(it);
        } else {
            it++;
        }
    }
    return it;
}

/**
 * \param since The time from when to look for an acked packet size.
 * \return The largest packet size acknowledged since the time given.
 */
int PmtuValidator::largestAckedSince(SimTime since) {
    for (auto it: largestPacketSizeAcked) {
        if (it.at >= since) {
            return it.size;
        }
    }
    return 0;
}

} /* namespace sctp */
} /* namespace inet */
