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

#ifndef INET_TRANSPORTLAYER_QUIC_PMTUVALIDATOR_H_
#define INET_TRANSPORTLAYER_QUIC_PMTUVALIDATOR_H_

#include "dplpmtud/Dplpmtud.h"
#include "SctpAssociation.h"

namespace inet {
namespace sctp {

class Dplpmtud;
class SctpPathVariables;

struct timeSize {
    SimTime at;
    int size;
};

struct packetInfo {
    SimTime sentTime;
    int size;
    std::vector<uint32_t> containedTsns;
};

class PmtuValidator {
public:
    PmtuValidator(SctpPathVariables *path);
    virtual ~PmtuValidator();

    void onDataPacketSent(const Ptr<SctpHeader>& sctpPacket);
    void onDataPacketSent(int sctpPacketSize, std::vector<uint32_t> containedTsns);
    void onChunkAcked(uint32_t tsn);
    void onChunkLost(uint32_t tsn);
    void onChunkAbandoned(uint32_t tsn);
    void onRtxTimeout();

private:
    SctpPathVariables *path;
    std::map<uint32_t, struct packetInfo *> tsnPacketMap;
    std::list<struct timeSize> largestPacketSizeAcked;
    std::list<struct timeSize> lostPacketsBySize;
    SimTime timeLastPmtuInvalid;
    SimTime pmtuInvalidTimeThreshold;

    void onPacketAcked(SimTime sentTime, int sctpPacketSize);
    void onPacketLost(SimTime sentTime, int sctpPacketSize);
    std::list<struct timeSize>::iterator deleteEarlierAndSmallerEntries(std::list<struct timeSize> *list, SimTime sentTime, int sctpPacketSize);
    int largestAckedSince(SimTime since);
    void pmtuInvalid();
    simtime_t getPmtuInvalidTimeThreshold();
    void clearTsnPacketMap();
    void removeTsnInPacketMap(uint32_t tsn, bool lost);

};

} /* namespace quic */
} /* namespace inet */

#endif /* INET_TRANSPORTLAYER_QUIC_PMTUVALIDATOR_H_ */
