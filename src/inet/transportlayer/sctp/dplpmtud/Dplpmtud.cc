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

#include "Dplpmtud.h"
#include "DplpmtudStateBase.h"
#include "DplpmtudSearchAlgorithmUp.h"
#include "DplpmtudSearchAlgorithmDown.h"
#include "DplpmtudSearchAlgorithmOptUp.h"
#include "DplpmtudSearchAlgorithmBinary.h"
#include "DplpmtudSearchAlgorithmJump.h"

namespace inet {
namespace sctp {

Dplpmtud::Dplpmtud(SctpAssociation *assoc, SctpPathVariables *path, int mtu) { //Path *path, int mtu, int overhead) {
    this->assoc = assoc;
    this->path = path;
    //this->overhead = overhead;
    //doSendProbe = false;
    minPmtu = 0;
    maxPmtu = (1 << 16) - 1;
    readParameters(assoc->getSctpMain());
    determinePmtuBounds(mtu);
    pmtu = minPmtu;
    state = nullptr;
    raiseTimer = nullptr;
    probeTimer = nullptr;
}

Dplpmtud::~Dplpmtud() {
    if (state != nullptr) {
        delete state;
    }
    if (probeTimer != nullptr) {
        stopTimer(probeTimer);
        delete probeTimer;
    }
    if (raiseTimer != nullptr) {
        stopTimer(raiseTimer);
        delete raiseTimer;
    }
}

void Dplpmtud::start() {
    state = new DplpmtudStateBase(this);
}

void Dplpmtud::readParameters(cModule *module)
{
    this->usePtb = module->par("dplpmtudUsePtb");
    this->searchAlgorithm = module->par("dplpmtudSearchAlgorithm").stdstringValue();
}

void Dplpmtud::determinePmtuBounds(int mtu) {
    minPmtu = 0;
    maxPmtu = mtu;

    L3Address remoteAddr = path->remoteAddress;
    if (remoteAddr.getType() == L3Address::IPv4) {
        minPmtu = 1200;
        overhead = 20;
    } else if (remoteAddr.getType() == L3Address::IPv6) {
        minPmtu = 1280;
        overhead = 40;
    } else {
        throw cRuntimeError("Unknown L3Address type");
    }

    if (maxPmtu < minPmtu) {
        throw cRuntimeError("DPLPMTUD: maxPmtu (%d) is smaller than minPmtu (%d).", maxPmtu, minPmtu);
    }

    initialMinPmtu = minPmtu;
    initialMaxPmtu = maxPmtu;
}

int Dplpmtud::getNextLargerPmtu() {
    if (pmtu == maxPmtu) {
        return 0;
    }
    return std::min(pmtu + step, maxPmtu);
}

simtime_t Dplpmtud::getRaiseTimeout() {
    return simTime() + RAISE_TIMEOUT;
}

simtime_t Dplpmtud::getRapidTestTimeout() {
    return simTime() + path->srtt*2;
}

simtime_t Dplpmtud::getProbeTimeout() {
    return simTime() + PROBE_TIMEOUT;
}

DplpmtudSearchAlgorithm *Dplpmtud::createSearchAlgorithm() {
    if (searchAlgorithm == "Up") {
        return new DplpmtudSearchAlgorithmUp(pmtu, maxPmtu, step);
    } else if (searchAlgorithm == "Down") {
        return new DplpmtudSearchAlgorithmDown(pmtu, maxPmtu, step);
    } else if (searchAlgorithm == "OptUp") {
        return new DplpmtudSearchAlgorithmOptUp(pmtu, maxPmtu, step);
    } else if (searchAlgorithm == "Binary") {
        return new DplpmtudSearchAlgorithmBinary(pmtu, maxPmtu, step);
    } else if (searchAlgorithm == "Jump") {
        return new DplpmtudSearchAlgorithmJump(pmtu, maxPmtu, step);
    } else {
        throw cRuntimeError("Unknown DPLPMTUD search algorithm specified");
    }
}

void Dplpmtud::onProbePacketAcked(int quicPacketSize) {
    state = state->onProbeAcked(quicPacketSize + overhead);
}

void Dplpmtud::onProbePacketLost(int quicPacketSize) {
    state = state->onProbeTimeout(quicPacketSize + overhead);
}

void Dplpmtud::onPtbReceived(int quicPacketSize, int ptbMtu) {
    if (!usePtb) {
        return;
    }

    int packetSize = quicPacketSize + overhead;

    if (ptbMtu >= packetSize) {
        EV_WARN << "PTB reports an MTU of " << ptbMtu << " upon a packet that is equal or larger than the size of the packet, which is " << packetSize << ". Ignore PTB." << endl;
        return;
    }

    if (ptbMtu < minPmtu || ptbMtu > maxPmtu) {
        EV_WARN << "PTB reports an MTU that is either smaller than MIN_PMTU or larger than MAX_PMTU. Ignore PTB." << endl;
        return;
    }

    state = state->onPtbReceived(ptbMtu);
}

void Dplpmtud::onProbeTimeout(cMessage *msg) {
    ProbeTimerMessage *probeMsg = check_and_cast<ProbeTimerMessage *>(msg);
    state = state->onProbeTimeout(probeMsg->getProbeSize());
}

void Dplpmtud::onRaiseTimeout() {
    state->onRaiseTimeout();
}

void Dplpmtud::sendProbe(int probeSize) {
    assoc->sendDplpmtudProbe(path, probeSize - overhead);
}

int Dplpmtud::getPlpmtu() {
    return pmtu - overhead;
}

int Dplpmtud::getMinPlpmtu() {
    return minPmtu - overhead;
}

void Dplpmtud::probePacketBuilt() {
    doSendProbe = false;
}

void Dplpmtud::onPmtuInvalid() {
    state = state->onPmtuInvalid();
}

void Dplpmtud::startRaiseTimer() {
    stopTimer(raiseTimer);
    if (raiseTimer == nullptr) {
        char str[128];
        snprintf(str, sizeof(str), "DPLPMTUD_RAISE_TIMER %d:%s", assoc->assocId, path->remoteAddress.str().c_str());
        raiseTimer = new cMessage(str);
        raiseTimer->setContextPointer(assoc);
        SctpPathInfo *pinfo = new SctpPathInfo("pinfo");
        pinfo->setRemoteAddress(path->remoteAddress);
        raiseTimer->setControlInfo(pinfo);
    }
    assoc->startTimer(raiseTimer, RAISE_TIMEOUT);
}

void Dplpmtud::startProbeTimer(int probeSize, bool rapid) {
    stopTimer(probeTimer);
    if (probeTimer == nullptr) {
        char str[128];
        snprintf(str, sizeof(str), "DPLPMTUD_PROBE_TIMER %d:%s", assoc->assocId, path->remoteAddress.str().c_str());
        probeTimer = new ProbeTimerMessage(str);
        probeTimer->setContextPointer(assoc);
        SctpPathInfo *pinfo = new SctpPathInfo("pinfo");
        pinfo->setRemoteAddress(path->remoteAddress);
        probeTimer->setControlInfo(pinfo);
    }
    probeTimer->setProbeSize(probeSize);
    if (rapid) {
        assoc->startTimer(probeTimer, path->srtt*2);
    } else {
        assoc->startTimer(probeTimer, PROBE_TIMEOUT);
    }
}

void Dplpmtud::stopTimer(cMessage *timer) {
    if (timer == nullptr) {
        return;
    }
    assoc->stopTimer(timer);
}

void Dplpmtud::stopRaiseTimer() {
    stopTimer(raiseTimer);
}

void Dplpmtud::stopProbeTimer() {
    stopTimer(probeTimer);
}

void Dplpmtud::setPmtu(int pmtu) {
    this->pmtu = pmtu;
    assoc->setPmtu(path, pmtu);
}

} /* namespace sctp */
} /* namespace inet */
