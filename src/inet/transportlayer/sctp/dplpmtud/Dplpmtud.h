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

#ifndef INET_TRANSPORTLAYER_SCTP_DPLPMTUD_DPLPMTUD_H_
#define INET_TRANSPORTLAYER_SCTP_DPLPMTUD_DPLPMTUD_H_

#include "DplpmtudState.h"
#include "DplpmtudSearchAlgorithm.h"
#include "ProbeTimerMessage_m.h"
#include "../SctpAssociation.h"

namespace inet {
namespace sctp {

class DplpmtudState;
class SctpPathVariables;

class Dplpmtud {
public:
    Dplpmtud(SctpAssociation *assoc, SctpPathVariables *path, int mtu);
    virtual ~Dplpmtud();

    virtual void start();
    virtual int getPlpmtu();
    virtual int getMinPlpmtu();
    virtual void sendProbe(int probeSize);
    virtual void onProbePacketAcked(int quicPacketSize);
    virtual void onProbePacketLost(int quicPacketSize);
    virtual void onProbeTimeout(cMessage *msg);
    virtual void onRaiseTimeout();
    virtual int getNextLargerPmtu();
    virtual simtime_t getRaiseTimeout();
    virtual simtime_t getProbeTimeout();
    virtual simtime_t getRapidTestTimeout();
    virtual DplpmtudSearchAlgorithm *createSearchAlgorithm();
    virtual void probePacketBuilt();
    virtual void onPtbReceived(int quicPacketSize, int ptbMtu);
    virtual void onPmtuInvalid();
    void startRaiseTimer();
    void startProbeTimer(int probeSize, bool rapid);
    void stopTimer(cMessage *timer);
    void stopRaiseTimer();
    void stopProbeTimer();
    void setPmtu(int pmtu);

    SctpPathVariables *getPath() {
        return path;
    }
    int getMinPmtu() {
        return minPmtu;
    }
//    void setMinPmtu(int minPmtu) {
//        this->minPmtu = minPmtu;
//    }
//    void resetMinPmtu() {
//        minPmtu = initialMinPmtu;
//    }
    int getMaxPmtu() {
        return maxPmtu;
    }
    void setMaxPmtu(int maxPmtu) {
        this->maxPmtu = maxPmtu;
    }
    void resetMaxPmtu() {
        maxPmtu = initialMaxPmtu;
    }
    int getPmtu() {
        return pmtu;
    }
    bool needToSendProbe() {
        return doSendProbe;
    }
    int getProbeSize() {
        return probeSize;
    }

    const int MAX_PROBES = 3;

    cMessage *raiseTimer;
    ProbeTimerMessage *probeTimer;

private:
    const int step = 4;
    const simtime_t RAISE_TIMEOUT = SimTime(600, SimTimeUnit::SIMTIME_S);
    const simtime_t PROBE_TIMEOUT = SimTime(1, SimTimeUnit::SIMTIME_S);

    int initialMinPmtu;
    int initialMaxPmtu;
    int minPmtu;
    int maxPmtu;
    int pmtu;
    int overhead;
    int probeSize;
    bool doSendProbe;
    bool usePtb;
    std::string searchAlgorithm;
    DplpmtudState *state;
    SctpPathVariables *path;
    SctpAssociation *assoc;

    void readParameters(cModule *module);
    void determinePmtuBounds(int mtu);
};

} /* namespace sctp */
} /* namespace inet */

#endif /* INET_TRANSPORTLAYER_SCTP_DPLPMTUD_DPLPMTUD_H_ */
