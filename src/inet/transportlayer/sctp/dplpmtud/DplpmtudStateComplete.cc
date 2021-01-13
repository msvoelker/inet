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

#include "DplpmtudStateComplete.h"
#include "DplpmtudStateSearch.h"
#include "DplpmtudStateBase.h"

namespace inet {
namespace sctp {

DplpmtudStateComplete::DplpmtudStateComplete(Dplpmtud *context) : DplpmtudState(context) {
    start();
}
DplpmtudStateComplete::~DplpmtudStateComplete() {
    context->stopRaiseTimer();
}

void DplpmtudStateComplete::start() {
    probedSize = 0;
    context->resetMaxPmtu();
    if (context->getNextLargerPmtu() > 0) {
        EV_DEBUG << "DPLPMTUD in COMPLETE: start RAISE_TIMER" << endl;
        context->startRaiseTimer();
    } else {
        EV_DEBUG << "DPLPMTUD in COMPLETE: no larger PMTU possible, nothing to do" << endl;
    }
}

DplpmtudState *DplpmtudStateComplete::onProbeAcked(int ackedProbeSize) {
    if (ackedProbeSize <= context->getPmtu()) {
        return this;
    }
    context->stopProbeTimer();
    context->setPmtu(ackedProbeSize);
    if (context->getNextLargerPmtu() > 0) {
        //context->setMinPmtu(ackedProbeSize);
        EV_DEBUG << "DPLPMTUD in COMPLETE: probe for " << ackedProbeSize << " acked. Transition to SEARCH." << endl;
        return newState(new DplpmtudStateSearch(context));
    }
    EV_DEBUG << "DPLPMTUD in COMPLETE: probe for " << ackedProbeSize << " acked. No larger candidates left, nothing to do." << endl;
    return this;
}

DplpmtudState *DplpmtudStateComplete::onProbeTimeout(int unackedProbeSize) {
    if (unackedProbeSize != probedSize) {
        return this;
    }
    if (probeCount < context->MAX_PROBES) {
        EV_DEBUG << "DPLPMTUD in COMPLETE: probe for " << unackedProbeSize << " lost. Repeat." << endl;
        sendProbe(probedSize);
    } else {
        probedSize = 0;
        context->startRaiseTimer();
        EV_DEBUG << "DPLPMTUD in COMPLETE: test for " << unackedProbeSize << " failed. RAISE_TIMER rescheduled." << endl;
    }
    return this;
}

DplpmtudState *DplpmtudStateComplete::onPtbReceived(int ptbMtu) {
    EV_DEBUG << "DPLPMTUD in COMPLETE: PTB received" << endl;
    context->stopProbeTimer();

    if (ptbMtu < context->getPmtu()) {
        EV_DEBUG << "DPLPMTUD in COMPLETE: reported MTU is smaller than current PMTU. Go back to BASE." << endl;
        context->setMaxPmtu(ptbMtu);
        return newState(new DplpmtudStateBase(context));
    }

    if (ptbMtu == context->getPmtu()) {
        EV_DEBUG << "DPLPMTUD in COMPLETE: reported MTU confirmed current PMTU. Reschedule RAISE_TIMER." << endl;
        probedSize = 0;
        context->startRaiseTimer();
        return this;
    }

    // ptbMtu > PMTU
    if (probedSize == 0 || ptbMtu >= probedSize) {
        EV_DEBUG << "DPLPMTUD in COMPLETE: no probe outstanding or reported MTU is equal or larger then the current probe size. Ignore PTB." << endl;
        return this;
    }

    // PMTU < ptbMtu < probedSize
    EV_DEBUG << "DPLPMTUD in COMPLETE: use reported MTU as new MAX_MTU and transition to SEARCH." << endl;
    //context->setMinPmtu(context->getPmtu());
    context->setMaxPmtu(ptbMtu);
    return newState(new DplpmtudStateSearch(context));
}

DplpmtudState *DplpmtudStateComplete::onPmtuInvalid() {
    EV_DEBUG << "DPLPMTUD in COMPLETE: PMTU reported invalid. Transition to BASE." << endl;
    return newState(new DplpmtudStateBase(context));
}

void DplpmtudStateComplete::onRaiseTimeout() {
    probedSize = context->getNextLargerPmtu();
    probeCount = 0;
    EV_DEBUG << "DPLPMTUD in COMPLETE: raise timer fired, send probe for " << probedSize << "B" << endl;
    sendProbe(probedSize);
}

} /* namespace quic */
} /* namespace inet */
