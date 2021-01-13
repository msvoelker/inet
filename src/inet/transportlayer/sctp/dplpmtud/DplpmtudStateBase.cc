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

#include "DplpmtudStateBase.h"
#include "DplpmtudStateSearch.h"

namespace inet {
namespace sctp {

DplpmtudStateBase::DplpmtudStateBase(Dplpmtud *context) : DplpmtudState(context) {
    start();
}
DplpmtudStateBase::~DplpmtudStateBase() { }

void DplpmtudStateBase::start() {
    //context->resetMinPmtu();
    base = context->getMinPmtu();
    context->setPmtu(base);
    probeCount = 0;
    EV_DEBUG << "DPLPMTUD in BASE: send probe for " << base << endl;
    sendProbe(base);
}

DplpmtudState *DplpmtudStateBase::onProbeAcked(int ackedProbeSize) {
    if (ackedProbeSize != base) {
        return this;
    }
    EV_DEBUG << "DPLPMTUD in BASE: probe acked, transition to SEARCH " << endl;
    context->stopProbeTimer();
    return newState(new DplpmtudStateSearch(context));
}

DplpmtudState *DplpmtudStateBase::onProbeTimeout(int unackedProbeSize) {
    if (unackedProbeSize != base) {
        return this;
    }
    if (probeCount < context->MAX_PROBES) {
        EV_DEBUG << "DPLPMTUD in BASE: probe lost, repeat. " << endl;
        sendProbe(base);
        return this;
    }

    throw cRuntimeError("DPLPMTUD: Failed to probe in base state");
}

DplpmtudState *DplpmtudStateBase::onPtbReceived(int ptbMtu) {
    EV_DEBUG << "DPLPMTUD in BASE: PTB received" << endl;
    // already in base
    return this;
}

DplpmtudState *DplpmtudStateBase::onPmtuInvalid() {
    return this;
}

void DplpmtudStateBase::onRaiseTimeout() {
    throw cRuntimeError("DPLPMTUD: Raise Timeout in base state should not happen");
    //return this;
}

} /* namespace quic */
} /* namespace inet */
