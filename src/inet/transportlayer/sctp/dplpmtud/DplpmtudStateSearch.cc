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

#include "DplpmtudStateSearch.h"
#include "DplpmtudStateComplete.h"
#include "DplpmtudStateBase.h"

namespace inet {
namespace sctp {

DplpmtudStateSearch::DplpmtudStateSearch(Dplpmtud *context) : DplpmtudState(context) {
    start();
}
DplpmtudStateSearch::~DplpmtudStateSearch() {
    context->stopProbeTimer();
    delete algorithm;
}

void DplpmtudStateSearch::start() {
    algorithm = context->createSearchAlgorithm();
    probedSize = algorithm->getFirstCandidate();
    probeCount = 0;
    EV_DEBUG << "DPLPMTUD in SEARCH: start, send probe for " << probedSize << endl;
    sendProbe(probedSize, algorithm->doRapidTest());
}

DplpmtudState *DplpmtudStateSearch::onProbeAcked(int ackedProbeSize) {
    if (ackedProbeSize != probedSize && ackedProbeSize <= context->getPmtu()) {
        return this;
    }
    EV_DEBUG << "DPLPMTUD in SEARCH: probe for " << ackedProbeSize << "B acked" << endl;
    context->stopProbeTimer();
    context->setPmtu(ackedProbeSize);
    probedSize = algorithm->getLargerCandidate(ackedProbeSize);
    if (probedSize == 0) { // no more candidates to test
        EV_DEBUG << "DPLPMTUD in SEARCH: no more candidates to test, transition to COMPLETE" << endl;
        return newState(new DplpmtudStateComplete(context));
    }
    probeCount = 0;
    EV_DEBUG << "DPLPMTUD in SEARCH: send probe for " << probedSize << "B" << endl;
    sendProbe(probedSize, algorithm->doRapidTest());
    return this;
}

DplpmtudState *DplpmtudStateSearch::onProbeTimeout(int unackedProbeSize) {
    if (unackedProbeSize != probedSize) {
        EV_DEBUG << "DPLPMTUD in SEARCH: probe timeout for " << unackedProbeSize << ", current probeSize is " << probedSize << endl;
        return this;
    }
    EV_DEBUG << "DPLPMTUD in SEARCH: probe for " << probedSize << "B lost." << endl;
    if (probeCount < context->MAX_PROBES && !algorithm->doRapidTest()) {
        EV_DEBUG << "DPLPMTUD in SEARCH: repeat." << endl;
        sendProbe(probedSize, algorithm->doRapidTest());
        return this;
    }
    if (probedSize <= context->getMinPmtu()) {
        throw cRuntimeError("DPLPMTUD: Unable to probe minPmtu in search state");
    }
    probedSize = algorithm->getSmallerCandidate(unackedProbeSize);
    if (probedSize == 0) { // no smaller candidates to test
        EV_DEBUG << "DPLPMTUD in SEARCH: no smaller candidates left. Transition to COMPLETE." << endl;
        return newState(new DplpmtudStateComplete(context));
    }
    probeCount = 0;
    EV_DEBUG << "DPLPMTUD in SEARCH: send probe for " << probedSize << "B" << endl;
    sendProbe(probedSize, algorithm->doRapidTest());
    return this;
}

DplpmtudState *DplpmtudStateSearch::onPtbReceived(int ptbMtu) {
    EV_DEBUG << "DPLPMTUD in SEARCH: PTB received" << endl;
    context->stopProbeTimer();
    if (ptbMtu < context->getPmtu()) {
        EV_DEBUG << "DPLPMTUD in SEARCH: reported MTU is smaller than a previously successful probed size. Go back to BASE." << endl;
        context->setMaxPmtu(ptbMtu);
        return newState(new DplpmtudStateBase(context));
    }

    if (ptbMtu == context->getPmtu()) {
        EV_DEBUG << "DPLPMTUD in SEARCH: reported MTU confirmed current PMTU. Transition to COMPLETE." << endl;
        return newState(new DplpmtudStateComplete(context));
    }

    // PMTU < PTB_MTU < MAX_PMTU
    EV_DEBUG << "DPLPMTUD in SEARCH: use reported MTU for a new probe." << endl;
    // use reported MTU for a new probe
    context->stopProbeTimer();
    context->setMaxPmtu(ptbMtu);
    algorithm->ptbReceived(ptbMtu);
    probedSize = ptbMtu;
    probeCount = 0;
    sendProbe(probedSize, algorithm->doRapidTest());
    return this;
}

DplpmtudState *DplpmtudStateSearch::onPmtuInvalid() {
    return newState(new DplpmtudStateBase(context));
}

void DplpmtudStateSearch::onRaiseTimeout() {
    throw cRuntimeError("DPLPMTUD: Raise Timeout in search state should not happen");
    //return this;
}

} /* namespace quic */
} /* namespace inet */
