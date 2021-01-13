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

#include "DplpmtudSearchAlgorithmOptUp.h"

namespace inet {
namespace sctp {

DplpmtudSearchAlgorithmOptUp::DplpmtudSearchAlgorithmOptUp(int minPmtu, int maxPmtu, int stepSize) : DplpmtudSearchAlgorithmUp(minPmtu, maxPmtu, stepSize) {
    optProbe = true;
}
DplpmtudSearchAlgorithmOptUp::~DplpmtudSearchAlgorithmOptUp() { }

int DplpmtudSearchAlgorithmOptUp::getFirstCandidate() {
    return maxPmtu;
}

int DplpmtudSearchAlgorithmOptUp::getSmallerCandidate(int unackedCandidate) {
    if (optProbe) {
        optProbe = false;
        return DplpmtudSearchAlgorithmUp::getFirstCandidate();
    }
    return DplpmtudSearchAlgorithmUp::getSmallerCandidate(unackedCandidate);
}

bool DplpmtudSearchAlgorithmOptUp::doRapidTest() {
    if (optProbe) {
        return true;
    }
    return DplpmtudSearchAlgorithmUp::doRapidTest();
}

void DplpmtudSearchAlgorithmOptUp::ptbReceived(int ptbMtu) {
    optProbe = false;
    DplpmtudSearchAlgorithmUp::ptbReceived(ptbMtu);
}

} /* namespace quic */
} /* namespace inet */
