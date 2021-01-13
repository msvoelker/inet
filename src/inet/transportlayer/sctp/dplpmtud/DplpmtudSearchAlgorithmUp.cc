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

#include "DplpmtudSearchAlgorithmUp.h"

namespace inet {
namespace sctp {

DplpmtudSearchAlgorithmUp::DplpmtudSearchAlgorithmUp(int minPmtu, int maxPmtu, int stepSize) : DplpmtudSearchAlgorithm(minPmtu, maxPmtu, stepSize) { }
DplpmtudSearchAlgorithmUp::~DplpmtudSearchAlgorithmUp() { }

int DplpmtudSearchAlgorithmUp::getFirstCandidate() {
    return minPmtu;
}

int DplpmtudSearchAlgorithmUp::getLargerCandidate(int ackedCandidate) {
    int next = ackedCandidate + stepSize;
    if (next > maxPmtu) {
        return 0;
    }
    return next;
}

int DplpmtudSearchAlgorithmUp::getSmallerCandidate(int unackedCandidate) {
    return 0;
}

bool DplpmtudSearchAlgorithmUp::doRapidTest() {
    return false;
}

} /* namespace quic */
} /* namespace inet */
