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

#include "DplpmtudSearchAlgorithmDown.h"

namespace inet {
namespace sctp {

DplpmtudSearchAlgorithmDown::DplpmtudSearchAlgorithmDown(int minPmtu, int maxPmtu, int stepSize) : DplpmtudSearchAlgorithm(minPmtu, maxPmtu, stepSize) { }
DplpmtudSearchAlgorithmDown::~DplpmtudSearchAlgorithmDown() { }

int DplpmtudSearchAlgorithmDown::getFirstCandidate() {
    return maxPmtu;
}

int DplpmtudSearchAlgorithmDown::getLargerCandidate(int ackedCandidate) {
    return 0;
}

int DplpmtudSearchAlgorithmDown::getSmallerCandidate(int unackedCandidate) {
    int next = unackedCandidate - stepSize;
    if (next < minPmtu) {
        return 0;
    }
    return next;
}

bool DplpmtudSearchAlgorithmDown::doRapidTest() {
    return false;
}

} /* namespace quic */
} /* namespace inet */
