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

#include "DplpmtudSearchAlgorithmBinary.h"

namespace inet {
namespace sctp {

DplpmtudSearchAlgorithmBinary::DplpmtudSearchAlgorithmBinary(int minPmtu, int maxPmtu, int stepSize) : DplpmtudSearchAlgorithm(minPmtu, maxPmtu, stepSize) { }
DplpmtudSearchAlgorithmBinary::~DplpmtudSearchAlgorithmBinary() { }

int DplpmtudSearchAlgorithmBinary::getFirstCandidate() {
    return calculateNextValue();
}

int DplpmtudSearchAlgorithmBinary::getLargerCandidate(int ackedCandidate) {
    minPmtu = ackedCandidate;
    int next = calculateNextValue();
    if (next == ackedCandidate) {
        return 0;
    }
    return next;
}

int DplpmtudSearchAlgorithmBinary::getSmallerCandidate(int unackedCandidate) {
    if (minPmtu == maxPmtu) {
        return 0;
    }
    maxPmtu = std::max(unackedCandidate - stepSize, minPmtu);
    int next = calculateNextValue();
    return next;
}

bool DplpmtudSearchAlgorithmBinary::doRapidTest() {
    return false;
}

int DplpmtudSearchAlgorithmBinary::calculateNextValue() {
    return std::ceil( ((double)(maxPmtu - minPmtu)) / (stepSize * 2) )  * stepSize + minPmtu;
}

} /* namespace quic */
} /* namespace inet */
