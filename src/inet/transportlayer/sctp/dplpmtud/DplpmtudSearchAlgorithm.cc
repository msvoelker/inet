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

#include "DplpmtudSearchAlgorithm.h"

namespace inet {
namespace sctp {

DplpmtudSearchAlgorithm::DplpmtudSearchAlgorithm(int minPmtu, int maxPmtu, int stepSize) {
    this->minPmtu = minPmtu;
    this->maxPmtu = maxPmtu;
    this->stepSize = stepSize;
}

DplpmtudSearchAlgorithm::~DplpmtudSearchAlgorithm() { }

void DplpmtudSearchAlgorithm::ptbReceived(int ptbMtu) {
    this->maxPmtu = ptbMtu;
}

} /* namespace quic */
} /* namespace inet */
