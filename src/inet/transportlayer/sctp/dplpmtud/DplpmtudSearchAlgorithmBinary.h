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

#ifndef INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSEARCHALGORITHMBINARY_H_
#define INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSEARCHALGORITHMBINARY_H_

#include "DplpmtudSearchAlgorithm.h"

namespace inet {
namespace sctp {

class DplpmtudSearchAlgorithmBinary: public DplpmtudSearchAlgorithm {
public:
    DplpmtudSearchAlgorithmBinary(int minPmtu, int maxPmtu, int stepSize);
    virtual ~DplpmtudSearchAlgorithmBinary();

    virtual int getFirstCandidate() override;
    virtual int getLargerCandidate(int ackedCandidate) override;
    virtual int getSmallerCandidate(int unackedCandidate) override;
    virtual bool doRapidTest() override;

private:
    int calculateNextValue();
};

} /* namespace quic */
} /* namespace inet */

#endif /* INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSEARCHALGORITHMBINARY_H_ */
