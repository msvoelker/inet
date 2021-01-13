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

#ifndef INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSEARCHALGORITHMJUMP_H_
#define INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSEARCHALGORITHMJUMP_H_

#include "DplpmtudSearchAlgorithm.h"
#include <vector>

namespace inet {
namespace sctp {

class DplpmtudSearchAlgorithmJump: public DplpmtudSearchAlgorithm {
public:
    DplpmtudSearchAlgorithmJump(int minPmtu, int maxPmtu, int stepSize);
    virtual ~DplpmtudSearchAlgorithmJump();

    virtual int getFirstCandidate() override;
    virtual int getLargerCandidate(int ackedCandidate) override;
    virtual int getSmallerCandidate(int unackedCandidate) override;
    virtual bool doRapidTest() override;
    virtual void ptbReceived(int ptbMtu) override;

private:
    std::vector<int> candidates;
    bool rapid;
    bool downward;

    void addCandidates(std::vector<int>::iterator &after);
    std::vector<int>::iterator getIterator(int value);
    bool rapidTest(std::vector<int>::iterator newCandidateIt);
};

} /* namespace quic */
} /* namespace inet */

#endif /* INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSEARCHALGORITHMJUMP_H_ */
