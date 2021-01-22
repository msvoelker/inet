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

#include "DplpmtudSearchAlgorithmJump.h"

namespace inet {
namespace sctp {

DplpmtudSearchAlgorithmJump::DplpmtudSearchAlgorithmJump(int minPmtu, int maxPmtu, int stepSize) : DplpmtudSearchAlgorithm(minPmtu, maxPmtu, stepSize) {
    rapid = true;
    downward = true;

    // add initial candidates to test
    // respecting the range given by [minPmtu, maxPmtu] add these candidates:
    // 1300, 1400, 1420, 1440, 1460, 1480, 1500, 1520, 4000, 6500, 9000, 12500, 34000, 46500, 59000
    // and add minPmtu and maxPmtu
    int candidate;
    candidates.push_back(minPmtu);
    for (candidate = 1300; candidate <= 1400 && candidate < maxPmtu; candidate += 100) {
        if (candidate > minPmtu) {
            candidates.push_back(candidate);
        }
    }
    for (candidate = 1420; candidate <= 1520 && candidate < maxPmtu; candidate += 20) {
        if (candidate > minPmtu) {
            candidates.push_back(candidate);
        }
    }
    for (candidate = 4000; candidate <= 9000 && candidate < maxPmtu; candidate += 2500) {
        if (candidate > minPmtu) {
            candidates.push_back(candidate);
        }
    }
    for (candidate = 21500; candidate <= 59000 && candidate < maxPmtu; candidate += 12500) {
        if (candidate > minPmtu) {
            candidates.push_back(candidate);
        }
    }
    candidates.push_back(maxPmtu);

}
DplpmtudSearchAlgorithmJump::~DplpmtudSearchAlgorithmJump() { }

int DplpmtudSearchAlgorithmJump::getFirstCandidate() {
    return maxPmtu;
}

int DplpmtudSearchAlgorithmJump::getLargerCandidate(int ackedCandidate) {
    auto it = getIterator(ackedCandidate);
    if ((it+1) == candidates.end()) {
        // no larger candidates left
        return 0;
    }

    if (downward) {
        downward = false;
        addCandidates(it);
    }

    rapid = rapidTest(it+1);
    return *(it+1);
}

int DplpmtudSearchAlgorithmJump::getSmallerCandidate(int unackedCandidate) {
    auto it = getIterator(unackedCandidate);
    if (it == candidates.begin()) {
        // no smaller candidates left
        return 0;
    }
    auto smallerIt = it-1;

    if (downward) {
        rapid = smallerIt != candidates.begin();
        return *smallerIt;
    } else {
        if (!rapid) {
            // no smaller candidates left
            return 0;
        }
        addCandidates(smallerIt);
        rapid = rapidTest(smallerIt+1);
        return *(smallerIt+1);
    }
}

bool DplpmtudSearchAlgorithmJump::doRapidTest() {
    return rapid;
}

/**
 * Remove all candidates larger than ptbMtu and add ptbMtu.
 */
void DplpmtudSearchAlgorithmJump::ptbReceived(int ptbMtu) {
    std::vector<int>::iterator it;
    for(it = candidates.begin(); it != candidates.end() && *it < ptbMtu; ++it);

    candidates.erase(it, candidates.end());
    candidates.push_back(ptbMtu);
}

/**
 * \param value Value in candidates to get an iterator for.
 * \return Iterator pointing to the element in candidates with the given value.
 */
std::vector<int>::iterator DplpmtudSearchAlgorithmJump::getIterator(int value) {
    for(std::vector<int>::iterator it = candidates.begin(); it != candidates.end(); ++it) {
        if (*it == value) {
            return it;
        }
    }
    throw omnetpp::cRuntimeError("DplpmtudSearchAlgorithmJump: Could not find iterator for value");
}

/**
 * Add further candidates after the element the given iterator points to.
 * \param after An iterator pointing to the element in candidates after that new candidates are to be added.
 */
void DplpmtudSearchAlgorithmJump::addCandidates(std::vector<int>::iterator &after) {
    int lower = *after;
    int upper = *(after+1);
    int d = upper - lower;
    if (d <= 4) {
        throw omnetpp::cRuntimeError("DplpmtudSearchAlgorithmJump::addCandidates: adding candidates is not possible as the distance does not exceed 4.");
    }
    // calculate the distance for new candidates based on the old distance d
    int newD;
    if (d%5 != 0 || (d/5)%4 != 0) {
        for (newD=4; newD*5 < d; newD*=5);
    } else {
        newD = d/5;
    }
    // add new candidates in descending order
    std::vector<int>::iterator insertBefore = (after+1);
    for (int newCandidate = upper-newD; newCandidate > lower; newCandidate -= newD) {
        insertBefore = candidates.insert(insertBefore, newCandidate);
    }
    // refresh the iterator given by the caller
    after = insertBefore-1;
}

/**
 * Do a rapid test as long as the distance between the tested candidate and the next smaller one is
 * exceeds 4, because only then it is possible to add new candidates to test.
 * \param newCandidateIt Iterator pointing to the candidate to test.
 * \return true if the test should be rapid, false otherwise.
 */
bool DplpmtudSearchAlgorithmJump::rapidTest(std::vector<int>::iterator newCandidateIt) {
    if (newCandidateIt == candidates.begin()) {
        return false;
    }

    int candidate = *newCandidateIt;
    int smallerCandidate = *(newCandidateIt-1);

    return ((candidate - smallerCandidate) > 4);
}

} /* namespace quic */
} /* namespace inet */
