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

#ifndef INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSTATEBASE_H_
#define INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSTATEBASE_H_

#include "DplpmtudState.h"

namespace inet {
namespace sctp {

class DplpmtudStateBase: public DplpmtudState {
public:
    DplpmtudStateBase(Dplpmtud *context);
    virtual ~DplpmtudStateBase();

    virtual DplpmtudState *onProbeAcked(int ackedProbeSize) override;
    virtual DplpmtudState *onProbeTimeout(int unackedProbeSize) override;
    virtual DplpmtudState *onPtbReceived(int ptbMtu) override;
    virtual DplpmtudState *onPmtuInvalid() override;
    virtual void onRaiseTimeout() override;

private:
    int base;

    void start();
};

} /* namespace quic */
} /* namespace inet */

#endif /* INET_TRANSPORTLAYER_QUIC_DPLPMTUD_DPLPMTUDSTATEBASE_H_ */