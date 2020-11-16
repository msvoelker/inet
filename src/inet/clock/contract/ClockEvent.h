//
// Copyright (C) 2020 OpenSim Ltd.
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

#ifndef __INET_CLOCKEVENT_H
#define __INET_CLOCKEVENT_H

#include "inet/common/INETDefs.h"
#ifdef INET_WITH_CLOCK_SUPPORT
#include "inet/clock/common/ClockEvent_m.h"
#endif

namespace inet {

#ifndef INET_WITH_CLOCK_SUPPORT
typedef cMessage ClockEvent;
#endif

} // namespace inet

#endif

