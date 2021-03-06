//
// Copyright (C) 2013 OpenSim Ltd.
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

#include "inet/physicallayer/wireless/common/radio/packetlevel/ListeningDecision.h"

namespace inet {
namespace physicallayer {

ListeningDecision::ListeningDecision(const IListening *listening, bool isListeningPossible_) :
    listening(listening),
    isListeningPossible_(isListeningPossible_)
{
}

std::ostream& ListeningDecision::printToStream(std::ostream& stream, int level, int evFlags) const
{
    stream << "ListeningDecision";
    if (level <= PRINT_LEVEL_DETAIL)
        stream << (isListeningPossible_ ? ", \x1b[1mpossible\x1b[0m" : ", \x1b[1mimpossible\x1b[0m");
    if (level <= PRINT_LEVEL_TRACE)
        stream << EV_FIELD(listening, printFieldToString(listening, level + 1, evFlags));
    return stream;
}

} // namespace physicallayer
} // namespace inet

