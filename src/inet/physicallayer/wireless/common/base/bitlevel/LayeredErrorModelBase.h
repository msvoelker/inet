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

#ifndef __INET_LAYEREDERRORMODELBASE_H
#define __INET_LAYEREDERRORMODELBASE_H

#include "inet/physicallayer/wireless/common/contract/bitlevel/ILayeredErrorModel.h"

namespace inet {

namespace physicallayer {

class INET_API LayeredErrorModelBase : public cModule, public ILayeredErrorModel
{
  protected:
    virtual const IReceptionPacketModel *computePacketModel(const LayeredTransmission *transmission, double packetErrorRate) const;
    virtual const IReceptionBitModel *computeBitModel(const LayeredTransmission *transmission, double bitErrorRate) const;
    virtual const IReceptionSymbolModel *computeSymbolModel(const LayeredTransmission *transmission, double symbolErrorRate) const;
};

} // namespace physicallayer

} // namespace inet

#endif

