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

#ifndef __INET_CONSTANTGAINANTENNA_H
#define __INET_CONSTANTGAINANTENNA_H

#include "inet/physicallayer/wireless/common/base/packetlevel/AntennaBase.h"

namespace inet {

namespace physicallayer {

class INET_API ConstantGainAntenna : public AntennaBase
{
  protected:
    virtual void initialize(int stage) override;

    class AntennaGain : public IAntennaGain
    {
      public:
        AntennaGain(double gain) : gain(gain) {}
        virtual double getMinGain() const override { return gain; }
        virtual double getMaxGain() const override { return gain; }
        virtual double computeGain(const Quaternion& direction) const override { return gain; }

      protected:
        double gain;
    };

    Ptr<AntennaGain> gain;

  public:
    ConstantGainAntenna();

    virtual std::ostream& printToStream(std::ostream& stream, int level, int evFlags = 0) const override;
    virtual Ptr<const IAntennaGain> getGain() const override { return gain; }
};

} // namespace physicallayer

} // namespace inet

#endif

