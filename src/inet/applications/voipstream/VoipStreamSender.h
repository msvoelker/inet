//
// Copyright (C) 2005 M. Bohge (bohge@tkn.tu-berlin.de), M. Renwanz
// Copyright (C) 2010 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//

#ifndef __INET_VOIPSTREAMSENDER_H
#define __INET_VOIPSTREAMSENDER_H

#ifndef HAVE_FFMPEG
#error Please install libavcodec, libavformat, libavutil or disable 'VoIPStream' feature
#endif // ifndef HAVE_FFMPEG

#include <fnmatch.h>

#include <vector>

#define __STDC_CONSTANT_MACROS

#include "inet/common/INETDefs.h"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#ifndef HAVE_FFMPEG_AVRESAMPLE
#error Please install libavresample or disable 'VoIPStream' feature
#endif // ifndef HAVE_FFMPEG_AVRESAMPLE
#include <libavresample/avresample.h>
};

#include "inet/applications/voipstream/AudioOutFile.h"
#include "inet/applications/voipstream/VoipStreamPacket_m.h"
#include "inet/common/lifecycle/LifecycleUnsupported.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

namespace inet {

class INET_API VoipStreamSender : public cSimpleModule, public LifecycleUnsupported
{
  public:
    VoipStreamSender();
    ~VoipStreamSender();

  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    virtual void openSoundFile(const char *name);
    virtual Packet *generatePacket();
    virtual bool checkSilence(AVSampleFormat sampleFormat, void *_buf, int samples);
    virtual void readFrame();

  protected:
    class Buffer
    {
      public:
        enum { BUFSIZE = 48000 * 2 * 2 }; // 1 second of two channel 48kHz 16bit audio

      protected:
        char *samples;
        int bufferSize;
        int readOffset;
        int writeOffset;

      public:
        Buffer();
        ~Buffer();
        void clear(int framesize);
        int length() const { return writeOffset - readOffset; }
        bool empty() const { return writeOffset <= readOffset; }
        char *readPtr() { return samples + readOffset; }
        char *writePtr() { return samples + writeOffset; }
        int availableSpace() const { return bufferSize - writeOffset; }
        void notifyRead(int length) { readOffset += length; ASSERT(readOffset <= writeOffset); }
        void notifyWrote(int length) { writeOffset += length; ASSERT(writeOffset <= bufferSize); }
        void align();
    };

  protected:
    // general parameters
    int localPort = -1;
    int destPort = -1;
    L3Address destAddress;

    int voipHeaderSize = 0;
    int voipSilenceThreshold = 0; // the maximum amplitude of a silence packet
    int voipSilencePacketSize = 0; // size of a silence packet
    int sampleRate = 0; // samples/sec [Hz]
    const char *codec = nullptr;
    int compressedBitRate = 0;
    simtime_t packetTimeLength;
    const char *soundFile = nullptr; // input audio file name
    int repeatCount = 0;

    const char *traceFileName = nullptr; // name of the output trace file, nullptr or empty to turn off recording
    AudioOutFile outFile;

    // AVCodec parameters
    AVFormatContext *pFormatCtx = nullptr;
    AVCodecContext *pCodecCtx = nullptr;
    AVCodec *pCodec = nullptr; // input decoder codec
    AVAudioResampleContext *pReSampleCtx = nullptr;
    AVCodecContext *pEncoderCtx = nullptr;
    AVCodec *pCodecEncoder = nullptr; // output encoder codec

    // state variables
    UdpSocket socket;
    int streamIndex = -1;
    uint32_t pktID = 0; // increasing packet sequence number
    int samplesPerPacket = 0;
    AVPacket packet {}; // {}: zero-initialize so that av_free_packet() doesn't crash if initialization doesn't go through
    Buffer sampleBuffer;

    cMessage *timer = nullptr;
};

} // namespace inet

#endif

