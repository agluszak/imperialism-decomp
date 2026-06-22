#pragma once

#include "decomp_types.h"

// DirectSound channel list node (vtable 0x00650a08). Allocated by TSoundPlayer at +0x6c/+0x70.
// VTABLE: IMPERIALISM 0x00650a08
class TSoundChannelNode {
public:
  virtual ~TSoundChannelNode() {}

#define SOUND_CHANNEL_NODE_DUMMY(n) virtual void SoundChannelNodeDummy##n() = 0
  SOUND_CHANNEL_NODE_DUMMY(00);
  SOUND_CHANNEL_NODE_DUMMY(01);
  SOUND_CHANNEL_NODE_DUMMY(02);
  SOUND_CHANNEL_NODE_DUMMY(03);
  SOUND_CHANNEL_NODE_DUMMY(04);
  SOUND_CHANNEL_NODE_DUMMY(05);
  SOUND_CHANNEL_NODE_DUMMY(06);
  SOUND_CHANNEL_NODE_DUMMY(07);
  SOUND_CHANNEL_NODE_DUMMY(08);
  SOUND_CHANNEL_NODE_DUMMY(09);
#undef SOUND_CHANNEL_NODE_DUMMY

  virtual int QueryPendingPlaybackCountSlot28();  // 0x28
  virtual void SoundChannelNodeDummy2C() = 0;
  virtual int StopOrResetActivePlaybackSlot30();  // 0x30
  virtual void SoundChannelNodeDummy34() = 0;
  virtual int ReleaseChannelNodeSlot38();         // 0x38
};
