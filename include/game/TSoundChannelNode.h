#pragma once

#include "game/mfc.h"

// DirectSound channel list node (vtable 0x00650a08).
// VTABLE: IMPERIALISM 0x00650a08
class TSoundChannelNode : public CObject {
public:
  int field4;
  int field8;
  int fieldC;
  int field10;
  int field14;
  int field18;

  TSoundChannelNode();
  ~TSoundChannelNode() override;
  void Serialize(CArchive& ar) override;
  void Dump(CDumpContext& dc) const override;

#define SOUND_CHANNEL_NODE_DUMMY(n) virtual void SoundChannelNodeDummy##n()
  SOUND_CHANNEL_NODE_DUMMY(00);
  SOUND_CHANNEL_NODE_DUMMY(01);
  SOUND_CHANNEL_NODE_DUMMY(02);
  SOUND_CHANNEL_NODE_DUMMY(03);
  SOUND_CHANNEL_NODE_DUMMY(04);
#undef SOUND_CHANNEL_NODE_DUMMY

  virtual int QueryPendingPlaybackCountSlot28(); // 0x28
  virtual void SoundChannelNodeDummy2C();        // 0x2c
  virtual int StopOrResetActivePlaybackSlot30(); // 0x30
  virtual void SoundChannelNodeDummy34();        // 0x34
  virtual int ReleaseChannelNodeSlot38();        // 0x38
};
