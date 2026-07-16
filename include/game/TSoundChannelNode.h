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

  // Defined inline: the original inlines this constructor at every `new` site (no
  // standalone ctor body exists in the binary). Body assignments in this order --
  // not a member-init list -- to match the original's inlined store order
  // (see 0x4e3830: 0xc, 0x10, 0x8, 0x4, 0x14, 0x18).
  TSoundChannelNode() {
    fieldC = 0;
    field10 = 0;
    field8 = 0;
    field4 = 0;
    field14 = 0;
    field18 = 10;
  }
  ~TSoundChannelNode() override;
  void Serialize(CArchive& ar) override;
  void Dump(CDumpContext& dc) const override;

  virtual void SoundChannelNodeDummy00(int value); // slot 0x05 (0x14) — appends a value
#define SOUND_CHANNEL_NODE_DUMMY(n) virtual void SoundChannelNodeDummy##n()
  SOUND_CHANNEL_NODE_DUMMY(01);
  SOUND_CHANNEL_NODE_DUMMY(02);
  SOUND_CHANNEL_NODE_DUMMY(03);
#undef SOUND_CHANNEL_NODE_DUMMY
  virtual int SoundChannelNodeDummy04(int index); // 0x24 — fetch the value at index

  virtual int QueryPendingPlaybackCountSlot28();   // 0x28
  virtual void SoundChannelNodeDummy2C(int index); // 0x2c
  virtual int StopOrResetActivePlaybackSlot30();   // 0x30
  virtual void SoundChannelNodeDummy34();          // 0x34
  virtual int ReleaseChannelNodeSlot38();          // 0x38
};
