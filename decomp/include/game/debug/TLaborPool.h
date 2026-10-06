#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0064f540
class TLaborPool : public TObject {
public:
  DECLARE_DYNCREATE(TLaborPool)
  virtual ~TLaborPool() override;                  // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b21d0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b2220
  virtual short TransferToLowSkillFirst(TLaborPool* destination,
                                        short amount); // slot 0x0a 0x4b2270
  virtual short TransferToHighSkillFirst(TLaborPool* destination,
                                         short amount); // slot 0x0b 0x4b2340

  TLaborPool() : lowSkillCount(0), mediumSkillCount(0), highSkillCount(0), pad0a(0) {}
  void ILaborPool();

  short lowSkillCount;
  short mediumSkillCount;
  short highSkillCount;
  short pad0a;
};

ASSERT_SIZE(TLaborPool, 0x0c);
