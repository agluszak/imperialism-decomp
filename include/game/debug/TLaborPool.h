#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0064f540
class TLaborPool : public TObject {
public:
  DECLARE_DYNCREATE(TLaborPool)
  virtual ~TLaborPool() override;                  // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4b21d0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4b2220
  // Move up to `amount` workers to another pool. The two slots differ only in
  // which skill band is consumed first.
  virtual short TransferToLowSkillFirst(TLaborPool* destination,
                                        short amount); // slot 0x0a 0x4b2270
  virtual short TransferToHighSkillFirst(TLaborPool* destination,
                                         short amount); // slot 0x0b 0x4b2340

  // SYNTHETIC: IMPERIALISM 0x004b2130
  // TLaborPool::TLaborPool
  TLaborPool() : lowSkillCount04(0), mediumSkillCount06(0), highSkillCount08(0), pad0a(0) {}
  void ILaborPool();

  short lowSkillCount04;
  short mediumSkillCount06;
  short highSkillCount08;
  short pad0a;
};

ASSERT_SIZE(TLaborPool, 0x0c);
