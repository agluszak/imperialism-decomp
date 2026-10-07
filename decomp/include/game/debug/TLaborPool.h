#pragma once

#include "game/app/TObject.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0064f540
class TLaborPool : public TObject {
public:
  DECLARE_DYNCREATE(TLaborPool)
  virtual ~TLaborPool() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual short TransferWorst(TLaborPool* destination, short amount);
  virtual short TransferToHighSkillFirst(TLaborPool* destination, short amount);

  TLaborPool() : lowSkillCount(0), mediumSkillCount(0), highSkillCount(0), pad0a(0) {}
  void ILaborPool();

  short lowSkillCount;
  short mediumSkillCount;
  short highSkillCount;
  short pad0a;
};

ASSERT_SIZE(TLaborPool, 0x0c);
