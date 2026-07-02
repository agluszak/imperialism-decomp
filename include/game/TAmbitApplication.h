#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TApplication.h"

class TMapUberPicture;
class TStream;

// Ambit-specific application subclass (size 0x54, base TApplication = 0x48).
// Introduces virtual overrides for runtime serialization and modal auto-scroll.
// VTABLE: IMPERIALISM 0x0063e398
class TAmbitApplication : public TApplication {
public:
  TAmbitApplication();
  virtual ~TAmbitApplication() override;

  DECLARE_DYNCREATE(TAmbitApplication)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05, 0x0049e2f0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06, 0x0049e280
  virtual void Free() override;                    // slot 0x07, 0x0049e1a0

  virtual void ForwardParam(int param) override; // slot 0x12, 0x0049e4b0

  virtual void VTableSlot2B(int arg1, int arg2, int arg3) override; // slot 0x2b, 0x0049e320
  virtual void VTableSlot2C() override;              // slot 0x2c, 0x00414770 OrphanRetStub
  virtual void VTableSlot2D(void* param_1) override; // slot 0x2d, 0x0049e4e0

  void ParseDirectionTokenAndSetMovementFlags(CString token, int parseMode, int parseTail);

  // Startup: builds the singleton manager graph (TLanguageMgr/TSimMgr/TAssetMgr/
  // TViewMgr/TDisplayMgr/TMacViewMgr/THelpMgr/TMultiplayerMgr). __thiscall on the
  // fresh TAmbitApplication (writes this+0x48/+0x50); previously mis-modeled as the
  // free function InitializeGlobalRuntimeSystemsFromConfig.
  void InitializeGlobalRuntimeSystems(); // 0x49ded0

  TMapUberPicture* field_48; // 0x48 — viewport edge-scroll handler (slot 0x74 target)
  int field_4c;              // 0x4c
  int field_50;              // 0x50
};
