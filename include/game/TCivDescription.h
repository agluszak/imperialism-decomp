#pragma once

#include "compat.h"
#include "game/TControl.h"

int AllocateWithFallbackHandler(undefined4 size_bytes);

struct Rect32 {
  int left;
  int top;
  int right;
  int bottom;
};

// VTABLE: IMPERIALISM 0x6431B0
class TCivDescription : public TControl {
public:
  short selectedCivilianClass;
  short ownerNationId;
  union {
    short targetTileCountsBySlot[5];
    struct {
      short pad_64[4];
      unsigned char legendInitialized;
      unsigned char pad_6d;
    };
  };
  Rect32 legendRects[16];
  unsigned char pad_170_to_16f[0]; // legends end at 0x170

  TCivDescription();

  // ~TCivDescription is compiler-generated (implicit virtual dtor); see
  // the SYNTHETIC scalar deleting destructor in the .cpp.

  void UpdateCivilianOrderClassAndRefreshTargetCounts(class TCivilianOrderState* orderState);
  void HandleCivilianLegendHitTestAndSelectOrder(int arg1, int arg2, struct Point32* point,
                                                 int arg4);
  void RefreshCivilianTargetLegendBySelectedClass();
  void RenderCivilianTargetLegendVariantA();

  void UpdateCivilianOrderTargetTileCountsForOwnerNation(class TCivilianOrderState* selectedOrder);
};

ASSERT_SIZE(TCivDescription, 0x194);
