#pragma once

#include "compat.h"
#include "game/TView.h"

struct CRuntimeClass;

struct Rect32 {
  int left;
  int top;
  int right;
  int bottom;
};

// VTABLE: IMPERIALISM 0x6431B0
class TCivDescription : public TView {
public:
  DECLARE_DYNCREATE(TCivDescription)
  virtual ~TCivDescription();

  virtual void ApplyRectSlot110(RECT* rectBuffer) override; // slot 0x44 0x58f550
  virtual void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                    int arg4) override; // slot 0x47 0x58f1a0
  virtual void DispatchPictureResourceCommand(int eventType, void* eventSender, void* eventDataA,
                                              void* eventDataB); // slot 0x68 0x58fec0
  virtual void DeserializeCityProductionQueueCommand(int* boundsBuffer); // slot 0x69 0x58f7b0
  virtual void AssertCityProductionGlobalStateInitialized(int arg1,
                                                          int arg2); // slot 0x6a 0x5903c0
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

  void UpdateCivilianOrderClassAndRefreshTargetCounts(class TCivUnit* orderState);
  void UpdateCivilianOrderTargetTileCountsForOwnerNation(class TCivUnit* selectedOrder);
};

