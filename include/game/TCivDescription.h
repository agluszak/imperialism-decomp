#pragma once

#include "compat.h"
#include "game/TView.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x6431B0
class TCivDescription : public TView {
public:
  DECLARE_DYNCREATE(TCivDescription)
  virtual ~TCivDescription() override;

  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x58f550
  virtual void BeginMouseCaptureAndStartRepeatTimer(const CPoint& point, TToolboxEvent* event,
                                                    CPoint origin) override; // slot 0x47 0x58f1a0
  virtual void DrawProspector(RECT* bounds);                                 // slot 0x68 0x58fec0
  // Mac CodeWarrior names this DrawEngineer(const VRect&). The Windows override ignores
  // the dirty rect and renders the Engineer's Depot/Port/Fort costs plus terrain legend.
  virtual void DrawEngineer(RECT* bounds);  // slot 0x69 0x58f7b0
  virtual void DrawDeveloper(RECT* bounds); // slot 0x6a 0x5903c0
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
  RECT legendRects[16];

  TCivDescription();

  void UpdateCivilianOrderClassAndRefreshTargetCounts(class TCivUnit* orderState);
  void UpdateCivilianOrderTargetTileCountsForOwnerNation(class TCivUnit* selectedOrder);
};
