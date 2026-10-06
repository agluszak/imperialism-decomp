#pragma once

#include "game/map_ui/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006594e8
class TMapEditView : public TMapDialog {
public:
  DECLARE_DYNCREATE(TMapEditView)
  virtual ~TMapEditView() override;

  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoPostCreate(int arg) override;
  virtual void ControlClick(int tileIndex, int dispatchContext) override;
  virtual void HandleMapTileClickSetOrderContextAndHandleEvent79(int arg1, int arg2) override;
  virtual void ShiftClick(int stridedRecord, int dispatchContext) override;
  virtual void NormalClick(short nTileIndex, int nInputFlags) override;

  TMapEditView() : reservedFlag(0), editorActionMode(0), editorActionValue(0) {}

  void DefaultResources(short tileIndex); // 0x0051d4f0
  void PlaceProvince(short tileIndex);    // 0x0051d7e0
  void PlaceResource(short tileIndex);    // 0x0051d970
  void PlaceRiver(short tileIndex);       // 0x0051dba0
  void PlaceCountySeat(short tileIndex);  // 0x0051dc90

  void PlaceTerrain(short tileIndex); // 0x0051d380
  void PlaceRail(short tileIndex);    // 0x0051db30

  // +0x364 is only constructor-zeroed; retain the byte without inventing semantics.
  unsigned char reservedFlag;
  unsigned char padding365[3];
  int editorActionMode;
  int editorActionValue;
};

ASSERT_SIZE(TMapEditView, 0x370);
