#pragma once

#include "game/TMapDialog.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006594e8
class TMapEditView : public TMapDialog {
public:
  DECLARE_DYNCREATE(TMapEditView)
  virtual ~TMapEditView() override;

  virtual void ForwardParam(int param) override;
  virtual void DoPostCreate(int arg) override;
  virtual void InvokeDialogHooks1D8ThenE4(int stridedRecord, int dispatchContext) override;
  virtual void HandleMapTileClickSetOrderContextAndHandleEvent79(int arg1, int arg2) override;
  virtual void DispatchOverlayEvent78FromStridedRecord(int stridedRecord,
                                                       int dispatchContext) override;
  virtual void HandleMapClickByInteractionMode(short nTileIndex, int nInputFlags) override;

  TMapEditView();

  // Mac CodeWarrior identities. These are deliberately non-virtual helpers selected by
  // NormalClick/HandleMapClickByInteractionMode's editor-action switch.
  void DefaultResources(short tileIndex); // 0x0051d4f0
  void PlaceProvince(short tileIndex);    // 0x0051d7e0
  void PlaceResource(short tileIndex);    // 0x0051d970
  void PlaceRiver(short tileIndex);       // 0x0051dba0
  void PlaceCountySeat(short tileIndex);  // 0x0051dc90

  // The retail binary contains these two additional Mac-named editor helpers even though
  // no surviving Windows callsite references them directly.
  void PlaceTerrain(short tileIndex); // 0x0051d380
  void PlaceRail(short tileIndex);    // 0x0051db30

  // +0x364 is only constructor-zeroed; retain the byte without inventing semantics.
  unsigned char reservedFlag364;
  unsigned char padding365[3];
  // Selected editor action (0=default resources, 1=province, 2=resource, 3=rail,
  // 4=county seat, 5=river) and that action's selected palette/value.
  int editorActionMode368;
  int editorActionValue36c;
};

ASSERT_SIZE(TMapEditView, 0x370);
