#pragma once

#include "game/ui_core/TCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_widgets/TNumberedArrowButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642f88
class TShipFractionCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TShipFractionCluster)
  virtual ~TShipFractionCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00568eb0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x568d70

  TShipFractionCluster();

  void SetAvailableAndSelectedShipCounts(int availableCount, int selectedCount);

  // Original object size is 0x98 (CRuntimeClass m_nObjectSize); the source class ended at
  // 0x88. Available ship count and upper bound for the selected count. The original
  // writes/reads it with 16-bit instructions throughout; TShipPlacard::Draw
  // also renders this count through its ownerContext.
  short availableShipCount88;
  short pad8a;
  // The 'main'-tagged control on GetWindow(), resolved by DoPostCreate.
  class TMapUberPicture* mainSelectionView8c;
  // The 'arro' TNumberedArrowButton, resolved by DoPostCreate. Windows calls its
  // TNumberedArrowButton::SetValue slot at vtable offset 0x1c4.
  TNumberedArrowButton* shipCountButton90;
  short selectedShipCount94;
  short pad96;
};
