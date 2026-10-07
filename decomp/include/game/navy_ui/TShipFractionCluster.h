#pragma once

#include "compat.h"

#include "game/ui_core/TCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_widgets/TNumberedArrowButton.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642f88
class TShipFractionCluster : public TCluster {
public:
  DECLARE_DYNCREATE(TShipFractionCluster)
  virtual ~TShipFractionCluster() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void DoPostCreate(int arg) override;

  TShipFractionCluster();

  void Set(int availableCount, int selectedCount);
  void IncrementSelectedShipCount(unsigned char displayOnly);
  void Less(unsigned char displayOnly);

  short availableShipCount;
  short pad8a;
  // The 'main'-tagged control on GetWindow(), resolved by DoPostCreate.
  class TMapUberPicture* mainSelectionView;
  TNumberedArrowButton* shipCountButton;
  short selectedShipCount;
  short pad96;
};
ASSERT_SIZE(TShipFractionCluster, 0x98);
