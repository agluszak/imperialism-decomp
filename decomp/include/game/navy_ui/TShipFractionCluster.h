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
  virtual ~TShipFractionCluster() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x00568eb0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x568d70

  TShipFractionCluster();

  void Set(int availableCount, int selectedCount);
  void IncrementSelectedShipCount(unsigned char displayOnly); // 0x005690d0
  void Less(unsigned char displayOnly);                       // 0x00569150

  short availableShipCount;
  short pad8a;
  // The 'main'-tagged control on GetWindow(), resolved by DoPostCreate.
  class TMapUberPicture* mainSelectionView;
  TNumberedArrowButton* shipCountButton;
  short selectedShipCount;
  short pad96;
};
ASSERT_SIZE(TShipFractionCluster, 0x98);
