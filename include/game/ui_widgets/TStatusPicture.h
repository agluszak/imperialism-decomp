#pragma once

#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00642268
class TStatusPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TStatusPicture)
  virtual ~TStatusPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005942f0
  virtual void DoPostCreate(int arg) override;  // slot 0x37 0x593f20
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x594540
  int comparisonMode90;    // +0x90 -- selects which per-nation metric fills values94
  int values94[7];         // +0x94 per-entry sort key (score)
  short pictureIds_b0[7];  // +0xb0 per-entry picture id (-1 = empty slot)
  char padBE[0xc0 - 0xbe]; // +0xbe

  TStatusPicture();

  // Mac oracle: DrawBar(short, short, short). Draws a black shadow and then the
  // nation-colored comparison bar at the fixed graph origin.
  void DrawBar(short rowY, short width, short nationSlot);
  void SetComparisonModeAndRefresh(int comparisonMode); // 0x005941e0
  // Sorts the seven entries by descending value (empty -1 ids sink to the end), then pushes
  // each entry's picture id into its child picture widget. 0x594c00.
  void SortSevenEntriesAndUpdatePictureWidgets();
  void RecomputeNationComparisonValuesAndNormalizeScale();
};

ASSERT_SIZE(TStatusPicture, 0xc0);
