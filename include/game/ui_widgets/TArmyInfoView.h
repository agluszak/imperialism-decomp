#pragma once

#include "compat.h"
#include "game/ui_core/TPicture.h"

struct CRuntimeClass;

// VTABLE: IMPERIALISM 0x668358
class TArmyInfoView : public TPicture {
public:
  virtual ~TArmyInfoView() override; // slot 0x01 (scalar deleting destructor)
  TArmyInfoView();
  DECLARE_DYNCREATE(TArmyInfoView)
  // Slot 0x73 (byte 0x1cc), 0x591620, RET 0x8. This is the 'DLOG' pict of MapView.rsrc
  // view 3100 "Friendly army report" (Mac resource oracle), and
  // TViewMgr::DispatchProvinceOrderOverlayConfirmDialog is its only caller: it forwards
  // the province's city-record index and the per-category order counts. The previous
  // `IsSelected(short, bool)` name/signature was a guess.
  virtual void StuffValues(short cityRecordIndex, int* categoryCounts);
};

ASSERT_SIZE(TArmyInfoView, 0x90);
