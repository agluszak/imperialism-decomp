#pragma once

#include "decomp_types.h"
#include "game/CPtrList.h"
#include "game/CView.h"

// MFC CDocument: owns a CPtrList of attached views (m_viewList at +0x28).
struct CDocument {
  char pad_00[0x28];
  CPtrList m_viewList;

  void DisconnectViews();
  void AddView(CView* view);
  void* DestructCDocumentBaseStateAndMaybeFree(byte freeSelfFlag);
};
