#pragma once

#include "decomp_types.h"
#include "game/TPtrList.h"

// MFC CDocument: owns a CPtrList of attached views (m_viewList at +0x28). Each
// view stores its owning document at +0x3c.
struct CView {
  char pad_00[0x3c];
  void* m_pDocument;
};

struct CDocument {
  char pad_00[0x28];
  CPtrListSentinelView m_viewList;

  void DisconnectViews();
  void* DestructCDocumentBaseStateAndMaybeFree(byte freeSelfFlag);
};
