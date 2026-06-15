#include "game/CDocument.h"

#include "game/CDocument_Virtuals.h"
#include "game/generated/vcall_facades.h"

// MFC CDocument code was compiled favor-size in the original.
#if defined(_MSC_VER)
#pragma optimize("ys", on)
#endif

void FreeHeapBufferIfNotNull(undefined4 ptrValue);
undefined4 DestructCDocumentBaseState(void);

// FUNCTION: IMPERIALISM 0x006109cf
void* CDocument::DestructCDocumentBaseStateAndMaybeFree(byte freeSelfFlag) {
  reinterpret_cast<void(__fastcall*)(void*)>(::DestructCDocumentBaseState)(this);
  if ((freeSelfFlag & 1) != 0) {
    FreeHeapBufferIfNotNull(static_cast<undefined4>(reinterpret_cast<unsigned int>(this)));
  }
  return this;
}

// LIBRARY: IMPERIALISM 0x00610a5f
// CDocument::DisconnectViews

// FUNCTION: IMPERIALISM 0x00611810
void CDocument::AddView(CView* view) {
  m_viewList.AddTail(view);
  view->m_pDocument = this;
  reinterpret_cast<CDocument_Virtuals*>(this)->NotifyViewListChangedSlot70();
}
