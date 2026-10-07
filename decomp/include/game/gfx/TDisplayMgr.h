#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

class TView;
class TPtrList;
struct TToolboxEvent;
struct TQuickDrawSurfaceContext;

// Display-surface / GWorld manager (singleton g_pDisplayMgr @ 0x006a2158).
// VTABLE: IMPERIALISM 0x00656680
class TDisplayMgr : public TObject {
public:
  DECLARE_DYNCREATE(TDisplayMgr)
  virtual ~TDisplayMgr() override;
  virtual void Free() override;
  virtual void IDisplayMgr();
  virtual void MakeNewGWorld(TQuickDrawSurfaceContext*& outContext, short bitDepth,
                             const RECT& bounds);
  virtual void ExamineGWorld();
  virtual void AboutToLoseControl(unsigned char saveState);
  virtual void RegainControl(unsigned char restoreState);
  virtual void SetMenuHeight(unsigned char menuHeight);
  virtual void SetBitDepth(unsigned char bitDepth);
  virtual void CloseBooks();
  virtual void DismissTouchyFloaters(TToolboxEvent* event);
  virtual void ModalMessage(CString message, const POINT& messagePosition);
  virtual void UpdateTheGWorld(short eventCode);
  virtual void SetHiliteColor(const RGBQUAD* color);
  virtual void CloseFloaters();

  void RemoveGWorld(TQuickDrawSurfaceContext*& surface);

  TView* activeDialog;
  short viewportMetric; // (default 8)
  short dialogActiveFlag;
  short field0c;
  short eventCode;
  RGBQUAD hiliteColor;
  RGBQUAD savedHiliteColor;
  int gworldFlags;
  short clipSnapshotEvent;
  unsigned short field1e;
  TPtrList* turnOrderList;

  TDisplayMgr();
};
ASSERT_SIZE(TDisplayMgr, 0x24);

struct GlobalViewportRectDefaultsRecord;

GlobalViewportRectDefaultsRecord** InitializeDefaultRects();

void PlayDefaultMessageBeep(...);
