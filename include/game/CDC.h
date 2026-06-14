#pragma once

#include "compat.h"
#include "game/CObject.h"

// MFC CDC wrapper (primary/attribute HDC pair + window handle).
// VTABLE: IMPERIALISM 0x0067241c
class CDC : public CObject {
public:
  int m_hDC;
  int m_hAttribDC;
  int m_pHandleMapEntry;
  int m_hWnd;

  CDC();
  virtual ~CDC() override;

  bool AttachOutput(int hdc);

protected:
  void DetachOutput();

  virtual void CdcSlot14OnAttach(int hdc);
  virtual void CdcSlot18Stub();
  virtual void CdcSlot1cOnDetach();
};

ASSERT_SIZE(CDC, 0x14);
