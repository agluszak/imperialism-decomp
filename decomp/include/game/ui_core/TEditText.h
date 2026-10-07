#pragma once

#include "compat.h"

#include "game/ui_core/TStaticText.h"
#include "game/mfc.h"

class CityDialogController;

class CMcEditWindow;

// VTABLE: IMPERIALISM 0x0064ad90
class TEditText : public TStaticText {
public:
  CMcEditWindow* editWindow; // 0x94, live edit-host window while focused/active
  CFont* editFont;           // 0x98, owns the HFONT installed into editWindow
  short maxCharacterCount;   // 0x9c
  short reserved9e;          // 0x9e, no accesses observed

  DECLARE_DYNCREATE(TEditText)
  virtual ~TEditText() override;

  void Free() override;
  char IsEnabled() override;
  void SetEnable(char enabled) override;
  void TargetValidationSucceeded() override;
  bool BecomeTarget() override;
  void SelectOwner(unsigned char select) override;
  CWnd* Open() override;
  void Close() override;
  void Show(int enabledState, int refreshFlag) override;
  void Draw(RECT* rectBuffer) override;
  char HandleMouseDown(const CPoint& point, TToolboxEvent* event, CPoint origin) override;
  void UpdateCoordinates() override;
  void SetJustification(short alignmentCode, bool refreshFlag) override;
  virtual void SetEditSelectionAndScrollCaret(short selStart, short selEnd, int unusedFlag);
  virtual void GetCurrentText(CString* out);
  virtual void InitDialogWindowAndSyncTitleIfChanged(CString* newText, int refreshFlag);

  TEditText();
  void IEditText(TView* panel, int* offsetLayout, int* sizeLayout,
                 short maximumCharacterCount); // 0x004905e0

  void CopyEditTextStateFromSource(TEditText* source);
};
ASSERT_SIZE(TEditText, 0xa0);
