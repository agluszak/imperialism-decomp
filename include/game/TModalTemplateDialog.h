#pragma once

#include "game/TControl.h"
#include "game/mfc.h"

// Template-driven modal dialog controller. Extends TControl (Ghidra types the stack object as
// TControl and routes template init / finalize through TControl methods). Modal-create scratch
// fields reuse TView members during setup (field3c, field48, field5c, field2c); extended state
// lives in the members below.
class TModalTemplateDialog : public TControl {
public:
  TModalTemplateDialog();
  ~TModalTemplateDialog();

  TControl* InitializeDialogTemplateFromId(UINT templateId, void* initParam);
  int PrepareAndCreateModalFromTemplate();
  int FinalizeModalDialogAndRestoreOwnerFocus();
  void CleanupModalCreateState();
  void DestroyListBoxAndHotKeyChildren();
  BOOL UpdateData(BOOL saveAndValidate);

  int DialogResult() const { return field2c; }

protected:
  UINT resourceTemplateId;
  void* templateInitContext;
  void* lockedTemplateBytes;
  int templateSourceCopy;
  HGLOBAL hDialogResource;

  HWND hModalDialog;
  int ownerWasDisabled;
  HWND hOwnerWindow;
  int modalCreated;

  CString promptText;
};

class TAutoResolutionDialog : public TModalTemplateDialog {
public:
  explicit TAutoResolutionDialog(void* initParam = nullptr);
};

class TLowDiskWarningDialog : public TModalTemplateDialog {
public:
  explicit TLowDiskWarningDialog(void* initParam = nullptr);
  void SetPromptText(LPCSTR text);
};
