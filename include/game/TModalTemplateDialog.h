#pragma once

#include "game/TControl.h"
#include "game/mfc.h"

// Template-driven modal dialog controller. Extends TControl (Ghidra types the stack object as
// TControl and routes template init / finalize through TControl methods). Modal-create scratch
// fields reuse TView members during setup (controlValue3c, stylePayload48, field5c, absoluteX); extended state
// lives in the members below.
class TModalTemplateDialog : public TControl {
public:
  TModalTemplateDialog();
  ~TModalTemplateDialog() override;

  TControl* InitializeDialogTemplateFromId(UINT templateId, void* initParam);
  int PrepareAndCreateModalFromTemplate();
  int FinalizeModalDialogAndRestoreOwnerFocus();
  void CleanupModalCreateState();
  void DestroyListBoxAndHotKeyChildren();
  BOOL UpdateData(BOOL saveAndValidate);

  int DialogResult() const {
    return absoluteX;
  }

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

class TLowDiskWarningDialog : public TModalTemplateDialog {
public:
  explicit TLowDiskWarningDialog(void* initParam = nullptr);
  void SetPromptText(LPCSTR text);
};
