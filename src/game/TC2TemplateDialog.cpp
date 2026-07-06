#include "game/TC2TemplateDialog.h"

#include "game/TViewMgr.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x0047cfd0
TC2TemplateDialog::TC2TemplateDialog(void* initParam) {
  InitializeDialogTemplateFromId(0xc2, initParam);
  hasCommandTagResource = 0;
  commandTagResourceByte = 0;
  padding_65_to_67[0] = 0;
  padding_65_to_67[1] = 0;
  padding_65_to_67[2] = 0;
}

TC2TemplateDialog::~TC2TemplateDialog() {}

// The ID_800C command: put up the C2 template dialog with a 0..6 city-view slider and a
// 10-row list box (each row carries a turn-event code as item data). On OK, dispatch the
// selected row's event code with the slider position through the UI runtime.
// FUNCTION: IMPERIALISM 0x004851b0
void TMacViewMgr_OnCommand_ID_800C_ShowCityViewSelectionDialog(void) {
  TC2TemplateDialog dialog(0);
  dialog.PrepareAndCreateModalFromTemplate();

  dialog.slider.SetRange(0, 6, FALSE);
  HWND hSlider = dialog.slider.m_hWnd;
  HWND hList = dialog.listbox.m_hWnd;

  ::SendMessageA(hSlider, TBM_SETPOS, 1, g_pUiRuntimeContext->pad06);

  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694e18);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694e08);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694df8);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694de8);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694dd4);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694dbc);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694da4);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694d94);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694d80);
  ::SendMessageA(hList, LB_ADDSTRING, 0, 0x694d68);

  ::SendMessageA(hList, LB_SETITEMDATA, 0, 0x3b8);
  ::SendMessageA(hList, LB_SETITEMDATA, 1, 0x3b8);
  ::SendMessageA(hList, LB_SETITEMDATA, 2, 0x7d8);
  ::SendMessageA(hList, LB_SETITEMDATA, 3, 0x2134);
  ::SendMessageA(hList, LB_SETITEMDATA, 4, 0x7d9);
  ::SendMessageA(hList, LB_SETITEMDATA, 5, 0x7d8);
  ::SendMessageA(hList, LB_SETITEMDATA, 6, 0x7db);
  ::SendMessageA(hList, LB_SETITEMDATA, 7, 0x2260);
  ::SendMessageA(hList, LB_SETITEMDATA, 8, 0x7dd);
  ::SendMessageA(hList, LB_SETITEMDATA, 9, 0x7de);

  ::SendMessageA(hList, LB_SETCURSEL, 4, 0);

  if (dialog.FinalizeModalDialogAndRestoreOwnerFocus() == 1) {
    LRESULT sliderPos = ::SendMessageA(hSlider, TBM_GETPOS, 0, 0);
    WPARAM selectedRow = ::SendMessageA(hList, LB_GETCURSEL, 0, 0);
    LRESULT eventCode = ::SendMessageA(hList, LB_GETITEMDATA, selectedRow, 0);
    g_pUiRuntimeContext->DispatchTurnEventSlot4C(static_cast<short>(eventCode),
                                                 static_cast<int>(sliderPos));
  }
}
