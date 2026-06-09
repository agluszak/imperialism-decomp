#include "game/CCmdUI.h"

// FUNCTION: IMPERIALISM 0x00606ddd
void CCmdUI::SetCheck(u32 checked_state) {
  int menu_context = *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0xc);
  if (menu_context == 0) {
    int owner_object = *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x14);
    int owner_hwnd = owner_object != 0 ? *reinterpret_cast<int*>(owner_object + 0x1c) : 0;
    u32 style_bits = SendMessageA(reinterpret_cast<hwnd_t>(owner_hwnd), 0x87, 0, 0);
    if ((style_bits & 0x2000U) != 0) {
      SendMessageA(reinterpret_cast<hwnd_t>(owner_hwnd), 0xF1, checked_state, 0);
    }
    return;
  }

  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x10) == 0) {
    u32 menu_item_id = *reinterpret_cast<u32*>(reinterpret_cast<char*>(this) + 8);
    hmenu_t menu_handle = *reinterpret_cast<hmenu_t*>(menu_context + 4);
    u32 flags = 4U | ((checked_state != 0) ? 8U : 0U);
    CheckMenuItem(menu_handle, menu_item_id, flags);
  }
}
