#include "game/list_box.h"

namespace {

static const unsigned int kGetControlWindowAddr = 0x006189dc;
static const unsigned int kEnsureSelectionAvailableAddr = 0x0060586d;
static const unsigned int kNormalizeItemDataAddr = 0x00605d99;
static const unsigned int kReleaseTempSharedRefAddr = 0x00605d71;

struct ListBoxControlWindowResolver {
  HWND ResolveControlWindow(undefined4 control_id);
};

struct ListBoxSharedStringRef {
  void EnsureSelectionAvailable();
  LPARAM NormalizeItemData(LRESULT raw_item_data);
  void ReleaseTempSharedRef(int value);
};

typedef HWND (ListBoxControlWindowResolver::*ResolveControlWindowMethod)(undefined4);
typedef void (ListBoxSharedStringRef::*EnsureSelectionAvailableMethod)();
typedef LPARAM (ListBoxSharedStringRef::*NormalizeItemDataMethod)(LRESULT);
typedef void (ListBoxSharedStringRef::*ReleaseTempSharedRefMethod)(int);

union ResolveControlWindowCast {
  unsigned int addr;
  ResolveControlWindowMethod method;
};

union EnsureSelectionAvailableCast {
  unsigned int addr;
  EnsureSelectionAvailableMethod method;
};

union NormalizeItemDataCast {
  unsigned int addr;
  NormalizeItemDataMethod method;
};

union ReleaseTempSharedRefCast {
  unsigned int addr;
  ReleaseTempSharedRefMethod method;
};

} // namespace

// FUNCTION: IMPERIALISM 0x00618df2
void __stdcall ListBox::AddOrUpdateItemData(ListBoxItemCount* item_count_ptr, undefined4 control_id,
                                            LPARAM* item_data_ptr) {
  ResolveControlWindowCast get_control_window;
  EnsureSelectionAvailableCast ensure_selection_available;
  NormalizeItemDataCast normalize_item_data;
  ReleaseTempSharedRefCast release_temp_shared_ref;
  ListBoxControlWindowResolver* window_resolver;
  ListBoxSharedStringRef* shared_ref;
  HWND listbox_hwnd;
  WPARAM sel_index;
  LRESULT raw_item_data;
  LPARAM normalized_item_data;

  get_control_window.addr = kGetControlWindowAddr;
  window_resolver = (ListBoxControlWindowResolver*)item_count_ptr;
  listbox_hwnd = (window_resolver->*(get_control_window.method))(control_id);
  shared_ref = (ListBoxSharedStringRef*)item_data_ptr;
  if (item_count_ptr->value == 0) {
    SendMessageA(listbox_hwnd, 0x18c, (WPARAM)0xffffffff, *item_data_ptr);
  } else {
    sel_index = SendMessageA(listbox_hwnd, 0x188, 0, 0);
    if (sel_index == (WPARAM)0xffffffff) {
      ensure_selection_available.addr = kEnsureSelectionAvailableAddr;
      (shared_ref->*(ensure_selection_available.method))();
    } else {
      raw_item_data = SendMessageA(listbox_hwnd, 0x18a, sel_index, 0);
      normalize_item_data.addr = kNormalizeItemDataAddr;
      normalized_item_data = (shared_ref->*(normalize_item_data.method))(raw_item_data);
      SendMessageA(listbox_hwnd, 0x189, sel_index, normalized_item_data);
    }

    release_temp_shared_ref.addr = kReleaseTempSharedRefAddr;
    (shared_ref->*(release_temp_shared_ref.method))(0xffffffff);
  }
}

// FUNCTION: IMPERIALISM 0x00618e72
void __stdcall SelectComboBoxItemByParam(int* state_flag, undefined4 owner_id, LPARAM* lparam_in) {
  ResolveControlWindowCast get_control_window;
  ListBoxControlWindowResolver* window_resolver;
  HWND target_hwnd;
  WPARAM item_index;

  get_control_window.addr = kGetControlWindowAddr;
  window_resolver = (ListBoxControlWindowResolver*)state_flag;
  target_hwnd = (window_resolver->*(get_control_window.method))(owner_id);
  if (*state_flag == 0) {
    item_index = SendMessageA(target_hwnd, 0x1a2, (WPARAM)0xffffffff, *lparam_in);
    if (item_index != (WPARAM)0xffffffff) {
      SendMessageA(target_hwnd, 0x186, item_index, 0);
    }
  } else {
    ListBox::AddOrUpdateItemData(reinterpret_cast<ListBoxItemCount*>(state_flag), owner_id,
                                 lparam_in);
  }
}
