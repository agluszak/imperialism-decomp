#include "game/app/ui_resource_builder.h"

#include "game/ui_core/TCluster.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TEditText.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TPicture.h"
#include "game/ui_core/TStaticText.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"

#include "game/app/ui_resource_builder_inlines_before_reset.h"

// FUNCTION: IMPERIALISM 0x0041b420
TUiStyleBytes* TUiStyleBytes::Reset() {
  // MATCH: preserve the retail byte-store sequence without restoring the
  // obsolete anonymous-union representation.
  unsigned char* bytes = reinterpret_cast<unsigned char*>(this);
  bytes[0] = 0;
  bytes[1] = 0;
  bytes[2] = 0;
  bytes[3] = 0;
  bytes[4] = 0;
  bytes[5] = 0;
  bytes[6] = 0;
  bytes[7] = 0;
  return this;
}

#include "game/app/ui_resource_builder_inlines_after_reset.h"

// 0x479a80 / 0x479b00 ("Pop/PushUiResourcePoolNode") are the out-of-line template COMDATs
// of CList<TView*,TView*>::RemoveTail / ::AddTail operating on g_UiWidgetBuildStack006a13e0
// - see global_data_tables.h. The builders call them directly
// (g_UiWidgetBuildStack006a13e0.RemoveTail()/.AddTail(node)); claimed here as templates.

// The early builders also call the const GetTail specialization to recover the current
// TView* from the stack's tail node.
// TEMPLATE: IMPERIALISM 0x00426f60
// ?GetTail@?$CList@PAVTView@@PAV1@@@QBEPAVTView@@XZ

// TEMPLATE: IMPERIALISM 0x00479a80
// ?RemoveTail@?$CList@PAVTView@@PAV1@@@QAEPAVTView@@XZ

// The builder TU emits two identical AddTail COMDATs. 0x426ec0 is reached by the
// early giant dialog builders; 0x479b00 is the later copy used by the shared stack helpers.
// TEMPLATE: IMPERIALISM 0x00479b00
// ?AddTail@?$CList@PAVTView@@PAV1@@@QAEPAU__POSITION@@PAVTView@@@Z

template TView* CList<TView*, TView*>::GetTail() const;
template TView* CList<TView*, TView*>::RemoveTail();
template POSITION CList<TView*, TView*>::AddTail(TView*);

// FUNCTION: IMPERIALISM 0x00479e10
int __stdcall ClearUiResourceEntryDwords(int* destination, int count) {
  while (count != 0) {
    *destination = 0;
    ++destination;
    --count;
  }
  return 0;
}
