#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x0041b420
unsigned char* ZeroUiResourceContextStyleBytes(unsigned char* buffer) {
  buffer[0] = 0;
  buffer[1] = 0;
  buffer[2] = 0;
  buffer[3] = 0;
  buffer[4] = 0;
  buffer[5] = 0;
  buffer[6] = 0;
  buffer[7] = 0;
  return buffer;
}

// 0x479a80 / 0x479b00 ("Pop/PushUiResourcePoolNode") are this TU's out-of-line twin copies
// of CList<void*,void*>::RemoveTail / ::AddTail operating on g_UiWidgetBuildStack006a13e0
// — see global_data_tables.h. They are template COMDATs, not game functions; their
// addresses stay with autogen stubs (template twin-copy reccmp gap).
