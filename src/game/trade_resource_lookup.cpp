#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00550d80
short GetResourceTypeRandomDrawBlockFlag(short resourceType) {
  const char* tableBase =
      reinterpret_cast<const char*>(static_cast<void*>(g_NavyOrderResourceDescriptorTable));
  const short* entry =
      reinterpret_cast<const short*>(tableBase + static_cast<unsigned int>(resourceType) * 9);
  return *entry;
}
