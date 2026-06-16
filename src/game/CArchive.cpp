#include "game/mfc.h"

extern "C" {
char g_pClassDescTNetMgr = 0;
}

// FUNCTION: IMPERIALISM 0x005e33c0
void* GetTNetMgrClassNamePointer() {
  return &g_pClassDescTNetMgr;
}

// LIBRARY: IMPERIALISM 0x005e6d04
// CArchive::operator<<

// LIBRARY: IMPERIALISM 0x005e6d27
// CArchive::operator<<

// LIBRARY: IMPERIALISM 0x005e6d4e
// CArchive::operator<<

// LIBRARY: IMPERIALISM 0x005e6da3
// CArchive::operator>>

// LIBRARY: IMPERIALISM 0x005e6dd6
// CArchive::operator>>

// LIBRARY: IMPERIALISM 0x00611d18
// CArchive::Close

// LIBRARY: IMPERIALISM 0x00611d26
// CArchive::Read

// LIBRARY: IMPERIALISM 0x00611e34
// CArchive::Write

// LIBRARY: IMPERIALISM 0x00611f3e
// CArchive::FillBuffer

// LIBRARY: IMPERIALISM 0x00612000
// CArchive::WriteCount

// LIBRARY: IMPERIALISM 0x006121cd
// CArchive::CheckCount

// LIBRARY: IMPERIALISM 0x006121e1
// CArchive::WriteObject

// LIBRARY: IMPERIALISM 0x0061225e
// CArchive::ReadObject

// LIBRARY: IMPERIALISM 0x00612315
// CArchive::MapObject

// LIBRARY: IMPERIALISM 0x0061240d
// CArchive::WriteClass
