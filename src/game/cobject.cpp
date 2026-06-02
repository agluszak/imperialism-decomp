#include "game/cobject.h"

// Minimal out-of-line definitions so MSVC emits the CObject vtable (mapped to
// 0x0066fec4 via the // VTABLE marker). These base bodies are placeholders; the
// real CObject methods live at their own addresses and are owned separately.
void* CObject::GetRuntimeClass() { return 0; }
int CObject::CObjectSlot08() { return 0; }
void CObject::CObjectSlot0c() {}
void CObject::CObjectSlot10() {}
