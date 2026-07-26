#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

class CDib;
class TBitmapResourceLoader;
struct TQuickDrawSurfaceContext;
struct TBitmapSurfaceNode;

void GetGWorld(TQuickDrawSurfaceContext** outContext, int* outFlags);
void SetGWorld(TQuickDrawSurfaceContext* context, int flags);
void DisposeQuickDrawMemoryDC(void); // 0x00496160
TBitmapSurfaceNode** GetGWorldPixMap(TQuickDrawSurfaceContext* context);
unsigned char* GetPixBaseAddr(TBitmapSurfaceNode** pixMap);
short NewGWorld(TQuickDrawSurfaceContext** outContext, short bitDepth, const RECT* bounds,
                int unusedHint, int unusedArg4, int unusedArg5);
unsigned char LockPixels(TBitmapSurfaceNode** pixMap);
void UnlockPixels(TBitmapSurfaceNode** pixMap);
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds);
// Mac Resource Manager LoadResource emulation: a no-op returning noErr(0) — the
// Windows "handles" are always resident. Callers invoke it before dereferencing a
// resource-loader handle, exactly where the Mac source called LoadResource(Handle).
// (QD prefix: Win32 LoadResource collides.)
int QDLoadResource(TBitmapResourceLoader** handle);
TQuickDrawSurfaceContext*
LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(unsigned short resourceId);
