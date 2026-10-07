#pragma once

#include "decomp_types.h"
#include "game/mfc.h"

class CDib;
class TBitmapResourceLoader;
struct TQuickDrawSurfaceContext;
struct TBitmapSurfaceNode;

void GetGWorld(TQuickDrawSurfaceContext** outContext, int* outFlags);
void SetGWorld(TQuickDrawSurfaceContext* context, int flags);
void DisposeQuickDrawMemoryDC(void);
TBitmapSurfaceNode** GetGWorldPixMap(TQuickDrawSurfaceContext* context);
unsigned char* GetPixBaseAddr(TBitmapSurfaceNode** pixMap);
short NewGWorld(TQuickDrawSurfaceContext** outContext, short bitDepth, const RECT* bounds,
                int unusedHint, int unusedArg4, int unusedArg5);
bool LockPixels(TBitmapSurfaceNode** pixMap);
void UnlockPixels(TBitmapSurfaceNode** pixMap);
void BlitBitmapResourceLoaderToActiveDc(TBitmapResourceLoader** handle, RECT* bounds);
int QDLoadResource(TBitmapResourceLoader** handle);
TQuickDrawSurfaceContext* LoadBitmapSurface(unsigned short resourceId);
