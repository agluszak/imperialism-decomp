#include "game/TPicture.h"

#include "game/CDib.h"
#include "game/CDibPal.h"
#include "game/ScopedMapQuickDrawContext.h"
#include "game/TView.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"

undefined4 SetPictureResourceIdAndRefresh_Impl(void);
// SYNTHETIC: IMPERIALISM 0x0048eeb0
// TPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x0048efa0
// TPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPicture, TControl)

// FUNCTION: IMPERIALISM 0x0048efc0
TPicture::TPicture()
    : TControl(), glyphBase84(-1), field86(0), bitmapId(0), field8A(0), field8C(0) {}

// SYNTHETIC: IMPERIALISM 0x0048f050
// TPicture::`scalar deleting destructor'
TPicture::~TPicture() {}

// Slot 0x44 override: draw the cached bitmap. 8bpp uncompressed pictures software-blit
// straight into the active QuickDraw surface; anything else realizes the default DIB
// palette and StretchDIBits-es to the active DC at the control's cached position.

// FUNCTION: IMPERIALISM 0x0048f3c0
void TPicture::ApplyRectSlot110(RECT* rectBuffer) {
  if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
    RECT bounds;
    this->BuildRectFromSlot158(&bounds);
  }

  if (GetActiveQuickDrawSurfaceDib() != 0 &&
      this->field8C->m_pInfoHeader->bmiHeader.biBitCount == 8 &&
      this->field8C->m_pInfoHeader->bmiHeader.biCompression == 0) {
    RECT bounds;
    this->BuildRectFromSlot158(&bounds);
    int width = bounds.right - bounds.left;
    int height = bounds.bottom - bounds.top;
    CDib* surface = GetActiveQuickDrawSurfaceDib();
    this->field8C->BlitSurfaceRectSkippingTransparentColor(surface, 0, 0, width, height,
                                                           bounds.left, bounds.top, -1);
    return;
  }

  g_pModuleLibraryCacheState->EnsureDefaultDibPalette()->SelectIntoDcAndRealize(
      GetActiveQuickDrawDc(), 0);

  int srcHeight = this->field8C->m_pInfoHeader->bmiHeader.biHeight;
  if (srcHeight <= 0) {
    srcHeight = -srcHeight;
  }
  {
    CPoint posForX;
    CPoint posForY;
    this->field8C->StretchDibitsRectToDc(
        GetActiveQuickDrawDc(), this->GetCachedPosPoint(&posForX)->x,
        this->GetCachedPosPoint(&posForY)->y, this->field34, this->field38, 0, 0,
        this->field8C->m_pInfoHeader->bmiHeader.biWidth, srcHeight);
  }
}

// Slot 0x08 override: allocate via slot 0x09 then copy city-dialog and picture-resource tail.

// FUNCTION: IMPERIALISM 0x0048f520
void TPicture::ResetPictureResourceEntry() {
  if (this->glyphBase84 != -1) {
    g_pModuleLibraryCacheState->ReleaseRecordById(this->glyphBase84);
  }
  this->glyphBase84 = -1;
  this->bitmapId = 0;
  this->field8A = 0;
  this->field8C = 0;
}

// FUNCTION: IMPERIALISM 0x0048f570
void TPicture::SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) {
  this->ResetPictureResourceEntry();
  this->glyphBase84 = nPictureId;
  if (nPictureId != -1) {
    this->field8C = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(nPictureId);
  }
  if (this->field8C == 0) {
    reinterpret_cast<void(__cdecl*)(int, int)>(SetPictureResourceIdAndRefresh_Impl)(this->field34,
                                                                                    this->field38);
    this->field8C = g_pModuleLibraryCacheState->BuildIndexedBmpResourceById(
        nPictureId, this->field34, this->field38, 0);
  }
  if (fRefreshNow) {
    this->RefreshControl();
  }
}

// FUNCTION: IMPERIALISM 0x0048f640
TObject* TPicture::ShallowClone() {
  TPicture* clone = static_cast<TPicture*>(ShallowFree());
  clone->CopyCityDialogStateFromSource(this);
  clone->hasCommandTagResource = hasCommandTagResource;
  clone->commandTagResourceByte = commandTagResourceByte;
  clone->field68 = field68;
  clone->field6C = field6C;
  clone->field70 = field70;
  clone->field74 = field74;
  clone->commandTagDefaultParam0 = commandTagDefaultParam0;
  clone->commandTagDefaultParam1 = commandTagDefaultParam1;
  clone->glyphBase84 = glyphBase84;
  clone->field86 = field86;
  clone->bitmapId = bitmapId;
  clone->field8A = field8A;
  clone->field8C = field8C;
  if (glyphBase84 != static_cast<short>(0xffff)) {
    unsigned int packedId =
        (static_cast<unsigned int>(static_cast<unsigned short>(field8A)) << 16) |
        static_cast<unsigned int>(static_cast<unsigned short>(glyphBase84));
    g_pModuleLibraryCacheState->IncrementDialogResourceRefCountByShortIdInRegistry(packedId);
  }
  return clone;
}
