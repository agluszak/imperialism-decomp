#include "game/TPictureResourceEntryBase.h"

#include "game/TView.h"
#include "game/mfc.h"

undefined4 IncrementDialogResourceRefCountByShortIdInRegistry(void);
undefined4 thunk_DecrementDialogResourceRefCountByShortIdAndCleanup(void);
undefined4 thunk_LoadBmpResourceByIdCached(void);
undefined4 BuildIndexedBmpResourceById(void);
undefined4 SetPictureResourceIdAndRefresh_Impl(void);





// FUNCTION: IMPERIALISM 0x0048efc0
TPictureResourceEntryBase::TPictureResourceEntryBase() : TControl() {}





// FUNCTION: IMPERIALISM 0x0048f250
TPictureResourceEntryBase::~TPictureResourceEntryBase() {}

// Slot 0x44 override (picture-resource branch): ctrl-key hint overlay helper.




// FUNCTION: IMPERIALISM 0x0048f3c0
void TPictureResourceEntryBase::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer;
}

// Slot 0x08 override: allocate via slot 0x09 then copy city-dialog and picture-resource tail.





// FUNCTION: IMPERIALISM 0x0048f520
void TPictureResourceEntryBase::ResetPictureResourceEntry() {
  if (this->glyphBase84 != -1) {
    reinterpret_cast<void(__cdecl*)(short)>(thunk_DecrementDialogResourceRefCountByShortIdAndCleanup)(
        this->glyphBase84);
  }
  this->glyphBase84 = -1;
  this->bitmapId = 0;
  this->field8A = 0;
  this->field8C = 0;
}




// FUNCTION: IMPERIALISM 0x0048f570
void TPictureResourceEntryBase::SetPictureResourceIdAndRefresh(short nPictureId, bool fRefreshNow) {
  this->ResetPictureResourceEntry();
  this->glyphBase84 = nPictureId;
  if (nPictureId != -1) {
    this->field8C = reinterpret_cast<int(__cdecl*)(short)>(thunk_LoadBmpResourceByIdCached)(nPictureId);
  }
  if (this->field8C == 0) {
    reinterpret_cast<void(__cdecl*)(int, int)>(SetPictureResourceIdAndRefresh_Impl)(
        this->field34, this->field38);
    this->field8C = reinterpret_cast<int(__cdecl*)(short)>(BuildIndexedBmpResourceById)(nPictureId);
  }
  if (fRefreshNow) {
    this->RefreshControl();
  }
}




// FUNCTION: IMPERIALISM 0x0048f640
TObject* TPictureResourceEntryBase::ShallowClone() {
  TPictureResourceEntryBase* clone =
      static_cast<TPictureResourceEntryBase*>(ShallowFree());
  clone->CopyCityDialogStateFromSource(this);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(clone) + 0x60) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x60);
  reinterpret_cast<char*>(clone)[0x64] = reinterpret_cast<char*>(this)[0x64];
  *reinterpret_cast<int*>(reinterpret_cast<char*>(clone) + 0x68) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x68);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(clone) + 0x6c) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x6c);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(clone) + 0x70) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x70);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(clone) + 0x74) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x74);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(clone) + 0x78) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x78);
  *reinterpret_cast<int*>(reinterpret_cast<char*>(clone) + 0x7c) =
      *reinterpret_cast<int*>(reinterpret_cast<char*>(this) + 0x7c);
  clone->glyphBase84 = glyphBase84;
  clone->field86 = field86;
  clone->bitmapId = bitmapId;
  clone->field8A = field8A;
  clone->field8C = field8C;
  if (glyphBase84 != static_cast<short>(0xffff)) {
    unsigned int packedId =
        (static_cast<unsigned int>(field8C) << 16) |
        static_cast<unsigned int>(static_cast<unsigned short>(glyphBase84));
    reinterpret_cast<void(__cdecl*)(unsigned int)>(IncrementDialogResourceRefCountByShortIdInRegistry)(
        packedId);
  }
  return clone;
}



// FUNCTION: IMPERIALISM 0x005708c0
bool TPictureResourceEntryBase::IsSelected(short value, bool refreshNow) {
  (void)value;
  (void)refreshNow;
  RECT rect = this->BuildRectFromSlot158();
  return RedrawWindow(reinterpret_cast<HWND>(this->nativeWindow50->m_hWnd), &rect, NULL,
                      RDW_INVALIDATE | RDW_UPDATENOW);
}

