#include "game/TPictureResourceEntryBase.h"

#include "game/TView.h"
#include "game/win_rect.h"

undefined4 IncrementDialogResourceRefCountByShortIdInRegistry(void);

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
// FUNCTION: IMPERIALISM 0x0048f640
void* TPictureResourceEntryBase::CloneEngineerDialogStateToNewInstance() {
  TPictureResourceEntryBase* clone =
      static_cast<TPictureResourceEntryBase*>(HandleTurnEventVtableSlot24CopyPayloadBuffer());
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
