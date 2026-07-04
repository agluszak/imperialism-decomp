#include "game/TStatusPicture.h"

// SYNTHETIC: IMPERIALISM 0x0043d870
// TStatusPicture::`scalar deleting destructor'
TStatusPicture::~TStatusPicture() {}
// SYNTHETIC: IMPERIALISM 0x00593e80
// TStatusPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x00593f00
// TStatusPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TStatusPicture, TPicture)

TStatusPicture::TStatusPicture() {}

// FUNCTION: IMPERIALISM 0x00593f20
void TStatusPicture::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005942f0
void TStatusPicture::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}

// FUNCTION: IMPERIALISM 0x00594540
void TStatusPicture::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x00594c00
void TStatusPicture::SortSevenEntriesAndUpdatePictureWidgets() {
  // Selection sort: move the highest-value entry with a live id to the front on each pass;
  // empty (-1) ids sink toward the end.
  int* valOuter = values94;
  short* idOuter = pictureIds_b0;
  int outer = 1;
  do {
    if (outer < 7) {
      int* valInner = valOuter + 1;
      short* idInner = idOuter + 1;
      int remaining = 7 - outer;
      do {
        if (*idInner != -1) {
          short outerId = *idOuter;
          if (outerId == -1 || *valInner > *valOuter) {
            *idOuter = *idInner;
            *idInner = outerId;
            int outerVal = *valOuter;
            *valOuter = *valInner;
            *valInner = outerVal;
          }
        }
        idInner = idInner + 1;
        valInner = valInner + 1;
        remaining = remaining - 1;
      } while (remaining != 0);
    }
    idOuter = idOuter + 1;
    valOuter = valOuter + 1;
    outer = outer + 1;
  } while (outer < 7);

  // Push each sorted entry's picture id into its child picture widget.
  short* idPtr = pictureIds_b0;
  int index = 0;
  do {
    if (*idPtr != -1) {
      TPicture* widget = static_cast<TPicture*>(ResolveControlByTag(index + 0x70696330));
      widget->AssertValid();
      widget->SetPictureResourceIdAndRefresh(static_cast<short>(*idPtr + 0x10d7), true);
    }
    index = index + 1;
    idPtr = idPtr + 1;
  } while (index < 7);
}
