#include "game/ui_screens/TPictureLine.h"
#include "game/ui_core/TPicture.h"

IMPLEMENT_DYNCREATE(TPictureLine, TLineData)

// FUNCTION: IMPERIALISM 0x005700f0
void TPictureLine::SetPictureLineRowBoundsAndResource(short rowArg, short colArg, int* bounds,
                                                      short pictureResourceId) {
  ILineData(rowArg, colArg, bounds);
  this->pictureResourceId = pictureResourceId;
}

// FUNCTION: IMPERIALISM 0x00570130
void TPictureLine::InstallViews(TView* panel, int* offsetLayout) {
  TPicture* picture = new TPicture();
  picture->IPicture(panel, offsetLayout, &layoutWidth, 5, 5, pictureResourceId);
}
