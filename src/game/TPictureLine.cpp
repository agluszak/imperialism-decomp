#include "game/TPictureLine.h"
#include "game/TPicture.h"
// SYNTHETIC: IMPERIALISM 0x00570030
// TPictureLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x00570060
// TPictureLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPictureLine, TLineData)

TPictureLine::TPictureLine() {}

// SYNTHETIC: IMPERIALISM 0x005700a0
// TPictureLine::`scalar deleting destructor'
TPictureLine::~TPictureLine() {}

// FUNCTION: IMPERIALISM 0x00570130
void TPictureLine::InstallViews(TView* panel, int* offsetLayout) {
  TPicture* picture = new TPicture();
  picture->InitializePictureEntryBaseAndRefresh(panel, offsetLayout, &field08, 5, 5,
                                                pictureResourceId10);
}
