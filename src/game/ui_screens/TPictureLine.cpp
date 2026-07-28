#include "game/ui_screens/TPictureLine.h"
#include "game/ui_core/TPicture.h"
// SYNTHETIC: IMPERIALISM 0x00570030
// TPictureLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x00570060
// TPictureLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TPictureLine, TLineData)

// SYNTHETIC: IMPERIALISM 0x005700a0
// TPictureLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005700d0
TPictureLine::~TPictureLine() {}

// FUNCTION: IMPERIALISM 0x00570130
void TPictureLine::InstallViews(TView* panel, int* offsetLayout) {
  TPicture* picture = new TPicture();
  picture->IPicture(panel, offsetLayout, &layoutWidth, 5, 5, pictureResourceId10);
}
