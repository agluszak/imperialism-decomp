#include "game/TMovieView.h"

// FUNCTION: IMPERIALISM 0x005e2210
CRuntimeClass* TMovieView::GetRuntimeClass() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005e22f0
// TMovieView::`scalar deleting destructor'
TMovieView::~TMovieView() {}

// FUNCTION: IMPERIALISM 0x005e23f0
void TMovieView::NoOpUiLifecycleHook(int arg) {}

// FUNCTION: IMPERIALISM 0x005e2490
void TMovieView::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x005e2520
char TMovieView::DispatchUiMouseMoveToChildren(CPoint* point, int arg2, int arg3, int arg4) {
  (void)point;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  return 0;
}

// FUNCTION: IMPERIALISM 0x0060a60a
int TMovieView::RunModalLoop(TMovieView* view, unsigned char loopKind) {
  (void)view;
  (void)loopKind;
  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0) > 0) {
    if (AfxGetApp() == nullptr || !AfxGetApp()->PreTranslateMessage(&msg)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }
  return 0;
}
