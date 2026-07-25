#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeUiDriver is test-only and must not be included in the production build
#endif

class TView;

class RuntimeUiDriver {
public:
  static TView* FindControl(TView* root, int tag);
  static bool ActivateControl(TView* root, int tag);
  static bool ClickControl(TView* root, int tag);
  static bool ClickView(TView* view);
  static bool ClickViewPoint(TView* view, int localX, int localY);
};
