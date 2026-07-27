#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeUiDriver is test-only and must not be included in the production build
#endif

class TView;

class RuntimeUiDriver {
public:
  static TView* FindControl(TView* root, int tag);
  static bool ActivateControlSemantically(TView* root, int tag);
  static bool ClickControlThroughNativeMessages(TView* root, int tag);
  static bool ClickViewThroughNativeMessages(TView* view);
  static bool ClickViewPointThroughNativeMessages(TView* view, int localX, int localY);
};
