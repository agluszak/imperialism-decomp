#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeUiDriver is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

class CString;
class TControl;
class TView;
struct CRuntimeClass;

const UINT WM_RUNTIME_ACTION = WM_APP + 0x173;

enum RuntimeActionKind { kRuntimeActionActivate, kRuntimeActionBarrier, kRuntimeActionObservation };

struct RuntimeControlSelector {
  enum { kMaxTagPath = 8 };

  RuntimeControlSelector();
  explicit RuntimeControlSelector(int tag0, CRuntimeClass* controlClass = 0, int eventNumber = -1);
  RuntimeControlSelector(int tag0, int tag1, CRuntimeClass* controlClass = 0, int eventNumber = -1);
  RuntimeControlSelector(int tag0, int tag1, int tag2, CRuntimeClass* controlClass = 0,
                         int eventNumber = -1);

  int tagPath[kMaxTagPath];
  unsigned int tagCount;
  CRuntimeClass* expectedClass;
  int expectedEvent;
};

struct PendingRuntimeAction {
  RuntimeControlSelector selector;
  RuntimeActionKind kind;
};

class RuntimeUiDriver {
public:
  static TControl* RequireControl(TView* root, const RuntimeControlSelector& selector,
                                  CString* failure);
  static bool Activate(TView* root, const RuntimeControlSelector& selector, CString* failure = 0);
  static bool PostActivate(const RuntimeControlSelector& selector, CString* failure = 0);
  static bool PostBarrier(CString* failure = 0);
  static bool PostObservation(unsigned int observationKinds, CString* failure = 0);
  static bool HandlePostedAction(CString* failure = 0);

private:
  static bool QueueAction(const PendingRuntimeAction& action, CString* failure);
};
