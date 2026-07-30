#include "RuntimeUiDriver.h"

#include "RuntimeObservations.h"
#include "RuntimeObservation.h"
#include "RuntimeTestDriver.h"

#include "game/ImperialismApp.h"
#include "game/globals/view_registries.h"
#include "game/ui_core/CIncludeView.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/mfc.h"

namespace {

enum { kRuntimeActionQueueCapacity = 16 };

PendingRuntimeAction g_runtimeActions[kRuntimeActionQueueCapacity];
unsigned int g_runtimeActionHead;
unsigned int g_runtimeActionCount;
unsigned int g_pendingObservationKinds;
bool g_observationActionQueued;

void InitializeSelector(RuntimeControlSelector& selector, CRuntimeClass* expectedClass,
                        int expectedEvent) {
  selector.tagCount = 0;
  selector.expectedClass = expectedClass;
  selector.expectedEvent = expectedEvent;
  for (unsigned int index = 0; index < RuntimeControlSelector::kMaxTagPath; ++index) {
    selector.tagPath[index] = 0;
  }
}

void FourCcText(unsigned int tag, char text[5]) {
  text[0] = static_cast<char>(tag >> 24);
  text[1] = static_cast<char>(tag >> 16);
  text[2] = static_cast<char>(tag >> 8);
  text[3] = static_cast<char>(tag);
  text[4] = 0;
}

TView* FindDirectChild(TView* parent, int tag) {
  if (parent == 0 || parent->childList44 == 0) {
    return 0;
  }
  TView* match = 0;
  POSITION position = parent->childList44->GetHeadPosition();
  while (position != 0) {
    TView* child = parent->childList44->GetNext(position);
    if (child->controlTag == tag) {
      if (match != 0) {
        return 0;
      }
      match = child;
    }
  }
  return match;
}

bool IsAttachedToRoot(TView* view, TView* root) {
  while (view != 0) {
    if (view == root) {
      return true;
    }
    view = view->ownerContext;
  }
  return false;
}

bool IsCurrentScreenRoot(TView* root) {
  TView* mainView = RuntimeMainView();
  if (root != 0 && (root == mainView || IsAttachedToRoot(root, mainView))) {
    return true;
  }
  POSITION position = g_ModalViewStack.GetHeadPosition();
  while (position != 0) {
    TWindow* modal = g_ModalViewStack.GetNext(position);
    if (root == modal || IsAttachedToRoot(root, modal)) {
      return true;
    }
  }
  position = g_LiveViewRegistry.GetHeadPosition();
  while (position != 0) {
    TWindow* window = g_LiveViewRegistry.GetNext(position);
    if (root == window || IsAttachedToRoot(root, window)) {
      return true;
    }
  }
  return false;
}

void SetFailure(CString* failure, const char* reason, const RuntimeControlSelector& selector,
                TView* found) {
  if (failure == 0) {
    return;
  }
  *failure = reason;
  *failure += "\nexpected control:\n  path:";
  for (unsigned int index = 0; index < selector.tagCount; ++index) {
    char tag[5];
    FourCcText(static_cast<unsigned int>(selector.tagPath[index]), tag);
    CString segment;
    segment.Format("%s%s", index == 0 ? " " : "/", tag);
    *failure += segment;
  }
  CString details;
  details.Format("\n  class: %s\n  event: 0x%04x\nfound:\n  class: %s\n  visible-actionable: %d"
                 "\n  input-enabled: %d\n  input-gate: %d\n  event: 0x%04x",
                 selector.expectedClass != 0 ? selector.expectedClass->m_lpszClassName : "TControl",
                 selector.expectedEvent, RuntimeClassName(found),
                 found != 0 ? found->IsActionable() : 0, found != 0 ? found->IsEnabled() : 0,
                 found != 0 ? found->EvaluateControlInputGate() : 0,
                 found != 0 && found->IsKindOf(RUNTIME_CLASS(TControl)) != 0
                     ? static_cast<TControl*>(found)->GetEventNumber()
                     : -1);
  *failure += details;
}

TView* MatchPathAt(TView* candidate, const RuntimeControlSelector& selector) {
  if (candidate == 0 || candidate->controlTag != selector.tagPath[0]) {
    return 0;
  }
  TView* current = candidate;
  for (unsigned int index = 1; index < selector.tagCount && current != 0; ++index) {
    current = FindDirectChild(current, selector.tagPath[index]);
  }
  return current;
}

void FindPathMatches(TView* view, const RuntimeControlSelector& selector, TView*& match,
                     unsigned int& matchCount) {
  if (view == 0) {
    return;
  }
  TView* candidate = MatchPathAt(view, selector);
  if (candidate != 0) {
    match = candidate;
    ++matchCount;
  }
  if (view->childList44 == 0) {
    return;
  }
  POSITION position = view->childList44->GetHeadPosition();
  while (position != 0) {
    FindPathMatches(view->childList44->GetNext(position), selector, match, matchCount);
  }
}

TView* ResolvePath(TView* root, const RuntimeControlSelector& selector) {
  if (root == 0 || selector.tagCount == 0) {
    return 0;
  }
  TView* match = 0;
  unsigned int matchCount = 0;
  FindPathMatches(root, selector, match, matchCount);
  return matchCount == 1 ? match : 0;
}

TView* CurrentActionRoot(const RuntimeControlSelector& selector) {
  if (!g_ModalViewStack.IsEmpty()) {
    TWindow* modal = g_ModalViewStack.GetHead();
    if (ResolvePath(modal, selector) != 0) {
      return modal;
    }
  }
  TView* mainView = RuntimeMainView();
  return ResolvePath(mainView, selector) != 0 ? mainView : 0;
}

} // namespace

RuntimeControlSelector::RuntimeControlSelector() {
  InitializeSelector(*this, 0, -1);
}

RuntimeControlSelector::RuntimeControlSelector(int tag0, CRuntimeClass* controlClass,
                                               int eventNumber) {
  InitializeSelector(*this, controlClass, eventNumber);
  tagPath[0] = tag0;
  tagCount = 1;
}

RuntimeControlSelector::RuntimeControlSelector(int tag0, int tag1, CRuntimeClass* controlClass,
                                               int eventNumber) {
  InitializeSelector(*this, controlClass, eventNumber);
  tagPath[0] = tag0;
  tagPath[1] = tag1;
  tagCount = 2;
}

RuntimeControlSelector::RuntimeControlSelector(int tag0, int tag1, int tag2,
                                               CRuntimeClass* controlClass, int eventNumber) {
  InitializeSelector(*this, controlClass, eventNumber);
  tagPath[0] = tag0;
  tagPath[1] = tag1;
  tagPath[2] = tag2;
  tagCount = 3;
}

TControl* RuntimeUiDriver::RequireControl(TView* root, const RuntimeControlSelector& selector,
                                          CString* failure) {
  if (!IsCurrentScreenRoot(root)) {
    SetFailure(failure, "control root does not belong to the current screen", selector, root);
    return 0;
  }
  TView* found = ResolvePath(root, selector);
  if (found == 0) {
    SetFailure(failure, "control path is missing or ambiguous", selector, 0);
    return 0;
  }
  if (found->IsKindOf(RUNTIME_CLASS(TControl)) == 0) {
    SetFailure(failure, "resolved object is not a TControl", selector, found);
    return 0;
  }
  if (selector.expectedClass != 0 && found->IsKindOf(selector.expectedClass) == 0) {
    SetFailure(failure, "resolved control has the wrong runtime class", selector, found);
    return 0;
  }
  TControl* control = static_cast<TControl*>(found);
  // ORACLE: what makes a control clickable is TControl's own mouse contract, not TView's.
  // TControl::PointInBoundsAndActionable (0x0048e940) overrides TView's (0x0048c6d0) and drops
  // its IsActionable() test, leaving a pure bounds hit; TView::HandleMouseDown/HandleMouseUp
  // (0x0048c450/0x0048c590) call that virtual on each child and then gate delivery on
  // PrepareForDrawing() (0x0048b770, unconditionally 1) and IsEnabled(). So for anything that IS
  // a TControl, viewEnabled plays no part in whether a click arrives -- `enabled` does.
  //
  // This is why retail can use a control as an invisible hit region over artwork that already
  // draws the button: the main-menu buttons at 0x00455e12-0x004561d0 and the Deal Book's 'mark'
  // bookmark (built with SetEnabled(0,0) at 0x00431c98, then SetState(1,0) by
  // TDealBookPicture::SwitchPages 0x005bc14c, whose DoEvent branch is reachable only in that
  // state) are both built viewEnabled == 0 and are both meant to be clicked.
  //
  // Restricting the exemption to exact TControl instances -- as this check first did, from the
  // main-menu evidence alone -- made every TControl *subclass* answer to a predicate the game
  // never applies to it.
  if (control->IsEnabled() == 0) {
    SetFailure(failure, "resolved control is not enabled for input", selector, found);
    return 0;
  }
  if (selector.expectedEvent >= 0 && control->GetEventNumber() != selector.expectedEvent) {
    SetFailure(failure, "resolved control has the wrong event number", selector, found);
    return 0;
  }
  return control;
}

bool RuntimeUiDriver::Activate(TView* root, const RuntimeControlSelector& selector,
                               CString* failure) {
  TControl* control = RequireControl(root, selector, failure);
  if (control == 0) {
    return false;
  }
  control->HandleEvent(control->GetEventNumber(), control, 0);
  return true;
}

bool RuntimeUiDriver::QueueAction(const PendingRuntimeAction& action, CString* failure) {
  if (g_runtimeActionCount == kRuntimeActionQueueCapacity) {
    if (failure != 0) {
      *failure = "runtime semantic action queue is full";
    }
    return false;
  }
  unsigned int tail = (g_runtimeActionHead + g_runtimeActionCount) % kRuntimeActionQueueCapacity;
  g_runtimeActions[tail] = action;
  ++g_runtimeActionCount;
  CIncludeView* host = GetMainViewHostFromActiveThread();
  if (host == 0 || host->m_hWnd == 0 || PostMessageA(host->m_hWnd, WM_RUNTIME_ACTION, 0, 0) == 0) {
    --g_runtimeActionCount;
    if (failure != 0) {
      *failure = "could not post runtime semantic action message";
    }
    return false;
  }
  return true;
}

bool RuntimeUiDriver::PostActivate(const RuntimeControlSelector& selector, CString* failure) {
  PendingRuntimeAction action;
  action.selector = selector;
  action.kind = kRuntimeActionActivate;
  return QueueAction(action, failure);
}

bool RuntimeUiDriver::PostBarrier(CString* failure) {
  PendingRuntimeAction action;
  action.kind = kRuntimeActionBarrier;
  return QueueAction(action, failure);
}

bool RuntimeUiDriver::PostObservation(unsigned int observationKinds, CString* failure) {
  g_pendingObservationKinds |= observationKinds;
  if (g_observationActionQueued) {
    return true;
  }
  PendingRuntimeAction action;
  action.kind = kRuntimeActionObservation;
  g_observationActionQueued = true;
  if (!QueueAction(action, failure)) {
    g_observationActionQueued = false;
    g_pendingObservationKinds = 0;
    return false;
  }
  return true;
}

bool RuntimeUiDriver::HandlePostedAction(CString* failure) {
  if (g_runtimeActionCount == 0) {
    if (failure != 0) {
      *failure = "runtime semantic action message had no queued action";
    }
    return false;
  }
  PendingRuntimeAction action = g_runtimeActions[g_runtimeActionHead];
  g_runtimeActionHead = (g_runtimeActionHead + 1) % kRuntimeActionQueueCapacity;
  --g_runtimeActionCount;
  if (action.kind == kRuntimeActionBarrier) {
    RuntimeTestDriver::Observe(kObserveRuntimeBarrier);
    return true;
  }
  if (action.kind == kRuntimeActionObservation) {
    unsigned int observationKinds = g_pendingObservationKinds;
    g_pendingObservationKinds = 0;
    g_observationActionQueued = false;
    RuntimeTestDriver::Observe(observationKinds);
    return true;
  }
  TView* root = CurrentActionRoot(action.selector);
  if (root == 0) {
    SetFailure(failure, "queued control path is not present in the current UI tree",
               action.selector, 0);
    return false;
  }
  if (action.kind == kRuntimeActionActivate) {
    return Activate(root, action.selector, failure);
  }
  if (failure != 0) {
    *failure = "queued runtime action has an unknown kind";
  }
  return false;
}
