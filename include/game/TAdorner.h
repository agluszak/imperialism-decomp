#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TView;

// A base class for pluggable draw/layout/hit-test decorations (Mac naming: an "adorner"
// attaches optional rendering behavior to a host view/control without subclassing it).
// No owner has been recovered yet in ported source -- there are currently zero `new
// TAdorner`/`new TColorFill` call sites and zero other references to either class anywhere
// in this codebase, so nothing here has been shown to actually attach or use one. The one
// piece of hard evidence is TColorFill's slot 0x0c assert string (0x00696b44,
// "D:\Ambit\Cross\UDisplayMgr.cpp", the same original source file TDisplayMgr.cpp already
// models via its own kSourceFileUDisplayMgr constant) -- both classes were compiled from
// that same cross-platform source file, which is at least circumstantial evidence
// TDisplayMgr is the eventual owner, though no owning field/attacher has been found to
// confirm it.
// VTABLE: IMPERIALISM 0x0064bdd0
class TAdorner : public TObject {
public:
  DECLARE_DYNCREATE(TAdorner)
  virtual ~TAdorner() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x49d990
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x49d960
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // The seven adorner hooks follow the MacApp declaration order. Windows RET immediates
  // prove their arity; TColorFill's slot-0x0c override proves Draw's slot, and DoesAdorn
  // uniquely clears AL before returning. The base implementations only pulse the global UI
  // invalidation flag, providing an inert default for each hook.
  virtual void AddedToView(TView* view);              // slot 0x0a 0x49d900
  virtual void RemovedFromView(TView* view);          // slot 0x0b 0x49d930
  virtual void Draw(TView* view, const RECT& bounds); // slot 0x0c 0x49d9c0
  virtual void ViewChangedFrame(TView* view, const RECT& oldFrame, const RECT& newFrame,
                                unsigned char redraw); // slot 0x0d 0x49d9f0
  virtual void InvalidateAdorner(TView* view);         // slot 0x0e 0x49da20
  virtual void DrawLine(signed char colorIndex, short x1, short y1,
                        short length);          // slot 0x0f 0x49da50
  virtual unsigned char DoesAdorn(TView* view); // slot 0x10 0x49da80

  TAdorner();

  // Original object size is 0xc: CRuntimeClass m_nObjectSize = 0xc and
  // CreateObject (0x49d650) allocates via operator_new(0xc). UNRESOLVED_FIELD_ATTRIBUTION:
  // neither dword is touched by ReadFrom/WriteTo/the ctor, or by any of the seven
  // AdornerSlot* overrides -- with no owner/attacher recovered yet (see class comment
  // above), there is no evidence available to type or name these two dwords. Declared raw
  // so sizeof(TAdorner) and the recomp's allocation size match the original binary; revisit
  // once an owner is found.
  int field04;
  int field08;
};
