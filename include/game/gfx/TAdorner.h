#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/gfx/ui_invalidation_guard.h"
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
  // FUNCTION: IMPERIALISM 0x0049dae0
  virtual ~TAdorner() override {}                  // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x49d990
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x49d960
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

  // Markerless inline ctor: CreateObject 0x49d650 expands the guard to its two
  // flag writes, while TColorFill::CreateObject 0x4ff0c0 keeps the out-of-line
  // guard call with the original UDisplayMgr.cpp source/line arguments.
  TAdorner() {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UDisplayMgr.cpp", 0x69);
  }

  // The Mac constructor oracle is TAdorner::IAdorner(unsigned long, unsigned char), and
  // TView's AdornerWithID/DeleteAdornerByID methods confirm the first argument is the
  // stable lookup ID. Windows RTTI and CreateObject independently fix the total size at
  // 0xc, leaving three bytes of tail padding after the one-byte flags value.
  unsigned long adornerId04;
  unsigned char adornerFlags08;
  unsigned char pad09[3];
};
ASSERT_SIZE(TAdorner, 0xc);
