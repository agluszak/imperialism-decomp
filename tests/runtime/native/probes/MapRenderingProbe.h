#pragma once

#ifndef IMPERIALISM_MAP_RENDERING_PROBE_H
#define IMPERIALISM_MAP_RENDERING_PROBE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error MapRenderingProbe is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

class TMapDialog;
// struct, not class: MSVC500 mangles the two differently, so declaring this `class` compiles
// and then fails to link against bitmap_descriptor_helpers.h's `struct` (skill rule 7).
struct TQuickDrawSurfaceContext;
class TView;

// Rendering evidence a screen cannot express: what the game actually put on a surface.
//
// A screen answers questions about controls and model state. Pixels are a different kind of
// evidence -- they need a device context, a locked surface, and a before/after pair -- and the
// machinery is Win32 GDI, which has no business inside a scenario body. It lived there anyway
// (`CreateDIBSection`, `BitBlt`, `DrawIconEx`, `GetGWorld`/`SetGWorld` and a hand-rolled
// surface guard, all in one test's anonymous namespace) because there was nowhere else to put
// it. This is that place.

// Every draw the suite forces has to land on the primary render surface: the map's Draw paths
// assume a GWorld is set, and drawing outside one reaches a null device context. RAII because
// the alternative is restoring the previous surface by hand at each early return -- which the
// original code did, at eleven of them.
class PrimarySurfaceGuard {
public:
  PrimarySurfaceGuard();
  ~PrimarySurfaceGuard();

private:
  TQuickDrawSurfaceContext* savedSurface;
  int savedFlags;

  // A guard is a scope, never a value.
  PrimarySurfaceGuard(const PrimarySurfaceGuard&);
  PrimarySurfaceGuard& operator=(const PrimarySurfaceGuard&);
};

// Pixels captured from a view's own window, owned so a caller cannot leak them by taking an
// early return -- which is the bug the raw `DWORD*` out-parameter kept inviting.
class CapturedPixels {
public:
  CapturedPixels();
  ~CapturedPixels();

  // Blit `view`'s frame out of its native window. False when the view has no window or no
  // extent, which is a legitimate "not yet" rather than a failure.
  bool CaptureFrom(TView* view);

  bool IsValid() const;
  int Width() const;
  int Height() const;
  // True when the two captures have the same extent and identical pixels.
  bool Matches(const CapturedPixels& other) const;
  // The same, ignoring a rectangle: for "everything except the part that was supposed to
  // change is unchanged", which is the shape most repaint assertions actually want.
  bool MatchesOutside(const CapturedPixels& other, const CRect& ignored) const;

private:
  unsigned long* pixels;
  int width;
  int height;

  CapturedPixels(const CapturedPixels&);
  CapturedPixels& operator=(const CapturedPixels&);
};

namespace MapRenderingProbe {

// True when drawing the cursor puts any non-white pixel on a scratch surface -- i.e. the
// handle is a real cursor with an image, not a valid-but-blank one. A blank cursor is exactly
// what a broken cursor-resource path produces, and it is invisible to a handle null-check.
bool CursorDrawsVisiblePixels(HCURSOR cursor);

// The cursor the game has actually installed is `expected`, and it draws something. Three
// separate ways to be wrong -- no such cursor, the system holding a different one, a valid
// handle with a blank image -- and a scenario should be asking one question.
bool CursorIsActiveAndVisible(HCURSOR expected);

// Draw one tile twice, once with `initialClass` and once with `completedClass` in its
// development nibble, and report whether the rendered pixels differ. The tile's own state is
// restored and redrawn either way. This is how "the farmer's finished work changed the map"
// is verified without trusting the model field that drove it.
bool DevelopmentClassChangesTilePixels(TMapDialog* mapDialog, short tileIndex,
                                       unsigned char initialClass, unsigned char completedClass);

// Hovering from one tile to another must leave every pixel outside the newly hovered tile
// exactly as it was: the map is expected to repaint what the pointer left behind. Compares a
// full-frame capture before and after, masking the tile now under the pointer.
//
// `excludedTile` is a tile the caller does not want chosen as either endpoint -- normally the
// one its scenario is already asserting about. False when the map offers no two distinct tiles
// to move between, which is a "cannot answer", not a failure.
bool HoverMovementRestoresPreviousTiles(TMapDialog* mapDialog, short excludedTile);

} // namespace MapRenderingProbe

#endif
