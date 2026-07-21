#pragma once

#include "compat.h"
#include "game/TView.h"

struct CRuntimeClass;

struct Rect32 {
  int left;
  int top;
  int right;
  int bottom;
};

// VTABLE: IMPERIALISM 0x6431B0
class TCivDescription : public TView {
public:
  DECLARE_DYNCREATE(TCivDescription)
  virtual ~TCivDescription() override;

  virtual void ApplyRectSlot110(RECT* rectBuffer) override; // slot 0x44 0x58f550
  virtual void BeginMouseCaptureAndStartRepeatTimer(CPoint* point, int arg2, int arg3,
                                                    int arg4) override; // slot 0x47 0x58f1a0
  virtual void DrawProspector(RECT* bounds);                            // slot 0x68 0x58fec0
  // Overrides TControl's "build inset content rect" slot with an unrelated real
  // function: renders the Engineer civilian's target-tile legend (icon grid +
  // labels) into legendRects/legendInitialized below. Ignores boundsBuffer entirely
  // (ApplyRectSlot110's Engineer-class call site passes a throwaway local). Currently
  // a no-op stub — the real 1438-byte body (Ghidra: RenderCivilianTargetLegendVariantA)
  // is unported; see bd tracking issue (imperialism-decomp-9u3).
  //
  // 2026-07-13 investigation (bd 9u3, not yet ported -- notes for the next pass):
  // - 4 enabled-flags: g_pCityOrderCapabilityState (TTechMgr*) read at absolute byte
  //   offsets base+nationId*0x1d+{0x26e,0x274,0x274,0x27f} (nationId = the *active*
  //   nation via TSimMgr::GetActiveNationId(), not this->ownerNationId), compared != 2.
  //   TTechMgr.h's own comment on orderCapRows277 documents this exact
  //   base+nationId*29+{0x26e,0x274} access as landing in orderCapRows277[nationId-1]'s
  //   tail (20/26 bytes in) -- no clean field name recovered yet, so a raw
  //   `*(reinterpret_cast<unsigned char*>(g_pCityOrderCapabilityState) + off +
  //   nationId*0x1d)` read matches the ground truth.
  // - Header/title block: repeated { g_pSimMgr->GetString(0x272d, N, &buf) or
  //   g_pSimMgr->NumToCurrency(value, &buf) (slot 0x74) ; SetQuickDrawTextOrigin-
  //   WithContextOffset(x, y) ; DrawTextWithCachedStyle(&buf) } blocks for N=6..10, plus
  //   one NumToCurrency(0x7d0/2000, ...), one NumToCurrency(0xbb8/3000, ...),
  //   and one keyed off the word at 0x662b52 -- all already-ported helpers. The final
  //   title line is centered via MeasureTextExtentWithCachedQuickDrawStyle(&buf) against
  //   this->frameWidth34 (same pattern as ApplyRectSlot110).
  // - Icon grid (the part that actually needs verification, not just static reading):
  //   UpdatePaletteIndexWithDefaultFallback(0x10) reset, then per-icon
  //   SetQuickDrawFillColor(0) + BlitRectWithOptionalTransparency(srcSurface, dstSurface,
  //   srcRect, dstRect, blitFlags=0x24, nullptr) where dstSurface =
  //   (char*)g_pActiveQuickDrawSurfaceContext + 4 and srcSurface =
  //   *(char**)((char*)g_pStrategicMapViewSystem + 0x698) + 4 (TMacViewMgr+0x698 is an
  //   unmodeled bitmap-resource-surface field). 3 icons are blitted unconditionally at
  //   fixed rects, then a 4-slot loop (gated by the enabled-flags above) blits the
  //   remaining icons in a 2-column grid (column reset via `if (col < 0x5e) col += 0x1c;
  //   else { col = 0xa; row += 0x16; }`) followed by SetQuickDrawStrokeColor(0xffffff)
  //   framing. The exact per-icon srcRect/dstRect stack layout needs re-derivation with
  //   `just stackcmp` once a first attempt is built -- reconstructing it purely from the
  //   listing (this pass) was not reliable enough to commit without visual verification
  //   (screenshot capture), which this session could not run.
  virtual void DrawEngineer(RECT* bounds);  // slot 0x69 0x58f7b0
  virtual void DrawDeveloper(RECT* bounds); // slot 0x6a 0x5903c0
  short selectedCivilianClass;
  short ownerNationId;
  union {
    short targetTileCountsBySlot[5];
    struct {
      short pad_64[4];
      unsigned char legendInitialized;
      unsigned char pad_6d;
    };
  };
  Rect32 legendRects[16];
  unsigned char pad_170_to_16f[0]; // legends end at 0x170

  TCivDescription();

  void UpdateCivilianOrderClassAndRefreshTargetCounts(class TCivUnit* orderState);
  void UpdateCivilianOrderTargetTileCountsForOwnerNation(class TCivUnit* selectedOrder);
};
