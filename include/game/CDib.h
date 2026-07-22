#pragma once

#include "compat.h"
#include "game/mfc.h"

// CDib: the well-known reusable DIB helper class (Prosise / MSDN DIBLOOK lineage), compiled
// into the game from source (NOT part of nafxcw.lib, so it is reverse-engineered/ported here,
// not LIBRARY-annotated). Real class name + 0x38 object size confirmed from its IMPLEMENT_DYNAMIC
// CRuntimeClass at 0x00694b48 ("CDib"). Owns a packed BITMAPINFOHEADER + palette + pixel buffer
// (used for .bmp file I/O) and, on demand, a separate CreateDIBSection HBITMAP/bits. Distinct
// from the non-polymorphic TQuickDrawBlitSurface blit subobject (TQuickDrawSurfaceContext.h).
// Built by the asset cache's BuildIndexedBmpResourceById path; construct via `new CDib(w, h,
// depth)`.
//
// VTABLE: IMPERIALISM 0x00645fc8
class CDib : public CObject {
public:
  void* m_colorTablePixels;  // 0x04  points at the packed color table / pixels (header + 0x28)
  HBITMAP m_hBitmap;         // 0x08  compatible/DIB-section bitmap (DeleteObject on release)
  void* m_dibBits;           // 0x0c  DIB section bits (owned when m_dibBitsOwned == 1)
  BITMAPINFO* m_pInfoHeader; // 0x10  packed BITMAPINFOHEADER + RGBQUAD palette
  HGLOBAL m_hGlobalInfo;     // 0x14  GlobalAlloc handle backing m_pInfoHeader (own mode 2)
  int m_infoOwnMode;         // 0x18  0=not owned, 1=heap (operator delete), 2=GlobalFree
  int m_dibBitsOwned;        // 0x1c  1 when m_dibBits is heap-owned
  int m_pixelBytes;          // 0x20  size of the pixel buffer in bytes
  int m_paletteCount;        // 0x24  number of palette entries (biClrUsed)
  HANDLE m_hFileMapping;     // 0x28  file-mapping handle (memory-mapped bmp path)
  HANDLE m_hFile;            // 0x2c  file handle for the mapping
  void* m_mappedView;        // 0x30  MapViewOfFile base
  HPALETTE m_hPalette;       // 0x34  palette built from the color table (DeleteObject)

  CDib();                                    // 0x00479f40
  CDib(int width, int height, int bitDepth); // 0x00479fe0

  DECLARE_SERIAL(CDib) // slot 0x00 GetRuntimeClass 0x00479ed0; schema 0 in the binary descriptor
  virtual ~CDib() override;                   // slot 0x01 (real dtor 0x0047a370)
  void Serialize(CArchive& archive) override; // slot 0x02 0x0047bb10
  // slot 0x03 AssertValid inherited unchanged
  // slot 0x04 Dump inherited unchanged

  // Free every owned GDI/heap/mapping resource and zero the state. 0x0047bca0
  void Release();
  // Lazily create the DIB section bitmap into m_hBitmap/m_dibBits. The original takes
  // the CDC (it derefs m_hDC itself, null-tolerant), not a raw HDC. 0x0047ae20
  HBITMAP EnsureDibSectionCreated(CDC* dc);
  // Build m_hPalette (LOGPALETTE -> CreatePalette) from the RGBQUAD color table. 0x0047ae90
  int BuildPaletteFromRgbQuadBuffer();
  // Convert a LOGPALETTE's entries into the surface's RGBQUAD color table. 0x0047b0c0
  void CopyRgbQuadTableFrom(const LOGPALETTE* source);
  // Copy bitmap width/height into a point, or zero it if no header is attached. 0x0047a3e0
  CPoint* CopyBitmapDimensionsToPoint(CPoint* out);
  // Realize the DIB palette into a DC before blitting. 0x0047aa00
  UINT SelectAndRealizeDibPalette(CDC* dc, BOOL background);
  // Stretch-blit stored DIB bits to a DC. 0x0047aa70
  BOOL StretchDibitsFromStoredBitmapToHdcSimple(CDC* dc, int x, int y, int width, int height);
  // Copy a source rectangle to the same-sized destination rectangle. 0x0047aae0
  BOOL StretchDibitsRectAtNaturalSize(int srcX, int srcY, CDC* dc, int destX, int destY, int width,
                                      int height);
  // Blit the whole stored DIB to a DC at the given top-left point (natural size). 0x0047ab60
  BOOL StretchDibitsFromStoredBitmapToHdc(CDC* dc, POINT* topLeft);
  // Full-control StretchDIBits of this DIB's bits/header: explicit dest and src rects,
  // DIB_RGB_COLORS + SRCCOPY, null-tolerant CDC. 0x0047abe0
  int StretchDibitsRectToDc(CDC* dc, int xDest, int yDest, int destWidth, int destHeight, int xSrc,
                            int ySrc, int srcWidth, int srcHeight);
  // CreateDIBitmap from the stored header/bits (CBM_INIT), compatible with the given DC.
  // Returns NULL if no pixel buffer. 0x0047b280
  HBITMAP CreateDibBitmapFromStoredInfo(CDC* dc);
  // StretchDIBits with the color-table entry `paletteIndex` temporarily forced white (then
  // restored): masks that palette slot to white for the blit. Two-pass (AND then paint ROP).
  // 0x0047ac50
  BOOL StretchDibitsWithCopiedPaletteTable(CDC* dc, int paletteIndex, int xDest, int yDest,
                                           int destWidth, int destHeight, int xSrc, int ySrc,
                                           int srcWidth, int srcHeight);
  // Load an RT_BITMAP resource from a module into the DIB state. 0x0047c080
  int LoadBitmapResourceAndInitializeSurfaceState(LPCSTR resourceName, HMODULE module);
  // For a 1-bpp DIB, replace every set pixel with the one-pixel ring immediately outside
  // the original bitmap. Used by the diagnostic DIB preview dialog. 0x0047c1f0
  int BuildMonochromeOutlineMaskInPlace();
  // Reverse the DIB's scanline order in place. 0x0047c980
  void FlipScanlineOrder();
  // Software-blit a `width`x`height` rect from this DIB's pixel buffer (top-left at
  // srcX/srcY) into destDib's pixel buffer (top-left at destX/destY), skipping any
  // source byte equal to transparentColor (a straight block copy when
  // transparentColor == -1). Row orientation (top-down vs bottom-up) is resolved from
  // each DIB's signed biHeight independently. 0x0047bde0
  void BlitSurfaceRectSkippingTransparentColor(CDib* destDib, int srcX, int srcY,
                                               unsigned int width, unsigned int height, int destX,
                                               int destY, int transparentColor);

  // Scan the pixel buffer and return a heap int array describing the outline polygon of
  // the non-transparent area: [0] = POINT count, POINTs from +2, closed (first point
  // repeated last). transparentIndex == 0xffffffff means "use the first pixel's value";
  // a 1-bpp surface treats zero bytes as transparent. Consumed by BitMapToRegion
  // (CreatePolygonRgn) and the cursor/city-region builders. 0x0047c3d0
  int* BuildNonTransparentOutlinePolygon(unsigned int transparentIndex);

  // Serialize backends: write a .bmp (BITMAPFILEHEADER + BITMAPINFO + pixels) / read one back.
  void Write(CFile* file); // 0x0047b9f0
  int Read(CFile* file);   // 0x0047b6d0

  // abs(biHeight) -- rows are stored bottom-up when biHeight > 0. 0x00575080
  int GetAbsoluteHeight();
};

ASSERT_SIZE(CDib, 0x38);
