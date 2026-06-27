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

  CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x00479ed0
  virtual ~CDib() override;                        // slot 0x01 (real dtor 0x0047a370)
  void Serialize(CArchive& archive) override;      // slot 0x02 0x0047bb10
  // slot 0x03 AssertValid inherited unchanged
  // slot 0x04 Dump inherited unchanged

  // Free every owned GDI/heap/mapping resource and zero the state. 0x0047bca0
  void Release();
  // Lazily create the DIB section bitmap into m_hBitmap/m_dibBits. 0x0047ae20
  HBITMAP EnsureDibSectionCreated(HDC hdc);
  // Build m_hPalette (LOGPALETTE -> CreatePalette) from the RGBQUAD color table. 0x0047ae90
  int BuildPaletteFromRgbQuadBuffer();
  // Convert a LOGPALETTE's entries into the surface's RGBQUAD color table. 0x0047b0c0
  void CopyRgbQuadTableFrom(const LOGPALETTE* source);
  // Copy bitmap width/height into a point, or zero it if no header is attached. 0x0047a3e0
  CPoint* CopyBitmapDimensionsToPoint(CPoint* out);
  // Load an RT_BITMAP resource from a module into the DIB state. 0x0047c080
  int LoadBitmapResourceAndInitializeSurfaceState(LPCSTR resourceName, HMODULE module);

  // Serialize backends: write a .bmp (BITMAPFILEHEADER + BITMAPINFO + pixels) / read one back.
  void Write(CFile* file); // 0x0047b9f0
  int Read(CFile* file);   // 0x0047b6d0
};

ASSERT_SIZE(CDib, 0x38);
