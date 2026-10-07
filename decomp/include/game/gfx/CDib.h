#pragma once

#include "compat.h"
#include "game/mfc.h"

// CDib: the MSDN DIBLOOK-lineage DIB helper compiled into the game (not an MFC library class).

enum eDibInfoOwnershipMode {
  kDibInfoNotOwned = 0,
  kDibInfoOwnedByteArray = 1,
  kDibInfoOwnedGlobalHandle = 2,
};

class CDibPal;

// VTABLE: IMPERIALISM 0x00645fc8
class CDib : public CObject {
public:
  void* m_colorTablePixels;  // points at the packed color table / pixels (header + 0x28)
  HBITMAP m_hBitmap;         // compatible/DIB-section bitmap (DeleteObject on release)
  void* m_dibBits;           // DIB section bits (owned when m_dibBitsOwned == 1)
  BITMAPINFO* m_pInfoHeader; // packed BITMAPINFOHEADER + RGBQUAD palette
  HGLOBAL m_hGlobalInfo;     // GlobalAlloc handle backing m_pInfoHeader (own mode 2)
  eDibInfoOwnershipMode m_infoOwnMode;
  BOOL m_dibBitsOwned;
  int m_pixelBytes;      // size of the pixel buffer in bytes
  int m_paletteCount;    // number of palette entries (biClrUsed)
  HANDLE m_hFileMapping; // file-mapping handle (memory-mapped bmp path)
  HANDLE m_hFile;        // file handle for the mapping
  void* m_mappedView;    // MapViewOfFile base
  HPALETTE m_hPalette;   // palette built from the color table (DeleteObject)

  CDib();
  CDib(int width, int height, int bitDepth);
  CDib(const CDib& source);

  DECLARE_SERIAL(CDib) // slot 0x00 GetRuntimeClass 0x00479ed0; schema 0 in the binary descriptor
  virtual ~CDib() override;
  void Serialize(CArchive& archive) override;

  // Free every owned GDI/heap/mapping resource and zero the state
  void Release();
  void ReleaseMappedFileView();
  BOOL AttachPackedInfoHeader(BITMAPINFO* info, BOOL ownsInfo, HGLOBAL hGlobalInfo);
  HBITMAP EnsureDibSectionCreated(CDC* dc);
  // Build m_hPalette (LOGPALETTE -> CreatePalette) from the RGBQUAD color table. 0x0047ae90
  int BuildPaletteFromRgbQuadBuffer();
  // Allocate a fresh CPalette from the color table (returns NULL if there is no palette). 0x0047af60
  CPalette* CreatePaletteObjectFromColorTable();
  LOGPALETTE* CreateLogPaletteFromColorTable();
  BOOL SetSystemPalette(CDC* dc);

  // Load a .bmp via a read-only file mapping and point the DIB buffers into it
  int LoadFromMemoryMappedBmpFile(LPCSTR fileName, int shareForWrite);
  // Serialize the DIB into a memory-mapped .bmp file and re-point the buffers into it
  int RemapSurfaceToMemoryMappedBmpFile(LPCSTR fileName);
  // Convert a LOGPALETTE's entries into the surface's RGBQUAD color table. 0x0047b0c0
  void CopyRgbQuadTableFrom(const LOGPALETTE* source);

  void AdoptPaletteAndCopyRgbQuadTable(CDibPal* palette);
  // Copy bitmap width/height into a point, or zero it if no header is attached
  CPoint* CopyBitmapDimensionsToPoint(CPoint* out);
  // Realize the DIB palette into a DC before blitting
  UINT SelectAndRealizeDibPalette(CDC* dc, BOOL background);
  // Stretch-blit stored DIB bits to a DC
  BOOL StretchDibitsFromStoredBitmapToHdcSimple(CDC* dc, int x, int y, int width, int height);
  // Copy a source rectangle to the same-sized destination rectangle
  BOOL StretchDibitsRectAtNaturalSize(int srcX, int srcY, CDC* dc, int destX, int destY, int width,
                                      int height);
  // Blit the whole stored DIB to a DC at the given top-left point (natural size)
  BOOL StretchDibitsFromStoredBitmapToHdc(CDC* dc, POINT* topLeft);
  int StretchDibitsRectToDc(CDC* dc, int xDest, int yDest, int destWidth, int destHeight, int xSrc,
                            int ySrc, int srcWidth, int srcHeight);
  HBITMAP CreateDibBitmapFromStoredInfo(CDC* dc);
  BOOL Compress(CDC* dc, BOOL compress);
  void ComputePaletteSize(unsigned int bitCount);
  void ComputeMetrics();
  BOOL StretchDibitsWithCopiedPaletteTable(CDC* dc, int paletteIndex, int xDest, int yDest,
                                           int destWidth, int destHeight, int xSrc, int ySrc,
                                           int srcWidth, int srcHeight);
  // Load an RT_BITMAP resource from a module into the DIB state
  int LoadBitmapResourceAndInitializeSurfaceState(LPCSTR resourceName, HMODULE module);
  int BuildMonochromeOutlineMaskInPlace();
  // Reverse the DIB's scanline order in place
  void FlipScanlineOrder();
  void BlitSurfaceRectSkippingTransparentColor(CDib* destDib, int srcX, int srcY,
                                               unsigned int width, unsigned int height, int destX,
                                               int destY, int transparentColor);

  void* GetPixelAddress(int x, int y);
  // Variant that preserves top-down (negative-height) row orientation
  void* GetPixelAddressRespectingTopDownOrientation(int x, int y);
  BOOL MapColorTableAndPixelsToPalette(CPalette* palette);

  void ForwardBlitSurfaceRectSkippingTransparentColor(CDib* destDib, POINT* srcPoint,
                                                      POINT* sizePoint, POINT* destPoint,
                                                      int transparentColor);

  POINT* BuildNonTransparentOutlinePolygon(unsigned int transparentIndex);

  // Serialize backends: write a .bmp (BITMAPFILEHEADER + BITMAPINFO + pixels) / read one back.
  void Write(CFile* file);
  int Read(CFile* file);

  // abs(biHeight) -- rows are stored bottom-up when biHeight > 0
  int GetAbsoluteHeight();
};

ASSERT_SIZE(CDib, 0x38);
