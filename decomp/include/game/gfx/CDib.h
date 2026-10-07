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
  void* m_colorTablePixels;  // 0x04  points at the packed color table / pixels (header + 0x28)
  HBITMAP m_hBitmap;         // 0x08  compatible/DIB-section bitmap (DeleteObject on release)
  void* m_dibBits;           // 0x0c  DIB section bits (owned when m_dibBitsOwned == 1)
  BITMAPINFO* m_pInfoHeader; // 0x10  packed BITMAPINFOHEADER + RGBQUAD palette
  HGLOBAL m_hGlobalInfo;     // 0x14  GlobalAlloc handle backing m_pInfoHeader (own mode 2)
  eDibInfoOwnershipMode m_infoOwnMode; // 0x18
  BOOL m_dibBitsOwned;
  int m_pixelBytes;      // 0x20  size of the pixel buffer in bytes
  int m_paletteCount;    // 0x24  number of palette entries (biClrUsed)
  HANDLE m_hFileMapping; // 0x28  file-mapping handle (memory-mapped bmp path)
  HANDLE m_hFile;        // 0x2c  file handle for the mapping
  void* m_mappedView;    // 0x30  MapViewOfFile base
  HPALETTE m_hPalette;   // 0x34  palette built from the color table (DeleteObject)

  CDib();                                    // 0x00479f40
  CDib(int width, int height, int bitDepth); // 0x00479fe0
  CDib(const CDib& source);                  // 0x0047a200

  DECLARE_SERIAL(CDib) // slot 0x00 GetRuntimeClass 0x00479ed0; schema 0 in the binary descriptor
  virtual ~CDib() override;                   // slot 0x01 (real dtor 0x0047a370)
  void Serialize(CArchive& archive) override; // slot 0x02 0x0047bb10

  // Free every owned GDI/heap/mapping resource and zero the state
  void Release();
  void ReleaseMappedFileView(); // 0x0047bd90
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
  void ComputePaletteSize(unsigned int bitCount); // 0x0047bb60
  void ComputeMetrics();                          // 0x0047bc30
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
  void Write(CFile* file); // 0x0047b9f0
  int Read(CFile* file);   // 0x0047b6d0

  // abs(biHeight) -- rows are stored bottom-up when biHeight > 0
  int GetAbsoluteHeight();
};

ASSERT_SIZE(CDib, 0x38);
