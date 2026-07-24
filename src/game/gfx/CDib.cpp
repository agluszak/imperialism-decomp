#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"

#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/globals/prelude.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

namespace {

const WORD kBitmapFileSignature = 0x4d42;

} // namespace

// SYNTHETIC: IMPERIALISM 0x00479e40
// CDib::CreateObject

// SYNTHETIC: IMPERIALISM 0x00479ed0
// CDib::GetRuntimeClass

IMPLEMENT_SERIAL(CDib, CObject, 0)

// FUNCTION: IMPERIALISM 0x00479f40
CDib::CDib() : CObject() {
  m_hBitmap = NULL;
  m_infoOwnMode = kDibInfoNotOwned;
  m_dibBitsOwned = 0;
  m_hFileMapping = NULL;
  m_hPalette = NULL;
  Release();
}

// The scalar deleting destructor is compiler-generated from the virtual dtor.
// SYNTHETIC: IMPERIALISM 0x00479fb0
// CDib::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00479fe0
CDib::CDib(int width, int height, int bitDepth) : CObject() {
  m_hBitmap = NULL;
  m_infoOwnMode = kDibInfoNotOwned;
  m_dibBitsOwned = 0;
  m_hFileMapping = NULL;
  m_hPalette = NULL;
  Release();

  if (m_pInfoHeader == NULL || m_pInfoHeader->bmiHeader.biClrUsed == 0) {
    switch (bitDepth) {
    case 1:
      m_paletteCount = 2;
      break;
    case 4:
      m_paletteCount = 0x10;
      break;
    case 8:
      m_paletteCount = 0x100;
      break;
    case 0x10:
    case 0x18:
    case 0x20:
      m_paletteCount = 0;
      break;
    }
  } else {
    m_paletteCount = m_pInfoHeader->bmiHeader.biClrUsed;
  }

  int infoBytes = width * height + sizeof(BITMAPINFOHEADER) + m_paletteCount * sizeof(RGBQUAD);
  m_pInfoHeader = static_cast<BITMAPINFO*>(static_cast<void*>(new unsigned char[infoBytes]));
  m_infoOwnMode = kDibInfoOwnedByteArray;
  m_pInfoHeader->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  m_pInfoHeader->bmiHeader.biWidth = width;
  if (g_nDibOrientationFlag_006A1890 > 0) {
    height = -height;
  }
  m_pInfoHeader->bmiHeader.biHeight = height;
  m_pInfoHeader->bmiHeader.biPlanes = 1;
  m_pInfoHeader->bmiHeader.biBitCount = static_cast<WORD>(bitDepth);
  m_pInfoHeader->bmiHeader.biCompression = 0;
  m_pInfoHeader->bmiHeader.biSizeImage = 0;
  m_pInfoHeader->bmiHeader.biXPelsPerMeter = 0;
  m_pInfoHeader->bmiHeader.biYPelsPerMeter = 0;
  m_pInfoHeader->bmiHeader.biClrUsed = m_paletteCount;
  m_pInfoHeader->bmiHeader.biClrImportant = m_paletteCount;

  m_pixelBytes = m_pInfoHeader->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits = static_cast<unsigned int>(m_pInfoHeader->bmiHeader.biBitCount) *
                           m_pInfoHeader->bmiHeader.biWidth;
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords = rowDwords + 1;
    }
    int rows = m_pInfoHeader->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = m_pInfoHeader->bmiColors;
  int* paletteWords = static_cast<int*>(m_colorTablePixels);
  for (int remaining = m_paletteCount & 0x3fffffff; remaining != 0; remaining--) {
    *paletteWords = 0;
    paletteWords++;
  }
}

// FUNCTION: IMPERIALISM 0x0047a200
CDib::CDib(const CDib& source)
    : CObject(), m_colorTablePixels(0), m_hBitmap(NULL), m_dibBits(0), m_pInfoHeader(0),
      m_hGlobalInfo(NULL), m_infoOwnMode(kDibInfoOwnedByteArray), m_dibBitsOwned(1),
      m_pixelBytes(source.m_pixelBytes), m_paletteCount(source.m_paletteCount),
      m_hFileMapping(NULL), m_hFile(NULL), m_mappedView(0), m_hPalette(NULL) {
  unsigned int infoBytes =
      static_cast<unsigned int>(m_paletteCount) * sizeof(RGBQUAD) + sizeof(BITMAPINFOHEADER);
  m_pInfoHeader = static_cast<BITMAPINFO*>(static_cast<void*>(new unsigned char[infoBytes]));
  memcpy(m_pInfoHeader, source.m_pInfoHeader, infoBytes);

  m_infoOwnMode = kDibInfoOwnedByteArray;
  m_pixelBytes = m_pInfoHeader->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits = static_cast<unsigned int>(m_pInfoHeader->bmiHeader.biBitCount) *
                           m_pInfoHeader->bmiHeader.biWidth;
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords++;
    }
    int rows = m_pInfoHeader->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * sizeof(int) * rows;
  }

  m_colorTablePixels = m_pInfoHeader->bmiColors;
  m_dibBits = new unsigned char[m_pixelBytes];
  memcpy(m_dibBits, source.m_dibBits, m_pixelBytes);
}

// FUNCTION: IMPERIALISM 0x0047a370
CDib::~CDib() {
  Release();
}

// FUNCTION: IMPERIALISM 0x0047a3e0
CPoint* CDib::CopyBitmapDimensionsToPoint(CPoint* out) {
  if (m_pInfoHeader == NULL) {
    out->x = 0;
    out->y = 0;
    return out;
  }

  out->x = m_pInfoHeader->bmiHeader.biWidth;
  out->y = m_pInfoHeader->bmiHeader.biHeight;
  return out;
}

// Opens `fileName` as a read-only memory mapping, validates the "BM" signature, then points
// this CDib's info-header/color-table/pixel buffers directly into the mapped file and rebuilds
// the palette. Same offset-swapped m_hFileMapping(0x28)=file / m_hFile(0x2c)=mapping note as the
// serialize path below.
// FUNCTION: IMPERIALISM 0x0047a420
int CDib::LoadFromMemoryMappedBmpFile(LPCSTR fileName, int shareForWrite) {
  DWORD shareMode = shareForWrite != 0 ? 1 : 0;
  HANDLE fileHandle = CreateFileA(fileName, 0x80000000, shareMode, NULL, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, NULL);
  GetFileSize(fileHandle, NULL);
  HANDLE mappingHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
  GetLastError();
  if (mappingHandle == NULL) {
    AfxMessageBox("Empty bitmap file", 0, 0);
    return 0;
  }

  unsigned short* mapped =
      static_cast<unsigned short*>(MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0));
  if (*mapped != 0x4d42) {
    AfxMessageBox("Invalid bitmap file", 0, 0);
    return 0;
  }

  Release();
  m_hGlobalInfo = NULL;
  m_infoOwnMode = kDibInfoNotOwned;

  BITMAPINFO* info = reinterpret_cast<BITMAPINFO*>(mapped + 7);
  m_pInfoHeader = info;
  if (info == NULL || info->bmiHeader.biClrUsed == 0) {
    switch (info->bmiHeader.biBitCount) {
    case 1:
      m_paletteCount = 2;
      break;
    case 4:
      m_paletteCount = 0x10;
      break;
    case 8:
      m_paletteCount = 0x100;
      break;
    case 0x10:
    case 0x18:
    case 0x20:
      m_paletteCount = 0;
      break;
    }
  } else {
    m_paletteCount = info->bmiHeader.biClrUsed;
  }

  m_pixelBytes = info->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits =
        info->bmiHeader.biWidth * static_cast<unsigned int>(info->bmiHeader.biBitCount);
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords = rowDwords + 1;
    }
    int rows = info->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = reinterpret_cast<char*>(mapped) + 0x36;
  m_dibBits = reinterpret_cast<char*>(mapped) + 0x36 + m_paletteCount * 4;
  BuildPaletteFromRgbQuadBuffer();
  m_mappedView = mapped;
  m_hFileMapping = fileHandle;
  m_hFile = mappingHandle;
  return 1;
}

// Writes the current DIB (BITMAPFILEHEADER + BITMAPINFOHEADER + color table + pixels) into a
// newly created memory-mapped .bmp file, then re-points this CDib's buffers into the mapping
// and rebuilds the palette from the mapped color table. NOTE: the m_hFileMapping (0x28) and
// m_hFile (0x2c) field names are offset-swapped from the CreateFile*/API roles but kept
// consistent with CDib::Release, so the stores below match the original's field offsets.
// FUNCTION: IMPERIALISM 0x0047a630
int CDib::RemapSurfaceToMemoryMappedBmpFile(LPCSTR fileName) {
  int offBits = m_paletteCount * 4 + 0x36;
  unsigned int fileSize = offBits + m_pixelBytes;

  HANDLE fileHandle =
      CreateFileA(fileName, 0xc0000000, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE mappingHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READWRITE, 0,
                                            m_pixelBytes + 0x36 + m_paletteCount * 4, NULL);
  GetLastError();
  unsigned int* mapped =
      static_cast<unsigned int*>(MapViewOfFile(mappingHandle, FILE_MAP_WRITE, 0, 0, 0));

  // BITMAPFILEHEADER (14 bytes) packed exactly as the original's dword stores.
  unsigned int* infoDest = reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(mapped) + 0xe);
  mapped[0] = (fileSize << 0x10) | 0x4d42;
  mapped[1] = fileSize >> 0x10;
  mapped[2] = offBits << 0x10;
  *reinterpret_cast<unsigned short*>(mapped + 3) = static_cast<unsigned short>(offBits >> 0x10);

  // Copy the packed BITMAPINFOHEADER (0x28 bytes) + color table into the mapped file.
  unsigned int* infoSrc = reinterpret_cast<unsigned int*>(m_pInfoHeader);
  unsigned int* infoWalk = infoDest;
  for (unsigned int words = (m_paletteCount * 4 + 0x28U) >> 2; words != 0; words--) {
    *infoWalk = *infoSrc;
    infoSrc++;
    infoWalk++;
  }

  // Copy the pixel buffer after the header + color table.
  unsigned int pixelBytes = m_pixelBytes;
  unsigned int* pixelStart =
      reinterpret_cast<unsigned int*>(reinterpret_cast<char*>(mapped) + m_paletteCount * 4 + 0x36);
  unsigned int* pixelSrc = static_cast<unsigned int*>(m_dibBits);
  unsigned int* pixelWalk = pixelStart;
  for (unsigned int pixelWords = pixelBytes >> 2; pixelWords != 0; pixelWords--) {
    *pixelWalk = *pixelSrc;
    pixelSrc++;
    pixelWalk++;
  }
  unsigned char* pixelSrcByte = reinterpret_cast<unsigned char*>(pixelSrc);
  unsigned char* pixelWalkByte = reinterpret_cast<unsigned char*>(pixelWalk);
  for (unsigned int rem = pixelBytes & 3; rem != 0; rem--) {
    *pixelWalkByte = *pixelSrcByte;
    pixelSrcByte++;
    pixelWalkByte++;
  }

  int savedPixelBytes = m_pixelBytes;
  Release();
  m_pixelBytes = savedPixelBytes;

  m_dibBits = pixelStart;
  m_hFileMapping = fileHandle;
  m_hFile = mappingHandle;
  m_dibBitsOwned = 0;
  m_infoOwnMode = kDibInfoNotOwned;
  m_pInfoHeader = reinterpret_cast<BITMAPINFO*>(infoDest);
  m_mappedView = mapped;

  if (infoDest == NULL || m_pInfoHeader->bmiHeader.biClrUsed == 0) {
    switch (m_pInfoHeader->bmiHeader.biBitCount) {
    case 1:
      m_paletteCount = 2;
      break;
    case 4:
      m_paletteCount = 0x10;
      break;
    case 8:
      m_paletteCount = 0x100;
      break;
    case 0x10:
    case 0x18:
    case 0x20:
      m_paletteCount = 0;
      break;
    }
  } else {
    m_paletteCount = m_pInfoHeader->bmiHeader.biClrUsed;
  }

  m_pixelBytes = m_pInfoHeader->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits = m_pInfoHeader->bmiHeader.biWidth *
                           static_cast<unsigned int>(m_pInfoHeader->bmiHeader.biBitCount);
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords = rowDwords + 1;
    }
    int rows = m_pInfoHeader->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = reinterpret_cast<char*>(mapped) + 0x36;
  BuildPaletteFromRgbQuadBuffer();
  return 1;
}

// FUNCTION: IMPERIALISM 0x0047a8a0
BOOL CDib::AttachPackedInfoHeader(BITMAPINFO* info, BOOL ownsInfo, HGLOBAL hGlobalInfo) {
  Release();
  m_hGlobalInfo = hGlobalInfo;
  if (ownsInfo == 0) {
    m_infoOwnMode = kDibInfoNotOwned;
  } else {
    m_infoOwnMode = (hGlobalInfo != NULL) ? kDibInfoOwnedGlobalHandle : kDibInfoOwnedByteArray;
  }

  m_pInfoHeader = info;
  // The switch selector is read ahead of the null test, exactly as the original does
  // (the load at 0x47a8d4 precedes the `test eax,eax` at 0x47a8d8), and it dies inside
  // the switch -- the pixel-size arithmetic below re-reads biBitCount rather than
  // keeping this value alive in a second register.
  unsigned int bitCount = info->bmiHeader.biBitCount;
  // Same palette-entry-count table as the (width, height, bitDepth) constructor; an
  // unlisted depth leaves m_paletteCount at whatever Release() left behind.
  if (info == NULL || info->bmiHeader.biClrUsed == 0) {
    switch (bitCount) {
    case 1:
      m_paletteCount = 2;
      break;
    case 4:
      m_paletteCount = 0x10;
      break;
    case 8:
      m_paletteCount = 0x100;
      break;
    case 0x10:
    case 0x18:
    case 0x20:
      m_paletteCount = 0;
      break;
    }
  } else {
    m_paletteCount = info->bmiHeader.biClrUsed;
  }

  m_pixelBytes = info->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits =
        info->bmiHeader.biWidth * static_cast<unsigned int>(info->bmiHeader.biBitCount);
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords = rowDwords + 1;
    }
    unsigned int rowBytes = rowDwords * 4;
    int rows = info->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowBytes * rows;
  }

  int paletteCount = m_paletteCount;
  RGBQUAD* colorTable = info->bmiColors;
  m_colorTablePixels = colorTable;
  m_dibBits = &colorTable[paletteCount];
  BuildPaletteFromRgbQuadBuffer();
  return 1;
}

// FUNCTION: IMPERIALISM 0x0047aa00
UINT CDib::SelectAndRealizeDibPalette(CDC* dc, BOOL background) {
  if (m_hPalette == NULL) {
    TemporarilyClearAndRestoreUiInvalidationFlag("CDib.cpp", 0xe9);
    return 0;
  }

  HDC hdc = (dc != NULL) ? dc->m_hDC : NULL;
  ::SelectPalette(hdc, m_hPalette, background);
  return ::RealizePalette(hdc);
}

// FUNCTION: IMPERIALISM 0x0047aa70
BOOL CDib::StretchDibitsFromStoredBitmapToHdcSimple(CDC* dc, int x, int y, int width, int height) {
  if (m_pInfoHeader == NULL) {
    return FALSE;
  }

  HDC hdc = (dc != NULL) ? dc->m_hDC : NULL;
  ::StretchDIBits(hdc, x, y, width, height, 0, 0, m_pInfoHeader->bmiHeader.biWidth,
                  m_pInfoHeader->bmiHeader.biHeight, m_dibBits, m_pInfoHeader, DIB_RGB_COLORS,
                  SRCCOPY);
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x0047aae0
BOOL CDib::StretchDibitsRectAtNaturalSize(int srcX, int srcY, CDC* dc, int destX, int destY,
                                          int width, int height) {
  if (m_pInfoHeader == NULL) {
    return FALSE;
  }

  HDC hdc = dc == NULL ? NULL : dc->m_hDC;
  ::StretchDIBits(hdc, destX, destY, width, height, srcX, srcY, width, height, m_dibBits,
                  m_pInfoHeader, DIB_RGB_COLORS, SRCCOPY);
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x0047ab60
BOOL CDib::StretchDibitsFromStoredBitmapToHdc(CDC* dc, POINT* topLeft) {
  if (m_pInfoHeader == NULL) {
    return FALSE;
  }
  HDC hdc = (dc != NULL) ? dc->m_hDC : NULL;
  int destHeight = m_pInfoHeader->bmiHeader.biHeight;
  int destWidth = m_pInfoHeader->bmiHeader.biWidth;
  ::StretchDIBits(hdc, topLeft->x, topLeft->y, destWidth, destHeight, 0, 0, destWidth, destHeight,
                  m_dibBits, m_pInfoHeader, DIB_RGB_COLORS, SRCCOPY);
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x0047abe0
int CDib::StretchDibitsRectToDc(CDC* dc, int xDest, int yDest, int destWidth, int destHeight,
                                int xSrc, int ySrc, int srcWidth, int srcHeight) {
  return ::StretchDIBits(dc->GetSafeHdc(), xDest, yDest, destWidth, destHeight, xSrc, ySrc,
                         srcWidth, srcHeight, m_dibBits, m_pInfoHeader, DIB_RGB_COLORS, SRCCOPY);
}

// Two-pass transparent stretch-blit: entry `paletteIndex` of the color table is forced white
// over an otherwise-black table for the AND pass (ROP 0x8800c6), then cleared to black over
// the restored table for the paint pass (ROP 0xee0086). The color table is saved to a scratch
// buffer up front and fully restored before returning. Returns TRUE only if both passes blit.
// FUNCTION: IMPERIALISM 0x0047ac50
BOOL CDib::StretchDibitsWithCopiedPaletteTable(CDC* dc, int paletteIndex, int xDest, int yDest,
                                               int destWidth, int destHeight, int xSrc, int ySrc,
                                               int srcWidth, int srcHeight) {
  unsigned char* savedTable = new unsigned char[0x400];
  memcpy(savedTable, m_colorTablePixels, m_paletteCount * 4);
  memset(m_colorTablePixels, 0, m_paletteCount * 4);

  int entry = paletteIndex * 4;
  static_cast<unsigned char*>(m_colorTablePixels)[entry] = 0xff;
  static_cast<unsigned char*>(m_colorTablePixels)[entry + 1] = 0xff;
  static_cast<unsigned char*>(m_colorTablePixels)[entry + 2] = 0xff;
  int blitted =
      ::StretchDIBits(dc->GetSafeHdc(), xDest, yDest, destWidth, destHeight, xSrc, ySrc, srcWidth,
                      srcHeight, m_dibBits, m_pInfoHeader, DIB_RGB_COLORS, 0x8800c6);

  memcpy(m_colorTablePixels, savedTable, m_paletteCount * 4);
  static_cast<unsigned char*>(m_colorTablePixels)[entry] = 0;
  static_cast<unsigned char*>(m_colorTablePixels)[entry + 1] = 0;
  static_cast<unsigned char*>(m_colorTablePixels)[entry + 2] = 0;
  BOOL result = FALSE;
  if (blitted != 0) {
    if (::StretchDIBits(dc->GetSafeHdc(), xDest, yDest, destWidth, destHeight, xSrc, ySrc, srcWidth,
                        srcHeight, m_dibBits, m_pInfoHeader, DIB_RGB_COLORS, 0xee0086) != 0) {
      result = TRUE;
    }
  }

  memcpy(m_colorTablePixels, savedTable, m_paletteCount * 4);
  delete[] savedTable;
  return result;
}

// FUNCTION: IMPERIALISM 0x0047ae20
HBITMAP CDib::EnsureDibSectionCreated(CDC* dc) {
  if (m_pInfoHeader == NULL) {
    return NULL;
  }
  if (m_dibBits != NULL) {
    return NULL;
  }
  HDC hdc = (dc != NULL) ? dc->m_hDC : NULL;
  m_hBitmap = CreateDIBSection(hdc, m_pInfoHeader, 0, &m_dibBits, NULL, 0);
  return m_hBitmap;
}

// FUNCTION: IMPERIALISM 0x0047ae90
int CDib::BuildPaletteFromRgbQuadBuffer() {
  if (m_paletteCount == 0) {
    return 0;
  }
  if (m_hPalette != NULL) {
    DeleteObject(m_hPalette);
  }
  unsigned char* paletteStorage = new unsigned char[m_paletteCount * 4 + 4];
  LOGPALETTE* logPalette = static_cast<LOGPALETTE*>(static_cast<void*>(paletteStorage));
  logPalette->palVersion = 0x300;
  logPalette->palNumEntries = static_cast<WORD>(m_paletteCount);
  const BYTE* source = static_cast<const BYTE*>(m_colorTablePixels);
  for (int i = 0; i < m_paletteCount; i++) {
    logPalette->palPalEntry[i].peRed = source[2];
    logPalette->palPalEntry[i].peGreen = source[1];
    logPalette->palPalEntry[i].peBlue = source[0];
    logPalette->palPalEntry[i].peFlags = 0;
    source += 4;
  }
  m_hPalette = CreatePalette(logPalette);
  delete[] paletteStorage;
  return 1;
}

// FUNCTION: IMPERIALISM 0x0047af60
CPalette* CDib::CreatePaletteObjectFromColorTable() {
  if (m_paletteCount == 0) {
    return NULL;
  }
  unsigned char* paletteStorage = new unsigned char[m_paletteCount * 4 + 4];
  LOGPALETTE* logPalette = static_cast<LOGPALETTE*>(static_cast<void*>(paletteStorage));
  logPalette->palVersion = 0x300;
  logPalette->palNumEntries = static_cast<WORD>(m_paletteCount);
  const BYTE* source = static_cast<const BYTE*>(m_colorTablePixels);
  for (int i = 0; i < m_paletteCount; i++) {
    logPalette->palPalEntry[i].peRed = source[2];
    logPalette->palPalEntry[i].peGreen = source[1];
    logPalette->palPalEntry[i].peBlue = source[0];
    logPalette->palPalEntry[i].peFlags = 0;
    source += 4;
  }
  CPalette* palette = new CPalette();
  HPALETTE hpal = CreatePalette(logPalette);
  palette->Attach(hpal);
  delete[] paletteStorage;
  return palette;
}

// FUNCTION: IMPERIALISM 0x0047b0c0
void CDib::CopyRgbQuadTableFrom(const LOGPALETTE* source) {
  RGBQUAD* dest = static_cast<RGBQUAD*>(m_colorTablePixels);
  for (int i = 0; i < m_paletteCount; i++) {
    dest[i].rgbRed = source->palPalEntry[i].peRed;
    dest[i].rgbGreen = source->palPalEntry[i].peGreen;
    dest[i].rgbBlue = source->palPalEntry[i].peBlue;
    dest[i].rgbReserved = source->palPalEntry[i].peFlags;
  }
}

// Build a device-dependent bitmap (CreateDIBitmap + CBM_INIT) from the stored header and
// bits, compatible with the given DC. Returns NULL when there is no pixel buffer.
// Adopt the palette object's HPALETTE and refill this DIB's colour table from its
// LOGPALETTE entries, reordering each PALETTEENTRY into RGBQUAD form. A null palette
// clears m_hPalette and leaves the table untouched when there are no entries.
// Adopt the palette object's HPALETTE and refill this DIB's colour table from its
// LOGPALETTE entries, reordering each PALETTEENTRY into RGBQUAD form. A null palette
// clears m_hPalette; an empty table skips the copy entirely.
// FUNCTION: IMPERIALISM 0x0047b130
void CDib::AdoptPaletteAndCopyRgbQuadTable(CDibPal* palette) {
  m_hPalette =
      (palette != nullptr) ? static_cast<HPALETTE>(palette->m_hObject) : static_cast<HPALETTE>(0);
  RGBQUAD* dest = static_cast<RGBQUAD*>(m_colorTablePixels);
  int index = 0;
  if (0 < m_paletteCount) {
    PALETTEENTRY* entry = palette->m_pLogPalette->palPalEntry;
    do {
      dest->rgbRed = entry->peRed;
      dest->rgbGreen = entry->peGreen;
      dest->rgbBlue = entry->peBlue;
      dest->rgbReserved = entry->peFlags;
      dest = dest + 1;
      index = index + 1;
      entry = entry + 1;
    } while (index < m_paletteCount);
  }
}

// FUNCTION: IMPERIALISM 0x0047b280
HBITMAP CDib::CreateDibBitmapFromStoredInfo(CDC* dc) {
  if (m_pixelBytes == 0) {
    return NULL;
  }
  return ::CreateDIBitmap(dc->GetSafeHdc(), &m_pInfoHeader->bmiHeader, CBM_INIT, m_dibBits,
                          m_pInfoHeader, DIB_RGB_COLORS);
}

// FUNCTION: IMPERIALISM 0x0047b6d0
int CDib::Read(CFile* file) {
  Release();
  BITMAPFILEHEADER fileHeader;
  if (file->Read(&fileHeader, sizeof(BITMAPFILEHEADER)) != sizeof(BITMAPFILEHEADER)) {
    AfxMessageBox("read error 1", MB_OK, 0);
    return 0;
  }
  if (fileHeader.bfType != kBitmapFileSignature) {
    AfxMessageBox("Invalid bitmap file", MB_OK, 0);
    return 0;
  }

  int infoBytes = fileHeader.bfOffBits - sizeof(BITMAPFILEHEADER);
  m_pInfoHeader = static_cast<BITMAPINFO*>(static_cast<void*>(new unsigned char[infoBytes]));
  m_dibBitsOwned = 1;
  m_infoOwnMode = kDibInfoOwnedByteArray;
  file->Read(m_pInfoHeader, infoBytes);

  m_pixelBytes = m_pInfoHeader->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits = static_cast<unsigned int>(m_pInfoHeader->bmiHeader.biBitCount) *
                           m_pInfoHeader->bmiHeader.biWidth;
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords = rowDwords + 1;
    }
    int rows = m_pInfoHeader->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = m_pInfoHeader->bmiColors;
  m_dibBits = new unsigned char[m_pixelBytes];
  file->Read(m_dibBits, m_pixelBytes);

  if (m_pInfoHeader->bmiHeader.biClrUsed != 0) {
    m_paletteCount = m_pInfoHeader->bmiHeader.biClrUsed;
    BuildPaletteFromRgbQuadBuffer();
    return 1;
  }
  switch (m_pInfoHeader->bmiHeader.biBitCount) {
  case 1:
    m_paletteCount = 2;
    break;
  case 4:
    m_paletteCount = 0x10;
    break;
  case 8:
    m_paletteCount = 0x100;
    break;
  case 0x10:
  case 0x18:
  case 0x20:
    m_paletteCount = 0;
    break;
  }
  BuildPaletteFromRgbQuadBuffer();
  return 1;
}

// FUNCTION: IMPERIALISM 0x0047b9f0
void CDib::Write(CFile* file) {
  BITMAPFILEHEADER fileHeader;
  fileHeader.bfType = kBitmapFileSignature;
  fileHeader.bfReserved1 = 0;
  fileHeader.bfReserved2 = 0;
  int payloadBytes = m_pixelBytes + sizeof(BITMAPINFOHEADER) + m_paletteCount * 4;
  fileHeader.bfOffBits = m_paletteCount * 4 + 0x36;
  fileHeader.bfSize = payloadBytes + sizeof(BITMAPFILEHEADER);
  file->Write(&fileHeader, sizeof(BITMAPFILEHEADER));
  file->Write(m_pInfoHeader, payloadBytes);
}

// FUNCTION: IMPERIALISM 0x0047bb10
void CDib::Serialize(CArchive& archive) {
  archive.Flush();
  if (archive.IsStoring()) {
    Write(archive.GetFile());
  } else {
    Read(archive.GetFile());
  }
}

// FUNCTION: IMPERIALISM 0x0047bca0
void CDib::Release() {
  if (m_hFileMapping != NULL) {
    UnmapViewOfFile(m_mappedView);
    CloseHandle(m_hFile);
    CloseHandle(m_hFileMapping);
    m_hFileMapping = NULL;
  }
  if (m_infoOwnMode == kDibInfoOwnedByteArray) {
    delete[] static_cast<unsigned char*>(static_cast<void*>(m_pInfoHeader));
  } else if (m_infoOwnMode == kDibInfoOwnedGlobalHandle) {
    GlobalUnlock(m_hGlobalInfo);
    GlobalFree(m_hGlobalInfo);
  }
  if (m_dibBitsOwned == 1) {
    delete[] static_cast<unsigned char*>(m_dibBits);
  }
  if (m_hPalette != NULL) {
    DeleteObject(m_hPalette);
  }
  if (m_hBitmap != NULL) {
    DeleteObject(m_hBitmap);
  }
  m_dibBitsOwned = 0;
  m_infoOwnMode = kDibInfoNotOwned;
  m_hGlobalInfo = NULL;
  m_pInfoHeader = NULL;
  m_dibBits = NULL;
  m_colorTablePixels = NULL;
  m_paletteCount = 0;
  m_pixelBytes = 0;
  m_mappedView = NULL;
  m_hFile = NULL;
  m_hFileMapping = NULL;
  m_hBitmap = NULL;
  m_hPalette = NULL;
}

// FUNCTION: IMPERIALISM 0x0047bde0
void CDib::BlitSurfaceRectSkippingTransparentColor(CDib* destDib, int srcX, int srcY,
                                                   unsigned int width, unsigned int height,
                                                   int destX, int destY, int transparentColor) {
  if (width == 0) {
    return;
  }
  if (height == 0) {
    return;
  }

  int srcBottomRow = srcY + static_cast<int>(height) - 1;
  int srcWidth = m_pInfoHeader->bmiHeader.biWidth;
  char* srcPtr;
  if (srcX < srcWidth) {
    int srcHeight = m_pInfoHeader->bmiHeader.biHeight;
    int srcAbsHeight = (srcHeight < 1) ? -srcHeight : srcHeight;
    if (srcAbsHeight <= srcBottomRow) {
      srcPtr = 0;
    } else {
      unsigned int srcStride = (srcWidth + 3) & ~3u;
      if (srcHeight < 0) {
        srcPtr = static_cast<char*>(m_dibBits) + srcBottomRow * srcStride + srcX;
      } else {
        int h = (srcHeight < 1) ? -srcHeight : srcHeight;
        srcPtr = static_cast<char*>(m_dibBits) + ((h - srcBottomRow) - 1) * srcStride + srcX;
      }
    }
  } else {
    srcPtr = 0;
  }

  int destBottomRow = destY + static_cast<int>(height) - 1;
  int destWidth = destDib->m_pInfoHeader->bmiHeader.biWidth;
  char* destPtr;
  if (destX < destWidth) {
    int destHeight = destDib->m_pInfoHeader->bmiHeader.biHeight;
    int destAbsHeight = (destHeight < 1) ? -destHeight : destHeight;
    if (destBottomRow < destAbsHeight) {
      int h = (destHeight < 1) ? -destHeight : destHeight;
      unsigned int destStride = (destWidth + 3) & ~3u;
      destPtr =
          static_cast<char*>(destDib->m_dibBits) + ((h - destBottomRow) - 1) * destStride + destX;
    } else {
      destPtr = 0;
    }
  } else {
    destPtr = 0;
  }

  unsigned int srcStride = (srcWidth + 3) & ~3u;
  unsigned int destStride = (destWidth + 3) & ~3u;

  if (transparentColor != -1) {
    unsigned int rowsRemaining = height;
    do {
      unsigned int colsRemaining = width;
      do {
        char pixel = *srcPtr;
        ++srcPtr;
        if (pixel != static_cast<char>(transparentColor)) {
          *destPtr = pixel;
        }
        ++destPtr;
        --colsRemaining;
      } while (colsRemaining != 0);
      srcPtr += srcStride - width;
      destPtr += destStride - width;
      --rowsRemaining;
    } while (rowsRemaining != 0);
    return;
  }

  do {
    char* srcRow = srcPtr;
    char* destRow = destPtr;
    for (unsigned int w = width >> 2; w != 0; --w) {
      *reinterpret_cast<unsigned int*>(destRow) = *reinterpret_cast<unsigned int*>(srcRow);
      srcRow += 4;
      destRow += 4;
    }
    srcPtr += srcStride;
    for (unsigned int b = width & 3; b != 0; --b) {
      *destRow = *srcRow;
      ++srcRow;
      ++destRow;
    }
    destPtr += destStride;
    --height;
  } while (height != 0);
}

// FUNCTION: IMPERIALISM 0x0047c080
int CDib::LoadBitmapResourceAndInitializeSurfaceState(LPCSTR resourceName, HMODULE module) {
  HRSRC resourceInfo = FindResourceA(module, resourceName, RT_BITMAP);
  if (resourceInfo == NULL) {
    return 0;
  }

  HGLOBAL resource = LoadResource(module, resourceInfo);
  Release();
  m_hGlobalInfo = NULL;
  m_infoOwnMode = kDibInfoNotOwned;
  m_pInfoHeader = reinterpret_cast<BITMAPINFO*>(resource);

  if (m_pInfoHeader->bmiHeader.biClrUsed == 0) {
    switch (m_pInfoHeader->bmiHeader.biBitCount) {
    case 1:
      m_paletteCount = 2;
      break;
    case 4:
      m_paletteCount = 0x10;
      break;
    case 8:
      m_paletteCount = 0x100;
      break;
    case 0x10:
    case 0x18:
    case 0x20:
      m_paletteCount = 0;
      break;
    }
  } else {
    m_paletteCount = m_pInfoHeader->bmiHeader.biClrUsed;
  }

  m_pixelBytes = m_pInfoHeader->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits = static_cast<unsigned int>(m_pInfoHeader->bmiHeader.biWidth) *
                           m_pInfoHeader->bmiHeader.biBitCount;
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords = rowDwords + 1;
    }
    int rows = m_pInfoHeader->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = m_pInfoHeader->bmiColors;
  m_dibBits = reinterpret_cast<BYTE*>(m_colorTablePixels) + m_paletteCount * sizeof(RGBQUAD);
  BuildPaletteFromRgbQuadBuffer();
  return 1;
}

// Convert a 1-bpp bitmap into the one-pixel outline around its set pixels. The byte-level
// scan is intentional: neighboring rows use the DWORD-aligned DIB stride, while horizontal
// neighbors carry across adjacent bytes only when both bytes belong to the same row.
// FUNCTION: IMPERIALISM 0x0047c1f0
int CDib::BuildMonochromeOutlineMaskInPlace() {
  if (m_pInfoHeader->bmiHeader.biBitCount != 1) {
    return 0;
  }

  int rowStride = ((m_pInfoHeader->bmiHeader.biWidth + 31) / 32) * 4;
  int height = m_pInfoHeader->bmiHeader.biHeight;
  if (height < 1) {
    height = -height;
  }
  int byteCount = rowStride * height;
  unsigned char* outline = new unsigned char[byteCount];
  unsigned char* pixels = static_cast<unsigned char*>(m_dibBits);
  memset(outline, 0, m_pixelBytes);

  for (int offset = 0; offset < byteCount; ++offset) {
    unsigned char outside = static_cast<unsigned char>(~pixels[offset]);
    if (offset - rowStride >= 0) {
      outline[offset] =
          static_cast<unsigned char>(outline[offset] | (pixels[offset - rowStride] & outside));
    }
    if (offset + rowStride < byteCount) {
      outline[offset] =
          static_cast<unsigned char>(outline[offset] | (pixels[offset + rowStride] & outside));
    }

    outline[offset] =
        static_cast<unsigned char>(outline[offset] | ((pixels[offset] << 1) & outside));
    if (offset / rowStride == (offset - 1) / rowStride) {
      outline[offset] =
          static_cast<unsigned char>(outline[offset] | ((pixels[offset - 1] << 7) & outside));
    }
    outline[offset] =
        static_cast<unsigned char>(outline[offset] | ((pixels[offset] >> 1) & outside));
    if (offset / rowStride == (offset + 1) / rowStride) {
      outline[offset] =
          static_cast<unsigned char>(outline[offset] | ((pixels[offset + 1] >> 7) & outside));
    }
  }

  memcpy(m_dibBits, outline, byteCount);
  delete[] outline;
  return 1;
}

// Outline-polygon scanner behind BitMapToRegion (see the header comment). The
// heavy local reuse mirrors the original codegen: phase 1 counts every second
// row containing a non-transparent pixel, phase 2 emits the left edge top-down
// then the right edge bottom-up and closes the polygon. Y coordinates are
// flipped through abs(biHeight) because DIB rows are stored bottom-up.
// FUNCTION: IMPERIALISM 0x0047c3d0
int* CDib::BuildNonTransparentOutlinePolygon(unsigned int transparentIndex) {
  byte bVar1;
  int scan_offset;
  int col_idx;
  int byte_idx;
  int* points;
  unsigned int stride;
  int byte_scan;
  int row_stride;
  char cVar9;
  char cVar10;
  byte* scan_ptr;
  int height;
  byte* pixel_ptr;
  int bit_row;
  int width;
  int* out_iter;
  int row_idx;
  int pair_count;
  byte* row_ptr;

  if (m_pInfoHeader->bmiHeader.biBitCount == 1) {
    // 1-bpp path: two phases over bit-packed rows (a set bit = opaque).
    width = m_pInfoHeader->bmiHeader.biWidth;
    height = m_pInfoHeader->bmiHeader.biHeight;
    bit_row = 0;
    transparentIndex = 0;
    scan_offset = (int)(width + 0x1f + ((width + 0x1f) >> 0x1f & 0x1fU)) >> 5;
    row_stride = reinterpret_cast<int>(m_dibBits);
    col_idx = scan_offset * 0x20;
    row_idx = row_stride;
    while (true) {
      byte_idx = height;
      if (height < 1) {
        byte_idx = -height;
      }
      if (byte_idx <= bit_row) {
        break;
      }
      byte_scan = 0;
      byte_idx = (int)(width + (width >> 0x1f & 7U)) >> 3;
      if (byte_idx < 1) {
      LAB_0047c453:
        bit_row = bit_row + 8;
        row_idx = row_idx + col_idx;
      } else {
        do {
          if (*(char*)(byte_scan + row_idx) != '\0') {
            transparentIndex = transparentIndex + 1;
            goto LAB_0047c453;
          }
          byte_scan = byte_scan + 1;
        } while (byte_scan < byte_idx);
        bit_row = bit_row + 8;
        row_idx = row_idx + col_idx;
      }
    }
    points = new int[(transparentIndex + 1) * 4];
    width = 0;
    *points = transparentIndex * 2 + 1;
    transparentIndex = 1;
    height = 0;
    out_iter = points + 2;
  LAB_0047c48c:
    do {
      row_idx = m_pInfoHeader->bmiHeader.biHeight;
      bit_row = row_idx;
      if (row_idx < 1) {
        bit_row = -row_idx;
      }
      if (bit_row <= width) {
        width = width + -8;
        if (-1 < width) {
          height = width * scan_offset * 4;
          out_iter = points + transparentIndex * 2;
          do {
            row_idx = m_pInfoHeader->bmiHeader.biWidth;
            row_idx = ((int)(row_idx + (row_idx >> 0x1f & 7U)) >> 3) + -1;
            if (-1 < row_idx) {
            LAB_0047c55c:
              if (*(char*)(row_idx + row_stride + height) == '\0') {
                goto code_r0x0047c562;
              }
              cVar10 = '\0';
              for (cVar9 = *(char*)(row_idx + row_stride + height); cVar9 != '\0';
                   cVar9 = cVar9 << 1) {
                cVar10 = cVar10 + '\x01';
              }
              col_idx = m_pInfoHeader->bmiHeader.biHeight;
              if (col_idx < 1) {
                col_idx = -col_idx;
              }
              *out_iter = (int)cVar10 + row_idx * 8;
              out_iter[1] = (col_idx - width) + -1;
              transparentIndex = transparentIndex + 1;
              out_iter = out_iter + 2;
            }
          LAB_0047c5a0:
            width = width + -8;
            height = height + scan_offset * -0x20;
          } while (-1 < width);
        }
        points[transparentIndex * 2] = points[2];
        points[transparentIndex * 2 + 1] = points[3];
        return points;
      }
      bit_row = m_pInfoHeader->bmiHeader.biWidth;
      byte_idx = 0;
      bit_row = (int)(bit_row + (bit_row >> 0x1f & 7U)) >> 3;
      if (0 < bit_row) {
      LAB_0047c4be:
        if (*(char*)(byte_idx + row_stride + height) == '\0') {
          goto code_r0x0047c4c4;
        }
        cVar9 = '\0';
        for (bVar1 = *(byte*)(byte_idx + row_stride + height); bVar1 != 0; bVar1 = bVar1 >> 1) {
          cVar9 = cVar9 + '\x01';
        }
        if (row_idx < 1) {
          row_idx = -row_idx;
        }
        *out_iter = (byte_idx * 8 + 8) - (int)cVar9;
        transparentIndex = transparentIndex + 1;
        out_iter[1] = (row_idx - width) + -1;
        out_iter = out_iter + 2;
      }
      width = width + 8;
      height = height + col_idx;
    } while (true);
  code_r0x0047c562:
    row_idx = row_idx + -1;
    if (row_idx < 0) {
      goto LAB_0047c5a0;
    }
    goto LAB_0047c55c;
  code_r0x0047c4c4:
    byte_idx = byte_idx + 1;
    if (bit_row <= byte_idx) {
      goto code_r0x0047c4c9;
    }
    goto LAB_0047c4be;
  code_r0x0047c4c9:
    width = width + 8;
    height = height + col_idx;
    goto LAB_0047c48c;
  }

  // 8-bpp path.
  width = m_pInfoHeader->bmiHeader.biWidth;
  pixel_ptr = static_cast<byte*>(m_dibBits);
  stride = width + 3U & 0xfffffffc;
  if (transparentIndex == 0xffffffff) {
    transparentIndex = *pixel_ptr;
  }
  height = m_pInfoHeader->bmiHeader.biHeight;
  row_idx = 0;
  scan_offset = 0;
  row_stride = stride * 2;
  scan_ptr = pixel_ptr;
LAB_0047c603:
  do {
    col_idx = height;
    if (height < 1) {
      col_idx = -height;
    }
    if (col_idx <= scan_offset) {
      points = new int[(row_idx + 1) * 4];
      *points = row_idx * 2 + 1;
      pair_count = 1;
      height = 0;
      out_iter = points + 2;
      row_ptr = pixel_ptr;
      do {
        width = m_pInfoHeader->bmiHeader.biHeight;
        row_idx = width;
        if (width < 1) {
          row_idx = -width;
        }
        if (row_idx <= height) {
          height = height + -2;
          if (-1 < height) {
            out_iter = points + pair_count * 2;
            pixel_ptr = pixel_ptr + height * stride;
            do {
              width = m_pInfoHeader->bmiHeader.biWidth;
              do {
                width = width + -1;
                if (width < 0) {
                  goto LAB_0047c72a;
                }
              } while (pixel_ptr[width] == transparentIndex);
              row_stride = m_pInfoHeader->bmiHeader.biHeight;
              if (row_stride < 1) {
                row_stride = -row_stride;
              }
              *out_iter = width;
              pair_count = pair_count + 1;
              out_iter[1] = (row_stride - height) + -1;
              out_iter = out_iter + 2;
            LAB_0047c72a:
              height = height + -2;
              pixel_ptr = pixel_ptr + stride * -2;
            } while (-1 < height);
          }
          points[pair_count * 2] = points[2];
          points[pair_count * 2 + 1] = points[3];
          return points;
        }
        row_idx = m_pInfoHeader->bmiHeader.biWidth;
        scan_offset = 0;
        if (0 < row_idx) {
          do {
            if (row_ptr[scan_offset] != transparentIndex) {
              if (width < 1) {
                width = -width;
              }
              *out_iter = scan_offset;
              out_iter[1] = (width - height) + -1;
              pair_count = pair_count + 1;
              out_iter = out_iter + 2;
              break;
            }
            scan_offset = scan_offset + 1;
          } while (scan_offset < row_idx);
        }
        height = height + 2;
        row_ptr = row_ptr + row_stride;
      } while (true);
    }
    col_idx = 0;
    if (0 < width) {
      do {
        if (scan_ptr[col_idx] != transparentIndex) {
          row_idx = row_idx + 1;
          goto LAB_0047c631;
        }
        col_idx = col_idx + 1;
      } while (col_idx < width);
      scan_offset = scan_offset + 2;
      scan_ptr = scan_ptr + row_stride;
      goto LAB_0047c603;
    }
  LAB_0047c631:
    scan_offset = scan_offset + 2;
    scan_ptr = scan_ptr + row_stride;
  } while (true);
}

// FUNCTION: IMPERIALISM 0x0047c980
void CDib::FlipScanlineOrder() {
  const unsigned int stride = (m_pInfoHeader->bmiHeader.biWidth + 3U) & ~3U;
  unsigned char* temporaryRow = new unsigned char[stride];
  unsigned char* firstRow = static_cast<unsigned char*>(m_dibBits);
  int height = m_pInfoHeader->bmiHeader.biHeight;
  if (height < 1) {
    height = -height;
  }
  unsigned char* lastRow = firstRow + (height - 1) * stride;

  for (int remaining = height / 2; remaining != 0; --remaining) {
    memcpy(temporaryRow, firstRow, stride);
    memcpy(firstRow, lastRow, stride);
    firstRow += stride;
    memcpy(lastRow, temporaryRow, stride);
    lastRow -= stride;
  }
  delete[] temporaryRow;
}

// FUNCTION: IMPERIALISM 0x004849e0
void CDib::ForwardBlitSurfaceRectSkippingTransparentColor(CDib* destDib, POINT* srcPoint,
                                                          POINT* sizePoint, POINT* destPoint,
                                                          int transparentColor) {
  BlitSurfaceRectSkippingTransparentColor(destDib, srcPoint->x, srcPoint->x, sizePoint->x,
                                          sizePoint->y, destPoint->x, destPoint->y,
                                          transparentColor);
}

// Builds a temporary CDib matching the source bitmap's depth, blits `sourceDib`'s pixels
// into it (a straight BitBlt of the destination DC region plus a transparent-color-skipping
// surface copy from the source), then stretch-presents the composed surface back to the
// destination DC at (srcX, srcY). The temp surface and its selected bitmap are released.
// FUNCTION: IMPERIALISM 0x00496b80
void BlitBitmapResourceToTemporaryCompatibleDcAndPresent(CDC* destDc, CDib* sourceDib, short srcX,
                                                         short srcY, short transparentColor,
                                                         short surfaceSrcX, short surfaceSrcY,
                                                         short width, short height) {
  CDib* surface = new CDib(width, height, sourceDib->m_pInfoHeader->bmiHeader.biBitCount);
  surface->EnsureDibSectionCreated(destDc);
  surface->CopyRgbQuadTableFrom(g_pModuleLibraryCacheState->ResolveDefaultLogPalette());

  HDC tempDc = ::CreateCompatibleDC(destDc != NULL ? destDc->m_hDC : NULL);
  HGDIOBJ oldBitmap = ::SelectObject(tempDc, surface->m_hBitmap);
  ::BitBlt(tempDc, 0, 0, width, height, destDc != NULL ? destDc->m_hDC : NULL, srcX, srcY, SRCCOPY);

  sourceDib->BlitSurfaceRectSkippingTransparentColor(surface, surfaceSrcX, surfaceSrcY, width,
                                                     height, 0, 0, transparentColor);

  POINT topLeft;
  topLeft.x = srcX;
  topLeft.y = srcY;
  surface->StretchDibitsFromStoredBitmapToHdc(destDc, &topLeft);

  ::SelectObject(tempDc, oldBitmap);
  ::DeleteDC(tempDc);
  delete surface;
}

// FUNCTION: IMPERIALISM 0x00575080
int CDib::GetAbsoluteHeight() {
  int height = m_pInfoHeader->bmiHeader.biHeight;
  if (height <= 0) {
    height = -height;
  }
  return height;
}
