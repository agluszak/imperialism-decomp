#include "game/gfx/CDib.h"
#include "game/gfx/CDibPal.h"

#include "game/gfx/TResourceMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

namespace {

const WORD kBitmapFileSignature = 0x4d42;

} // namespace

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
  if (g_nDibOrientationFlag > 0) {
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
      ++rowDwords;
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

  unsigned char* mapped =
      static_cast<unsigned char*>(MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0));
  const BITMAPFILEHEADER* fileHeader =
      static_cast<const BITMAPFILEHEADER*>(static_cast<const void*>(mapped));
  if (fileHeader->bfType != 0x4d42) {
    AfxMessageBox("Invalid bitmap file", 0, 0);
    return 0;
  }

  Release();
  m_hGlobalInfo = NULL;
  m_infoOwnMode = kDibInfoNotOwned;

  BITMAPINFO* info =
      static_cast<BITMAPINFO*>(static_cast<void*>(mapped + sizeof(BITMAPFILEHEADER)));
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
      ++rowDwords;
    }
    int rows = info->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = mapped + 0x36;
  m_dibBits = mapped + 0x36 + m_paletteCount * 4;
  BuildPaletteFromRgbQuadBuffer();
  m_mappedView = mapped;
  m_hFileMapping = fileHandle;
  m_hFile = mappingHandle;
  return 1;
}

// FUNCTION: IMPERIALISM 0x0047a630
int CDib::RemapSurfaceToMemoryMappedBmpFile(LPCSTR fileName) {
  int offBits = m_paletteCount * 4 + 0x36;
  unsigned int fileSize = offBits + m_pixelBytes;

  BITMAPFILEHEADER fileHeader;
  fileHeader.bfType = 0x4d42;
  fileHeader.bfSize = fileSize;
  fileHeader.bfReserved1 = 0;
  fileHeader.bfReserved2 = 0;
  fileHeader.bfOffBits = offBits;

  HANDLE fileHandle =
      CreateFileA(fileName, 0xc0000000, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE mappingHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READWRITE, 0,
                                            m_pixelBytes + 0x36 + m_paletteCount * 4, NULL);
  GetLastError();
  unsigned char* mapped =
      static_cast<unsigned char*>(MapViewOfFile(mappingHandle, FILE_MAP_WRITE, 0, 0, 0));
  memcpy(mapped, &fileHeader, sizeof(fileHeader));

  // Copy the packed BITMAPINFOHEADER (0x28 bytes) + color table into the mapped file.
  unsigned char* infoDest = mapped + sizeof(BITMAPFILEHEADER);
  memcpy(infoDest, m_pInfoHeader, m_paletteCount * 4 + sizeof(BITMAPINFOHEADER));

  // Copy the pixel buffer after the header + color table.
  unsigned int pixelBytes = m_pixelBytes;
  unsigned char* pixelStart = mapped + m_paletteCount * 4 + 0x36;
  memcpy(pixelStart, m_dibBits, pixelBytes);

  int savedPixelBytes = m_pixelBytes;
  Release();
  m_pixelBytes = savedPixelBytes;

  m_dibBits = pixelStart;
  m_hFileMapping = fileHandle;
  m_hFile = mappingHandle;
  m_dibBitsOwned = 0;
  m_infoOwnMode = kDibInfoNotOwned;
  m_pInfoHeader = static_cast<BITMAPINFO*>(static_cast<void*>(infoDest));
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
      ++rowDwords;
    }
    int rows = m_pInfoHeader->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = mapped + 0x36;
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
  unsigned int bitCount = info->bmiHeader.biBitCount;
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
      ++rowDwords;
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

// FUNCTION: IMPERIALISM 0x0047b030
LOGPALETTE* CDib::CreateLogPaletteFromColorTable() {
  if (m_paletteCount == 0) {
    return NULL;
  }
  unsigned char* storage = new unsigned char[m_paletteCount * sizeof(PALETTEENTRY) + 4];
  LOGPALETTE* palette = static_cast<LOGPALETTE*>(static_cast<void*>(storage));
  palette->palVersion = 0x300;
  palette->palNumEntries = static_cast<WORD>(m_paletteCount);
  RGBQUAD* source = static_cast<RGBQUAD*>(m_colorTablePixels);
  for (int i = 0; i < m_paletteCount; i++) {
    palette->palPalEntry[i].peRed = source[i].rgbRed;
    palette->palPalEntry[i].peGreen = source[i].rgbGreen;
    palette->palPalEntry[i].peBlue = source[i].rgbBlue;
    palette->palPalEntry[i].peFlags = 0;
  }
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

// FUNCTION: IMPERIALISM 0x0047b130
void CDib::AdoptPaletteAndCopyRgbQuadTable(CDibPal* palette) {
  m_hPalette =
      (palette != NULL) ? static_cast<HPALETTE>(palette->m_hObject) : static_cast<HPALETTE>(0);
  RGBQUAD* dest = static_cast<RGBQUAD*>(m_colorTablePixels);
  int index = 0;
  if (0 < m_paletteCount) {
    PALETTEENTRY* entry = palette->m_pLogPalette->palPalEntry;
    do {
      dest->rgbRed = entry->peRed;
      dest->rgbGreen = entry->peGreen;
      dest->rgbBlue = entry->peBlue;
      dest->rgbReserved = entry->peFlags;
      ++dest;
      ++index;
      ++entry;
    } while (index < m_paletteCount);
  }
}

// FUNCTION: IMPERIALISM 0x0047b1b0
BOOL CDib::SetSystemPalette(CDC* dc) {
  if (m_paletteCount != 0) {
    return FALSE;
  }
  HDC hdc = dc != NULL ? dc->m_hDC : NULL;
  if ((::GetDeviceCaps(hdc, RASTERCAPS) & RC_PALETTE) == 0) {
    return FALSE;
  }
  int entryCount = ::GetDeviceCaps(hdc, NUMCOLORS);
  int paletteSize = ::GetDeviceCaps(hdc, SIZEPALETTE);
  if (paletteSize != 0) {
    entryCount = paletteSize;
  }
  unsigned char* storage = new unsigned char[entryCount * sizeof(PALETTEENTRY) + 4];
  LOGPALETTE* palette = static_cast<LOGPALETTE*>(static_cast<void*>(storage));
  palette->palVersion = 0x300;
  palette->palNumEntries = static_cast<WORD>(entryCount);
  ::GetSystemPaletteEntries(hdc, 0, entryCount, palette->palPalEntry);
  m_hPalette = ::CreatePalette(palette);
  delete[] storage;
  return TRUE;
}

// FUNCTION: IMPERIALISM 0x0047b280
HBITMAP CDib::CreateDibBitmapFromStoredInfo(CDC* dc) {
  if (m_pixelBytes == 0) {
    return NULL;
  }
  return ::CreateDIBitmap(dc->GetSafeHdc(), &m_pInfoHeader->bmiHeader, CBM_INIT, m_dibBits,
                          m_pInfoHeader, DIB_RGB_COLORS);
}

// FUNCTION: IMPERIALISM 0x0047b2d0
BOOL CDib::Compress(CDC* dc, BOOL compress) {
  if (g_dibCompressAssertGate == 0) {
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\CDib.cpp", 0x31b);
  }

  if (m_pInfoHeader->bmiHeader.biBitCount != 4 && m_pInfoHeader->bmiHeader.biBitCount != 8) {
    return FALSE;
  }
  if (m_hBitmap != NULL) {
    return FALSE;
  }

  HDC hdc = dc != NULL ? dc->m_hDC : NULL;
  HPALETTE oldPalette = ::SelectPalette(hdc, m_hPalette, FALSE);
  HBITMAP bitmap;
  if (m_pixelBytes == 0) {
    bitmap = NULL;
  } else {
    bitmap = ::CreateDIBitmap(hdc, &m_pInfoHeader->bmiHeader, CBM_INIT, m_dibBits, m_pInfoHeader,
                              DIB_RGB_COLORS);
  }
  if (bitmap == NULL) {
    return FALSE;
  }

  int infoBytes = sizeof(BITMAPINFOHEADER) + sizeof(RGBQUAD) * m_paletteCount;
  BITMAPINFO* info = static_cast<BITMAPINFO*>(static_cast<void*>(new unsigned char[infoBytes]));
  memcpy(info, m_pInfoHeader, infoBytes);

  if (compress != FALSE) {
    switch (info->bmiHeader.biBitCount) {
    case 4:
      info->bmiHeader.biCompression = BI_RLE4;
      break;
    case 8:
      info->bmiHeader.biCompression = BI_RLE8;
      break;
    }

    if (::GetDIBits(hdc, bitmap, 0, info->bmiHeader.biHeight, NULL, info, DIB_RGB_COLORS) == 0) {
      AfxMessageBox("Unable to compress this DIB", MB_OK, 0);
      ::DeleteObject(bitmap);
      delete[] static_cast<unsigned char*>(static_cast<void*>(info));
      ::SelectPalette(hdc, oldPalette, FALSE);
      return FALSE;
    }
    if (info->bmiHeader.biSizeImage == 0) {
      AfxMessageBox("Driver can't do compression", MB_OK, 0);
      ::DeleteObject(bitmap);
      delete[] static_cast<unsigned char*>(static_cast<void*>(info));
      ::SelectPalette(hdc, oldPalette, FALSE);
      return FALSE;
    }
    m_pixelBytes = info->bmiHeader.biSizeImage;
  } else {
    info->bmiHeader.biCompression = BI_RGB;
    unsigned int rowBits =
        static_cast<unsigned int>(info->bmiHeader.biWidth) * info->bmiHeader.biBitCount;
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords++;
    }
    int rows = info->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * sizeof(int) * rows;
    info->bmiHeader.biSizeImage = m_pixelBytes;
  }

  unsigned char* pixels = new unsigned char[m_pixelBytes];
  ::GetDIBits(hdc, bitmap, 0, info->bmiHeader.biHeight, pixels, info, DIB_RGB_COLORS);
  ::DeleteObject(bitmap);

  Release();
  m_dibBitsOwned = TRUE;
  m_infoOwnMode = kDibInfoOwnedByteArray;
  m_pInfoHeader = info;
  m_dibBits = pixels;

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
        static_cast<unsigned int>(info->bmiHeader.biWidth) * info->bmiHeader.biBitCount;
    unsigned int rowDwords = rowBits >> 5;
    if ((rowBits & 0x1f) != 0) {
      rowDwords++;
    }
    int rows = info->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * sizeof(int) * rows;
  }

  m_colorTablePixels = info->bmiColors;
  BuildPaletteFromRgbQuadBuffer();
  ::SelectPalette(hdc, oldPalette, FALSE);
  return TRUE;
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
      ++rowDwords;
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

// FUNCTION: IMPERIALISM 0x0047bb60
void CDib::ComputePaletteSize(unsigned int bitCount) {
  if (m_pInfoHeader != NULL && m_pInfoHeader->bmiHeader.biClrUsed != 0) {
    m_paletteCount = m_pInfoHeader->bmiHeader.biClrUsed;
    return;
  }
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
}

// FUNCTION: IMPERIALISM 0x0047bc30
void CDib::ComputeMetrics() {
  m_pixelBytes = m_pInfoHeader->bmiHeader.biSizeImage;
  if (m_pixelBytes == 0) {
    unsigned int rowBits = static_cast<unsigned int>(m_pInfoHeader->bmiHeader.biWidth) *
                           m_pInfoHeader->bmiHeader.biBitCount;
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

// FUNCTION: IMPERIALISM 0x0047bd90
void CDib::ReleaseMappedFileView() {
  if (m_hFileMapping != NULL) {
    UnmapViewOfFile(m_mappedView);
    CloseHandle(m_hFile);
    CloseHandle(m_hFileMapping);
    m_hFileMapping = NULL;
  }
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
    unsigned int copiedDwordBytes = width & ~3u;
    memcpy(destRow, srcRow, copiedDwordBytes);
    srcRow += copiedDwordBytes;
    destRow += copiedDwordBytes;
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

// FUNCTION: IMPERIALISM 0x0047bf90
void* CDib::GetPixelAddress(int x, int y) {
  int width = m_pInfoHeader->bmiHeader.biWidth;
  if (x < width) {
    int height = m_pInfoHeader->bmiHeader.biHeight;
    int absoluteHeight = height;
    if (absoluteHeight <= 0) {
      absoluteHeight = -absoluteHeight;
    }
    if (y < absoluteHeight) {
      unsigned int rowStride = (width + 3) & ~3u;
      if (height <= 0) {
        height = -height;
      }
      return static_cast<unsigned char*>(m_dibBits) + (height - y - 1) * rowStride + x;
    }
  }
  return NULL;
}

// FUNCTION: IMPERIALISM 0x0047c000
void* CDib::GetPixelAddressRespectingTopDownOrientation(int x, int y) {
  int width = m_pInfoHeader->bmiHeader.biWidth;
  if (x >= width) {
    return NULL;
  }
  int signedHeight = m_pInfoHeader->bmiHeader.biHeight;
  int height = signedHeight > 0 ? signedHeight : -signedHeight;
  if (y >= height) {
    return NULL;
  }
  int stride = (width + 3) & ~3;
  unsigned char* pixels = static_cast<unsigned char*>(m_dibBits);
  if (signedHeight < 0) {
    return pixels + y * stride + x;
  }
  return pixels + (height - y - 1) * stride + x;
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
  m_pInfoHeader = static_cast<BITMAPINFO*>(static_cast<void*>(resource));

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
      ++rowDwords;
    }
    int rows = m_pInfoHeader->bmiHeader.biHeight;
    if (rows < 1) {
      rows = -rows;
    }
    m_pixelBytes = rowDwords * 4 * rows;
  }

  m_colorTablePixels = m_pInfoHeader->bmiColors;
  m_dibBits = static_cast<BYTE*>(m_colorTablePixels) + m_paletteCount * sizeof(RGBQUAD);
  BuildPaletteFromRgbQuadBuffer();
  return 1;
}

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

// DIB rows are stored bottom-up.
// FUNCTION: IMPERIALISM 0x0047c3d0
POINT* CDib::BuildNonTransparentOutlinePolygon(unsigned int transparentIndex) {
  // The outline is points[0].x = vertex count, then the left edge top to bottom, the right edge
  // bottom to top, and a closing copy of the first vertex. y is flipped to top-down rows.
  int row;
  int col;
  int count;
  POINT* points;
  POINT* out;

  if (m_pInfoHeader->bmiHeader.biBitCount == 1) {
    // 1-bpp mask: a set bit is opaque; every eighth row is sampled.
    int width = m_pInfoHeader->bmiHeader.biWidth;
    int height = m_pInfoHeader->bmiHeader.biHeight;
    int absHeight = height < 1 ? -height : height;
    int dwordsPerRow = (width + 0x1f) / 32;
    int sampleStep = dwordsPerRow * 0x20; // eight rows of bytes
    int rowBytes = width / 8;
    byte* bits = static_cast<byte*>(m_dibBits);

    count = 0;
    byte* scanRow = bits;
    for (row = 0; row < absHeight; row += 8, scanRow += sampleStep) {
      for (col = 0; col < rowBytes; ++col) {
        if (scanRow[col] != 0) {
          ++count;
          break;
        }
      }
    }

    points = new POINT[(count + 1) * 2];
    points[0].x = count * 2 + 1;
    count = 1;
    out = points + 1;
    int offset = 0;
    for (row = 0; row < absHeight; row += 8, offset += sampleStep) {
      for (col = 0; col < rowBytes; ++col) {
        byte value = bits[col + offset];
        if (value != 0) {
          char bitLength = 0;
          for (; value != 0; value = value >> 1) {
            ++bitLength;
          }
          out->x = (col * 8 + 8) - bitLength;
          out->y = (absHeight - row) - 1;
          ++count;
          ++out;
          break;
        }
      }
    }
    for (row -= 8, offset = row * dwordsPerRow * 4; row >= 0; row -= 8, offset -= sampleStep) {
      for (col = rowBytes - 1; col >= 0; --col) {
        if (bits[col + offset] != 0) {
          char shiftsToClear = 0;
          for (char value = bits[col + offset]; value != 0; value = static_cast<char>(value << 1)) {
            ++shiftsToClear;
          }
          out->x = shiftsToClear + col * 8;
          out->y = (absHeight - row) - 1;
          ++count;
          ++out;
          break;
        }
      }
    }
    points[count] = points[1];
    return points;
  }

  // 8-bpp: every other row is sampled; -1 takes the transparent index from the first pixel.
  int width = m_pInfoHeader->bmiHeader.biWidth;
  byte* pixels = static_cast<byte*>(m_dibBits);
  unsigned int stride = width + 3U & 0xfffffffc;
  if (transparentIndex == 0xffffffff) {
    transparentIndex = *pixels;
  }
  int height = m_pInfoHeader->bmiHeader.biHeight;
  int absHeight = height < 1 ? -height : height;

  count = 0;
  byte* scanRow = pixels;
  for (row = 0; row < absHeight; row += 2, scanRow += stride * 2) {
    for (col = 0; col < width; ++col) {
      if (scanRow[col] != transparentIndex) {
        ++count;
        break;
      }
    }
  }

  points = new POINT[(count + 1) * 2];
  points[0].x = count * 2 + 1;
  count = 1;
  out = points + 1;
  scanRow = pixels;
  for (row = 0; row < absHeight; row += 2, scanRow += stride * 2) {
    for (col = 0; col < width; ++col) {
      if (scanRow[col] != transparentIndex) {
        out->x = col;
        out->y = (absHeight - row) - 1;
        ++count;
        ++out;
        break;
      }
    }
  }
  row -= 2;
  for (scanRow = pixels + row * stride; row >= 0; row -= 2, scanRow -= stride * 2) {
    for (col = width - 1; col >= 0; --col) {
      if (scanRow[col] != transparentIndex) {
        out->x = col;
        out->y = (absHeight - row) - 1;
        ++count;
        ++out;
        break;
      }
    }
  }
  points[count] = points[1];
  return points;
}

// FUNCTION: IMPERIALISM 0x0047c850
BOOL CDib::MapColorTableAndPixelsToPalette(CPalette* palette) {
  unsigned char translation[0x100];
  RGBQUAD* sourceColors = static_cast<RGBQUAD*>(m_colorTablePixels);
  HPALETTE paletteHandle = static_cast<HPALETTE>(palette->m_hObject);
  for (int i = 0; i < 0x100; i++) {
    COLORREF color = RGB(sourceColors[i].rgbRed, sourceColors[i].rgbGreen, sourceColors[i].rgbBlue);
    translation[i] = static_cast<unsigned char>(::GetNearestPaletteIndex(paletteHandle, color));
  }
  translation[0x10] = 0x10;

  int rows = m_pInfoHeader->bmiHeader.biHeight;
  if (rows < 1) {
    rows = -rows;
  }
  int byteCount = ((m_pInfoHeader->bmiHeader.biWidth + 3) & ~3) * rows;
  unsigned char* pixels = static_cast<unsigned char*>(m_dibBits);
  for (int remaining = byteCount; remaining != 0; remaining--) {
    *pixels = translation[*pixels];
    pixels++;
  }

  PALETTEENTRY entries[0x100];
  ::GetPaletteEntries(paletteHandle, 0, 0x100, entries);
  RGBQUAD* destination = static_cast<RGBQUAD*>(m_colorTablePixels);
  for (int j = 0; j < 0x100; j++) {
    destination[j].rgbRed = entries[j].peRed;
    destination[j].rgbGreen = entries[j].peGreen;
    destination[j].rgbBlue = entries[j].peBlue;
  }
  m_pInfoHeader->bmiHeader.biClrUsed = 0x100;
  return TRUE;
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

// FUNCTION: IMPERIALISM 0x00496b80
void BlitBitmapResourceToTemporaryCompatibleDcAndPresent(CDC* destDc, CDib* sourceDib, short srcX,
                                                         short srcY, short transparentColor,
                                                         short surfaceSrcX, short surfaceSrcY,
                                                         short width, short height) {
  CDib* surface = new CDib(width, height, sourceDib->m_pInfoHeader->bmiHeader.biBitCount);
  surface->EnsureDibSectionCreated(destDc);
  surface->CopyRgbQuadTableFrom(g_pResourceMgr->ResolveDefaultLogPalette());

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
