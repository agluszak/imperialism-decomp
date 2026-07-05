#include "game/CDib.h"

#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x00479ed0
CRuntimeClass* CDib::GetRuntimeClass() const {
  return &s_CDib_RuntimeClass_00694b48;
}

// FUNCTION: IMPERIALISM 0x00479f40
CDib::CDib() : CObject() {
  m_hBitmap = NULL;
  m_infoOwnMode = 0;
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
  m_infoOwnMode = 0;
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

  m_pInfoHeader = static_cast<BITMAPINFO*>(
      ::operator new(width * height + sizeof(BITMAPINFOHEADER) + m_paletteCount * 4));
  m_infoOwnMode = 1;
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

// FUNCTION: IMPERIALISM 0x0047abe0
int CDib::StretchDibitsRectToDc(CDC* dc, int xDest, int yDest, int destWidth, int destHeight,
                                int xSrc, int ySrc, int srcWidth, int srcHeight) {
  return ::StretchDIBits(dc->GetSafeHdc(), xDest, yDest, destWidth, destHeight, xSrc, ySrc,
                         srcWidth, srcHeight, m_dibBits, m_pInfoHeader, DIB_RGB_COLORS, SRCCOPY);
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
  LOGPALETTE* logPalette = static_cast<LOGPALETTE*>(::operator new(m_paletteCount * 4 + 4));
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
  ::operator delete(logPalette);
  return 1;
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

// FUNCTION: IMPERIALISM 0x0047b6d0
int CDib::Read(CFile* file) {
  Release();
  BITMAPFILEHEADER fileHeader;
  if (file->Read(&fileHeader, sizeof(BITMAPFILEHEADER)) != sizeof(BITMAPFILEHEADER)) {
    AfxMessageBox("read error 1", MB_OK, 0);
    return 0;
  }
  if (fileHeader.bfType != 0x4d42) {
    AfxMessageBox("Invalid bitmap file", MB_OK, 0);
    return 0;
  }

  int infoBytes = fileHeader.bfOffBits - sizeof(BITMAPFILEHEADER);
  m_pInfoHeader = static_cast<BITMAPINFO*>(::operator new(infoBytes));
  m_dibBitsOwned = 1;
  m_infoOwnMode = 1;
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
  m_dibBits = ::operator new(m_pixelBytes);
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
  fileHeader.bfType = 0x4d42;
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
  if (m_infoOwnMode == 1) {
    ::operator delete(m_pInfoHeader);
  } else if (m_infoOwnMode == 2) {
    GlobalUnlock(m_hGlobalInfo);
    GlobalFree(m_hGlobalInfo);
  }
  if (m_dibBitsOwned == 1) {
    ::operator delete(m_dibBits);
  }
  if (m_hPalette != NULL) {
    DeleteObject(m_hPalette);
  }
  if (m_hBitmap != NULL) {
    DeleteObject(m_hBitmap);
  }
  m_dibBitsOwned = 0;
  m_infoOwnMode = 0;
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
  m_infoOwnMode = 0;
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
