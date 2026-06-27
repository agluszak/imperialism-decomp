#include "game/CDib.h"

// Orientation flag: when > 0 the engine builds top-down DIBs (negative biHeight).
// GLOBAL: IMPERIALISM 0x006a1890
int g_nDibOrientationFlag_006A1890 = 0;

// CRuntimeClass descriptor returned by GetRuntimeClass (data values matched separately).
// GLOBAL: IMPERIALISM 0x00694b48
CRuntimeClass s_CDib_RuntimeClass_00694b48 = {nullptr, 0, 0, nullptr, nullptr};

// FUNCTION: IMPERIALISM 0x00479ed0
CRuntimeClass* CDib::GetRuntimeClass() const {
  return &s_CDib_RuntimeClass_00694b48;
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

// FUNCTION: IMPERIALISM 0x0047ae20
HBITMAP CDib::EnsureDibSectionCreated(HDC hdc) {
  if (m_pInfoHeader == NULL) {
    return NULL;
  }
  if (m_dibBits != NULL) {
    return NULL;
  }
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
