#include "game/gfx/CDibPal.h"

#include <afxdlgs.h>
#include <stdlib.h>
#include <string.h>

// FUNCTION: IMPERIALISM 0x0047e360
CDibPal::CDibPal() : CPalette() {
  m_pLogPalette = NULL;
}

// The scalar deleting destructor is compiler-generated from the virtual dtor.
// SYNTHETIC: IMPERIALISM 0x0047e390
// CDibPal::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0047e3c0
CDibPal::~CDibPal() {
  if (m_pLogPalette != NULL) {
    free(m_pLogPalette);
  }
}

// FUNCTION: IMPERIALISM 0x0047e440
int CDibPal::BuildPaletteFromBitmapColorTable(CDib* dib) {
  int colorCount = dib->m_paletteCount;
  if (colorCount == 0) {
    return 0;
  }

  const BYTE* source = static_cast<const BYTE*>(dib->m_colorTablePixels);
  if (m_pLogPalette != NULL) {
    free(m_pLogPalette);
  }

  m_pLogPalette = static_cast<LOGPALETTE*>(malloc(colorCount * sizeof(PALETTEENTRY) + 8));
  if (m_pLogPalette == NULL) {
    return 0;
  }

  m_pLogPalette->palVersion = 0x300;
  m_pLogPalette->palNumEntries = static_cast<WORD>(colorCount);
  for (int i = 0; i < colorCount; i++) {
    m_pLogPalette->palPalEntry[i].peRed = source[2];
    m_pLogPalette->palPalEntry[i].peGreen = source[1];
    m_pLogPalette->palPalEntry[i].peBlue = source[0];
    m_pLogPalette->palPalEntry[i].peFlags = 0;
    source += sizeof(RGBQUAD);
  }

  return Attach(::CreatePalette(m_pLogPalette));
}

// FUNCTION: IMPERIALISM 0x0047e590
void CDibPal::DrawPalettePreviewGridRectangles(CDC* dc, RECT* bounds, BOOL bForceBackground) {
  // The entry count only counts if GetObject succeeded: 0x0047e5d2's NEG/SBB turns the
  // return into a 0 or -1 mask and ANDs it over the count, so a failed query draws
  // nothing rather than looping on an uninitialized local.
  int entryCount = 0;
  int remaining = ::GetObject(m_hObject, 4, &entryCount) != 0 ? entryCount : 0;

  CPalette* oldPalette = dc->SelectPalette(this, bForceBackground);
  ::RealizePalette(dc->m_hDC);

  int prevBottom = 0;
  for (int row = 0; row < 0x10 && remaining != 0; row++) {
    int bottom = bounds->bottom * (row + 1) / 16 + 1;
    int prevRight = 0;
    for (int col = 0; col < 0x10 && remaining != 0; col++) {
      int right = bounds->right * (col + 1) / 16 + 1;
      CBrush brush(PALETTEINDEX(row * 16 + col));
      CBrush* oldBrush = dc->SelectObject(&brush);
      ::Rectangle(dc->m_hDC, prevRight - 1, prevBottom - 1, right, bottom);
      dc->SelectObject(oldBrush);
      remaining--;
      prevRight = right;
    }
    prevBottom = bottom;
  }

  dc->SelectPalette(oldPalette, FALSE);
}

// FUNCTION: IMPERIALISM 0x0047e930
UINT CDibPal::SelectIntoDcAndRealize(CDC* dc, BOOL background) {
  // LIBRARY: CDC::SelectPalette (0x00612a78)
  dc->SelectPalette(this, background);
  return dc->RealizePalette();
}

// FUNCTION: IMPERIALISM 0x0047e960
int CDibPal::LoadPaletteFile(LPCSTR fileName) {
  CString path;
  if (fileName != NULL && fileName[0] != '\0') {
    path = fileName;
  } else {
    CFileDialog dialog(TRUE, NULL, NULL, OFN_HIDEREADONLY | OFN_FILEMUSTEXIST,
                       "Palette files (*.PAL)|*.PAL|All files (*.*)|*.*||", NULL);
    if (dialog.DoModal() != IDOK) {
      return 0;
    }
    path = dialog.GetPathName();
  }

  CFile file;
  if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite)) {
    AfxMessageBox("Failed to open file", MB_OK, 0);
    return 0;
  }

  MMIOINFO info;
  memset(&info, 0, sizeof(info));
  info.adwInfo[0] = file.m_hFile;
  HMMIO mmioHandle = mmioOpenA(NULL, &info, MMIO_ALLOCBUF | MMIO_READ);
  int loaded = mmioHandle == NULL ? 0 : LoadPalette(mmioHandle);
  if (mmioHandle != NULL) {
    mmioClose(mmioHandle, MMIO_FHOPEN);
  }
  file.Close();

  if (loaded == 0) {
    AfxMessageBox("Failed to load file", MB_OK, 0);
  }
  return loaded;
}

// FUNCTION: IMPERIALISM 0x0047ec70
int CDibPal::LoadPalette(CFile* file) {
  MMIOINFO info;
  memset(&info, 0, sizeof(info));
  info.adwInfo[0] = file->m_hFile;
  HMMIO mmioHandle = mmioOpenA(NULL, &info, MMIO_ALLOCBUF | MMIO_READ);
  if (mmioHandle == NULL) {
    return 0;
  }
  int loaded = LoadPalette(mmioHandle);
  mmioClose(mmioHandle, MMIO_FHOPEN);
  return loaded;
}

// FUNCTION: IMPERIALISM 0x0047ecf0
int CDibPal::LoadPalette(UINT fileHandle) {
  MMIOINFO info;
  memset(&info, 0, sizeof(info));
  info.adwInfo[0] = fileHandle;
  HMMIO mmioHandle = mmioOpenA(NULL, &info, MMIO_ALLOCBUF | MMIO_READ);
  if (mmioHandle == NULL) {
    return 0;
  }
  int loaded = LoadPalette(mmioHandle);
  mmioClose(mmioHandle, MMIO_FHOPEN);
  return loaded;
}

// FUNCTION: IMPERIALISM 0x0047ed70
int CDibPal::LoadPalette(HMMIO mmioHandle) {
  MMCKINFO riffChunk;
  riffChunk.fccType = mmioFOURCC('P', 'A', 'L', ' ');
  if (mmioDescend(mmioHandle, &riffChunk, NULL, MMIO_FINDRIFF) != MMSYSERR_NOERROR) {
    return 0;
  }

  MMCKINFO dataChunk;
  dataChunk.ckid = mmioFOURCC('d', 'a', 't', 'a');
  if (mmioDescend(mmioHandle, &dataChunk, &riffChunk, MMIO_FINDCHUNK) != MMSYSERR_NOERROR) {
    return 0;
  }

  unsigned char* paletteBytes = new unsigned char[dataChunk.cksize];
  LOGPALETTE* palette = static_cast<LOGPALETTE*>(static_cast<void*>(paletteBytes));
  if (palette == NULL) {
    return 0;
  }
  if (mmioRead(mmioHandle, static_cast<HPSTR>(static_cast<void*>(palette)), dataChunk.cksize) !=
      static_cast<LONG>(dataChunk.cksize)) {
    delete[] paletteBytes;
    return 0;
  }
  if (palette->palVersion != 0x300 || palette->palNumEntries == 0) {
    delete[] paletteBytes;
    return 0;
  }
  return Attach(::CreatePalette(palette));
}

// FUNCTION: IMPERIALISM 0x0047eea0
int CDibPal::SavePalette(CFile* file) {
  MMIOINFO info;
  memset(&info, 0, sizeof(info));
  info.adwInfo[0] = file->m_hFile;
  HMMIO mmioHandle = mmioOpenA(NULL, &info, MMIO_ALLOCBUF | MMIO_CREATE | MMIO_WRITE);
  if (mmioHandle == NULL) {
    return 0;
  }
  int saved = SavePalette(mmioHandle);
  mmioClose(mmioHandle, MMIO_FHOPEN);
  return saved;
}

// FUNCTION: IMPERIALISM 0x0047ef20
int CDibPal::SavePalette(UINT fileHandle) {
  MMIOINFO info;
  memset(&info, 0, sizeof(info));
  info.adwInfo[0] = fileHandle;
  HMMIO mmioHandle = mmioOpenA(NULL, &info, MMIO_ALLOCBUF | MMIO_CREATE | MMIO_WRITE);
  if (mmioHandle == NULL) {
    return 0;
  }
  int saved = SavePalette(mmioHandle);
  mmioClose(mmioHandle, MMIO_FHOPEN);
  return saved;
}

// FUNCTION: IMPERIALISM 0x0047efa0
int CDibPal::SavePalette(HMMIO mmioHandle) {
  MMCKINFO riffChunk;
  memset(&riffChunk, 0, sizeof(riffChunk));
  riffChunk.fccType = mmioFOURCC('P', 'A', 'L', ' ');
  if (mmioCreateChunk(mmioHandle, &riffChunk, MMIO_CREATERIFF) != MMSYSERR_NOERROR) {
    return 0;
  }

  UINT entryCount = 0;
  HPALETTE paletteHandle = static_cast<HPALETTE>(*this);
  if (::GetObjectA(paletteHandle, sizeof(entryCount), &entryCount) == 0) {
    entryCount = 0;
  }
  DWORD byteCount = entryCount * sizeof(PALETTEENTRY) + sizeof(WORD) * 2;
  unsigned char* paletteBytes = new unsigned char[byteCount];
  LOGPALETTE* palette = static_cast<LOGPALETTE*>(static_cast<void*>(paletteBytes));
  palette->palVersion = 0x300;
  palette->palNumEntries = static_cast<WORD>(entryCount);
  ::GetPaletteEntries(paletteHandle, 0, entryCount, palette->palPalEntry);

  MMCKINFO dataChunk;
  memset(&dataChunk, 0, sizeof(dataChunk));
  dataChunk.ckid = mmioFOURCC('d', 'a', 't', 'a');
  dataChunk.cksize = byteCount;
  if (mmioCreateChunk(mmioHandle, &dataChunk, 0) != MMSYSERR_NOERROR) {
    return 0;
  }
  if (mmioWrite(mmioHandle, static_cast<const char*>(static_cast<const void*>(palette)),
                byteCount) != static_cast<LONG>(byteCount)) {
    delete[] paletteBytes;
    return 0;
  }

  delete[] paletteBytes;
  mmioAscend(mmioHandle, &dataChunk, 0);
  mmioAscend(mmioHandle, &riffChunk, 0);
  return 1;
}
