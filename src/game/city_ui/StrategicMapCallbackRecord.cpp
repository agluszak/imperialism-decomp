#include "game/city_ui/StrategicMapCallbackRecord.h"

#include <cstdlib>
#include <cstring>

#include "game/gfx/CDib.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00430750
StrategicMapCallbackRecord::~StrategicMapCallbackRecord() {}

// TEMPLATE: IMPERIALISM 0x004307a0
// ?Add@?$stretch@E@@UAEPAEE@Z

// TEMPLATE: IMPERIALISM 0x00430830
// ?Add@?$stretch@H@@UAEPAHH@Z

// FUNCTION: IMPERIALISM 0x004d4b90
StrategicMapCallbackRecord::StrategicMapCallbackRecord()
    : opcodeAppendCursor10(0), opcodeAlignmentOffset14(0), hadTrailingPadding18(0),
      destinationRowStride2c(0) {}

// TEMPLATE: IMPERIALISM 0x004d4dd0
// ?OverStretch@?$stretch@E@@QAEXI@Z

// TEMPLATE: IMPERIALISM 0x004d4e40
// stretch::operator[]

// TEMPLATE: IMPERIALISM 0x004d4ed0
// stretch::OverStretch

// TEMPLATE: IMPERIALISM 0x004d4f50
// stretch::operator[]

// Patches the generated packed-color write program and applies it to the destination pixels.
// FUNCTION: IMPERIALISM 0x004d4bf0
void StrategicMapCallbackRecord::AppendPackedColorDword(unsigned char* destinationPixels,
                                                        int packedColor) {
  const unsigned int packed = (packedColor & 0xff) * 0x01010101u;

  const int cursor = packedColorCursor1c[0];
  opcodeBytes00[cursor] = static_cast<unsigned char>(packed);
  opcodeBytes00[cursor + 1] = static_cast<unsigned char>(packed >> 8);
  opcodeBytes00[cursor + 2] = static_cast<unsigned char>(packed >> 16);
  opcodeBytes00[cursor + 3] = static_cast<unsigned char>(packed >> 24);

  opcodeBytes00[opcodeAlignmentOffset14];
  ApplyPackedColorToPixelBuffer(destinationPixels);
}

void StrategicMapCallbackRecord::ApplyPackedColorToPixelBuffer(unsigned char* destinationPixels) {
  unsigned char* instruction = opcodeBytes00.Data() + opcodeAlignmentOffset14;
  unsigned char* end = opcodeBytes00.Data() + opcodeBytes00.Count();
  unsigned char* destinationBase = destinationPixels;
  unsigned int packedColor = 0;

  while (instruction < end) {
    unsigned char opcode = *instruction++;
    if (opcode == 0xc3) {
      return;
    }
    if (opcode == 0xb9 && end - instruction >= 4) {
      packedColor = static_cast<unsigned int>(instruction[0]) |
                    (static_cast<unsigned int>(instruction[1]) << 8) |
                    (static_cast<unsigned int>(instruction[2]) << 16) |
                    (static_cast<unsigned int>(instruction[3]) << 24);
      instruction += 4;
      continue;
    }
    if (opcode == 0x05 && end - instruction >= 4) {
      unsigned int advance = static_cast<unsigned int>(instruction[0]) |
                             (static_cast<unsigned int>(instruction[1]) << 8) |
                             (static_cast<unsigned int>(instruction[2]) << 16) |
                             (static_cast<unsigned int>(instruction[3]) << 24);
      destinationBase += advance;
      instruction += 4;
      continue;
    }
    if (opcode == 0x89 && end - instruction >= 2 && instruction[0] == 0x48) {
      signed char displacement = static_cast<signed char>(instruction[1]);
      destinationBase[displacement] = static_cast<unsigned char>(packedColor);
      destinationBase[displacement + 1] = static_cast<unsigned char>(packedColor >> 8);
      destinationBase[displacement + 2] = static_cast<unsigned char>(packedColor >> 16);
      destinationBase[displacement + 3] = static_cast<unsigned char>(packedColor >> 24);
      instruction += 2;
      continue;
    }
    if (opcode == 0x66 && end - instruction >= 3 && instruction[0] == 0x89 &&
        instruction[1] == 0x48) {
      signed char displacement = static_cast<signed char>(instruction[2]);
      destinationBase[displacement] = static_cast<unsigned char>(packedColor);
      destinationBase[displacement + 1] = static_cast<unsigned char>(packedColor >> 8);
      instruction += 3;
      continue;
    }
    if (opcode == 0x88 && end - instruction >= 2 && instruction[0] == 0x48) {
      signed char displacement = static_cast<signed char>(instruction[1]);
      destinationBase[displacement] = static_cast<unsigned char>(packedColor);
      instruction += 2;
      continue;
    }
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004d4ff0
void StrategicMapCallbackRecord::ApplyBitmapMaskToPixelBuffer(unsigned char* destinationPixels) {
  unsigned char* instruction = opcodeBytes00.Data();
  unsigned char* end = instruction + opcodeBytes00.Count();
  unsigned char* destinationBase = destinationPixels;

  while (instruction < end) {
    unsigned char opcode = *instruction++;
    if (opcode == 0xc3) {
      return;
    }
    if (opcode == 0x05 && end - instruction >= 4) {
      unsigned int advance = static_cast<unsigned int>(instruction[0]) |
                             (static_cast<unsigned int>(instruction[1]) << 8) |
                             (static_cast<unsigned int>(instruction[2]) << 16) |
                             (static_cast<unsigned int>(instruction[3]) << 24);
      destinationBase += advance;
      instruction += 4;
      continue;
    }
    if (opcode == 0xc6 && end - instruction >= 3 && instruction[0] == 0x40) {
      signed char displacement = static_cast<signed char>(instruction[1]);
      destinationBase[displacement] = instruction[2];
      instruction += 3;
      continue;
    }
    if (opcode == 0x66 && end - instruction >= 5 && instruction[0] == 0xc7 &&
        instruction[1] == 0x40) {
      signed char displacement = static_cast<signed char>(instruction[2]);
      destinationBase[displacement] = instruction[3];
      destinationBase[displacement + 1] = instruction[4];
      instruction += 5;
      continue;
    }
    if (opcode == 0xc7 && end - instruction >= 6 && instruction[0] == 0x40) {
      signed char displacement = static_cast<signed char>(instruction[1]);
      memcpy(destinationBase + displacement, instruction + 2, 4);
      instruction += 6;
      continue;
    }
    return;
  }
}

// FUNCTION: IMPERIALISM 0x004d5090
void StrategicMapCallbackRecord::BuildBitmapMaskOpcodeBufferFromResourceRows(
    int resourceId, short width, short height, int destinationRowStride,
    unsigned char transparentPixel) {
  destinationRowStride2c = destinationRowStride;

  CDib* dib = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(
      static_cast<unsigned short>(resourceId));
  unsigned char* row = static_cast<unsigned char*>(dib->m_dibBits);
  int sourceRowStride = (dib->m_pInfoHeader->bmiHeader.biWidth + 3) & 0xfffffffc;
  int generatedBaseOffset = 0;

  opcodeAppendCursor10 = 0;
  opcodeBytes00.RemoveAll();
  opcodeAlignmentOffset14 = 0;
  hadTrailingPadding18 = 0;

  int y = 0;
  while (y < height) {
    int x = 0;
    while (x < width) {
      unsigned char pixel = row[x];
      if (pixel != transparentPixel) {
        int destinationOffset = y * destinationRowStride + x;
        int displacement = destinationOffset - generatedBaseOffset;
        if (displacement > 0x7f) {
          int advance = displacement;
          AppendOpcodeByte(0x05);
          AppendOpcodeByte(advance);
          AppendOpcodeByte(advance >> 8);
          AppendOpcodeByte(advance >> 16);
          AppendOpcodeByte(advance >> 24);
          generatedBaseOffset = destinationOffset;
          displacement = 0;
        }
        AppendOpcodeByte(0xc6);
        AppendOpcodeByte(0x40);
        AppendOpcodeByte(displacement);
        AppendOpcodeByte(pixel);
      }
      x = x + 1;
    }
    row = row + sourceRowStride;
    y = y + 1;
  }

  g_pModuleLibraryCacheState->ReleaseRecordById(static_cast<short>(resourceId));
  AppendOpcodeByte(0xc3);
}

// FUNCTION: IMPERIALISM 0x004d5580
StrategicMapCallbackRecord* StrategicMapCallbackRecord::AppendOpcodeByte(int value) {
  unsigned int index = static_cast<unsigned int>(opcodeAppendCursor10);
  opcodeAppendCursor10 = static_cast<int>(index) + 1;
  opcodeBytes00[index] = static_cast<unsigned char>(value);
  return this;
}

// FUNCTION: IMPERIALISM 0x004d5610
void StrategicMapCallbackRecord::AppendOpcodeBytePair(int value) {
  AppendOpcodeByte((value >> 8) & 0xff);
  AppendOpcodeByte(value & 0xff);
}

// FUNCTION: IMPERIALISM 0x004d5720
void StrategicMapCallbackRecord::FinalizeOpcodeBufferAlignment() {
  unsigned char* alignmentProbe = &opcodeBytes00[opcodeAlignmentOffset14];
  opcodeAlignmentOffset14 = reinterpret_cast<unsigned int>(alignmentProbe) & 3;
  if (opcodeAlignmentOffset14 != 0) {
    opcodeBytes00.Add(0);
    opcodeBytes00.Add(0);
    opcodeBytes00.Add(0);
    opcodeBytes00.Compact();
    alignmentProbe = &opcodeBytes00[opcodeAlignmentOffset14];
    opcodeAlignmentOffset14 = reinterpret_cast<unsigned int>(alignmentProbe) & 3;
  }

  if (opcodeAlignmentOffset14 != 0) {
    int payloadByteCount = opcodeBytes00.GetSize() - 3;
    for (int sourceIndex = 0; sourceIndex < payloadByteCount; ++sourceIndex) {
      unsigned char value = opcodeBytes00[sourceIndex];
      opcodeBytes00[sourceIndex + opcodeAlignmentOffset14] = value;
    }
    hadTrailingPadding18 = 1;
  }
}

// TEMPLATE: IMPERIALISM 0x004d5970
// stretch::SetCapacity

// Edge test against a QuickDraw hit region: true when (x, y) is inside the region and,
// with neighbour checking enabled, at least one of its four orthogonal neighbours falls
// outside it -- i.e. the point sits on the region's boundary. With checkNeighbours off it
// degenerates to a plain containment test. Each probe uses its own point slot, matching
// the original's frame.
// FUNCTION: IMPERIALISM 0x004d59a0
int __cdecl IsPointOnHitRegionEdge(int x, int y, RgnHandle region, char checkNeighbours) {
  CPoint centre;
  centre.x = x;
  centre.y = y;
  if (PtInRgn(&centre, region) == 0) {
    return 0;
  }
  if (checkNeighbours == '\0') {
    return 1;
  }

  CPoint toRight;
  toRight.x = x + 1;
  toRight.y = y;
  if (PtInRgn(&toRight, region) == 0) {
    return 1;
  }

  CPoint toLeft;
  toLeft.x = x - 1;
  toLeft.y = y;
  if (PtInRgn(&toLeft, region) == 0) {
    return 1;
  }

  CPoint below;
  below.x = x;
  below.y = y + 1;
  if (PtInRgn(&below, region) == 0) {
    return 1;
  }

  CPoint above;
  above.x = x;
  above.y = y - 1;
  if (PtInRgn(&above, region) == 0) {
    return 1;
  }

  return 0;
}

// FUNCTION: IMPERIALISM 0x004d5cf0
void StrategicMapCallbackRecord::StreamOverlayHitMaskToSurfaceDib(DiplomacyMaskBufferRun* run,
                                                                  TQuickDrawSurfaceContext* surface,
                                                                  int outlineOnly) {
  int height = surface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
  if (height <= 0) {
    height = -height;
  }
  BuildDiplomacyOverlayHitMaskOpcodeStream(
      run, surface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biWidth, outlineOnly, height);
}

// Builds the compact x86 write stream used by AppendPackedColorDword. Each selected mask
// pixel becomes a byte/word/dword write; long gaps advance the destination base explicitly.
// FUNCTION: IMPERIALISM 0x004d5d30
void StrategicMapCallbackRecord::BuildDiplomacyOverlayHitMaskOpcodeStream(
    DiplomacyMaskBufferRun* run, int destinationRowStride, int outlineOnly, int surfaceHeight) {
  opcodeBytes00.SetCapacity(0x400);
  destinationRowStride2c = destinationRowStride;

  AppendOpcodeByte(0xb9);
  packedColorCursor1c.Add(opcodeAppendCursor10);
  AppendOpcodeByte(0xcd);
  AppendOpcodeByte(0xcd);
  AppendOpcodeByte(0xcd);
  AppendOpcodeByte(0xcd);

  int generatedBaseOffset = 0;
  int destinationRow = surfaceHeight - run->boundsAt04.bottom;
  for (int y = run->boundsAt04.bottom - 1; y >= run->boundsAt04.top; --y, ++destinationRow) {
    int x = run->boundsAt04.left;
    while (x < run->boundsAt04.right) {
      bool emitPixel = run->IsMaskPixelSet(x, y);
      if (emitPixel && outlineOnly != 0 && run->IsMaskPixelSet(x + 1, y) &&
          run->IsMaskPixelSet(x - 1, y) && run->IsMaskPixelSet(x, y + 1) &&
          run->IsMaskPixelSet(x, y - 1)) {
        emitPixel = false;
      }

      if (!emitPixel) {
        ++x;
        continue;
      }

      int displacement = destinationRow * destinationRowStride + x - generatedBaseOffset;
      while (displacement > 0x7f) {
        int advance = displacement + 0x80;
        generatedBaseOffset += advance;
        displacement -= advance;
        AppendOpcodeByte(0x05);
        AppendOpcodeByte(advance);
        AppendOpcodeByte(advance >> 8);
        AppendOpcodeByte(advance >> 16);
        AppendOpcodeByte(advance >> 24);
      }

      int contiguousPixelCount = 1;
      while (contiguousPixelCount < 4) {
        int nextX = x + contiguousPixelCount;
        bool emitNextPixel = run->IsMaskPixelSet(nextX, y);
        if (emitNextPixel && outlineOnly != 0 && run->IsMaskPixelSet(nextX + 1, y) &&
            run->IsMaskPixelSet(nextX - 1, y) && run->IsMaskPixelSet(nextX, y + 1) &&
            run->IsMaskPixelSet(nextX, y - 1)) {
          emitNextPixel = false;
        }
        if (!emitNextPixel) {
          break;
        }
        ++contiguousPixelCount;
      }

      if (contiguousPixelCount == 4) {
        AppendOpcodeByte(0x89);
        AppendOpcodeByte(0x48);
        AppendOpcodeByte(displacement);
      } else if (contiguousPixelCount >= 2) {
        AppendOpcodeByte(0x66);
        AppendOpcodeByte(0x89);
        AppendOpcodeByte(0x48);
        AppendOpcodeByte(displacement);
        contiguousPixelCount = 2;
      } else {
        AppendOpcodeByte(0x88);
        AppendOpcodeByte(0x48);
        AppendOpcodeByte(displacement);
      }
      x += contiguousPixelCount;
    }
  }

  AppendOpcodeByte(0xc3);
  opcodeBytes00.Compact();
  FinalizeOpcodeBufferAlignment();
  unsigned char* alignedEntry = &opcodeBytes00[opcodeAlignmentOffset14];
  if ((reinterpret_cast<unsigned int>(alignedEntry) & 3) != 0) {
    FinalizeOpcodeBufferAlignment();
  }
}

// TEMPLATE: IMPERIALISM 0x004d62d0
// stretch::Compact
