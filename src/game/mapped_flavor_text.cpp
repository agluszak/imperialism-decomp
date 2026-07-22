#include "game/mapped_flavor_text.h"

#include "game/CString.h"
#include "game/global_data_tables.h"
#include "game/TLanguageMgr.h"
#include "game/TSimMgr.h"

#include <stdlib.h>
#include <string.h>

// FUNCTION: IMPERIALISM 0x0056d5c0
CString BuildSharedStringFromMappedFlavorTextIndex(short variantIndex) {
  CString result;
  GenerateMappedFlavorTextUntilValidationPasses(&result, variantIndex);
  return result;
}

// FUNCTION: IMPERIALISM 0x0057fef0
void scanBracketExpressions(TSimMgr* ctx, CString* out, const char* input, ...) {
  (void)ctx;
  CString* result = out;
  const char* const* args = &input + 1; // first variadic argument
  *result = CString(g_szEmptyString);

  const char* p = input;
  char ch = *input;
  unsigned int idx = 0;
  while (ch != '\0') {
    ch = p[idx];
    unsigned int scan = idx;
    if (ch == '[') {
      for (;;) {
        idx = scan;
        if (ch == '\0') {
          break;
        }
        ch = p[scan + 1];
        idx = scan + 1;
        if (ch >= '0' && ch <= '9') {
          char letter = p[idx + 1];
          if (letter < 'a' || letter > 'z') {
            *result += args[ch - '0'];
          } else {
            *result += g_pLanguageMgr->Localize(args[ch - '0'], letter);
          }
          break;
        }
        scan = idx;
        if (ch == ']') {
          break;
        }
      }
      ch = p[idx];
      while (ch != ']' && ch != '\0') {
        idx = idx + 1;
        ch = p[idx];
      }
    } else {
      *result += ch;
    }
    ch = p[idx + 1];
    idx = idx + 1;
  }
}

// FUNCTION: IMPERIALISM 0x00580060
void __cdecl BuildUiMessageTextFromBracketTemplate(TSimMgr* sim, CString* out, int groupA,
                                                   int indexA, int groupB, int indexB) {
  // groupB/indexB are read through the (&groupA)[] pair table below when the template
  // contains "[1]"; they are never referenced by name.
  (void)groupB;
  (void)indexB;
  *out = CString(g_szEmptyString);

  CString text;
  sim->GetString(static_cast<short>(groupA), static_cast<short>(indexA), &text);

  for (int i = 0; i < text.GetLength(); i++) {
    char ch = text[i];
    if (ch == '[') {
      for (;;) {
        if (ch == '\0') {
          break;
        }
        ch = text[i + 1];
        i = i + 1;
        if (ch >= '0' && ch <= '9') {
          CString expansion;
          sim->GetString(static_cast<short>((&groupA)[(ch - '0') * 2]),
                         static_cast<short>((&indexA)[(ch - '0') * 2]), &expansion);
          char letter = text[i + 1];
          if (letter < 'a' || letter > 'z') {
            *out += expansion;
          } else {
            *out += g_pLanguageMgr->Localize(expansion, letter);
          }
          break;
        }
        if (ch == ']') {
          break;
        }
      }
      if (text[i] != ']') {
        while (i < text.GetLength()) {
          char next = text[i + 1];
          i = i + 1;
          if (next == ']') {
            break;
          }
        }
      }
    } else {
      *out += ch;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00580280
char* __cdecl AppendInterNationEventSummaryTextEntry_Impl(TSimMgr* sim, const char* templateText,
                                                          const char* token1, const char* token2,
                                                          const char* token3, const char* token4) {
  (void)sim;
  (void)token1;
  (void)token2;
  (void)token3;
  (void)token4;
  TResizableByteSink sink;
  TResizableByteSink* out = &sink;
  // Tokens are 1-indexed relative to the template parameter (bracket digit '1' selects
  // token1), matching scanBracketExpressions' variadic idiom.
  const char* const* args = &templateText;
  int idx = 0;
  char ch;
  if (*templateText != 0) {
    do {
      ch = templateText[idx];
      if (ch == '[') {
        while (ch != 0) {
          ch = templateText[idx + 1];
          idx++;
          if (ch >= '0' && ch <= '9') {
            char letter = templateText[idx + 1];
            if (letter < 'a' || letter > 'z') {
              const char* token = args[templateText[idx] - '0'];
              while (*token != 0) {
                out->AppendByteToResizableBuffer(*token);
                token++;
              }
            } else {
              CString localized = g_pLanguageMgr->Localize(args[templateText[idx] - '0'], letter);
              const char* p = localized;
              while (*p != 0) {
                out->AppendByteToResizableBuffer(*p);
                p++;
              }
            }
            break;
          }
          if (ch == ']') {
            break;
          }
        }
        while (true) {
          ch = templateText[idx];
          if (ch == ']' || ch == 0) {
            break;
          }
          ch = templateText[idx + 1];
          idx++;
          if (ch == ']') {
            break;
          }
        }
      } else {
        out->AppendByteToResizableBuffer(ch);
      }
      ch = templateText[idx + 1];
      idx++;
    } while (ch != 0);
  }
  out->AppendByteToResizableBuffer(0);
  return sink.buffer4;
}

// FUNCTION: IMPERIALISM 0x00580460
void TResizableByteSink::AppendByteToResizableBuffer(char byteValue) {
  unsigned int pos = lengthC;
  if (pos >= static_cast<unsigned int>(capacity8)) {
    int grownLength = pos + 1;
    unsigned int doubled = grownLength * 2;
    int clampedCapacity = doubled;
    if (doubled > 0x7fffffff) {
      clampedCapacity = 0x7fffffff;
    }
    char* grown = static_cast<char*>(realloc(buffer4, doubled));
    if (grown == 0) {
      buffer4 = static_cast<char*>(realloc(buffer4, grownLength));
      capacity8 = grownLength;
    } else {
      buffer4 = grown;
      capacity8 = clampedCapacity;
    }
  }
  if (pos >= static_cast<unsigned int>(lengthC)) {
    lengthC = pos + 1;
  }
  buffer4[pos] = byteValue;
}

// The generated flavor text is rejected (regenerate) if it contains any character from
// this banned set list; each entry is a FindOneOf char-set probe against the result.
// FUNCTION: IMPERIALISM 0x005d4240
bool ShouldRetryMappedFlavorTextGeneration(CString* dest) {
  const char* bannedSets[34] = {s_mcflavor_0069b640, s_mcflavor_0069b638,
                                s_mcflavor_0069b630, s_mcflavor_0069b628,
                                s_mcflavor_0069b624, s_mcflavor_0069b61c,
                                s_mcflavor_0069b614, s_mcflavor_0069b60c,
                                s_mcflavor_0069b604, s_mcflavor_0069b5fc,
                                s_mcflavor_0069b5f4, s_mcflavor_0069b5ec,
                                s_mcflavor_0069b5e4, s_mcflavor_0069b5dc,
                                s_mcflavor_0069b5d4, s_mcflavor_0069b5cc,
                                s_mcflavor_0069b5c4, s_mcflavor_0069b5c0,
                                s_mcflavor_0069b5b8, s_mcflavor_0069b5ac,
                                s_mcflavor_0069b5a4, s_mcflavor_0069b59c,
                                s_mcflavor_0069b598, s_mcflavor_0069b590,
                                s_mcflavor_0069b584, s_mcflavor_0069b57c,
                                s_mcflavor_0069b56c, s_mcflavor_0069b564,
                                s_mcflavor_0069b55c, s_mcflavor_0069b554,
                                s_mcflavor_0069b54c, s_mcflavor_0069b544,
                                s_mcflavor_0069b53c, 0};
  for (const char* const* set = bannedSets; *set != 0; set = set + 1) {
    if (dest->FindOneOf(*set) > -1) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x005d4410
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot) {
  if (g_pSimMgr->useLocalizedNameTables68 == '\0') {
    short variantIndex = g_MappedFlavorTextNationVariantTable_0066EF30[tableSlot].variantIndex;
    GenerateMappedFlavorTextUntilValidationPasses(dest, variantIndex);
    if (g_bMultiplayerScenarioSetupActive == '\0') {
      while (dest->GetLength() > 0xc) {
        GenerateMappedFlavorTextUntilValidationPasses(dest, variantIndex);
      }
    }
    return;
  }

  CString localizedName;
  g_pSimMgr->GetString(0x2715, tableSlot, &localizedName);
  *dest = localizedName;
}

// FUNCTION: IMPERIALISM 0x005d4550
void __cdecl AssignNextProvinceNameForNationSlot(CString* dest, short nationSlot) {
  if (nationSlot == -1) {
    memset(g_anProvinceNameOrdinalByNationSlot_006a5af0, 0,
           sizeof(g_anProvinceNameOrdinalByNationSlot_006a5af0));
    return;
  }

  if (g_pSimMgr->useLocalizedNameTables68 != '\0') {
    CString provinceName;
    short ordinal = ++g_anProvinceNameOrdinalByNationSlot_006a5af0[nationSlot];
    g_pSimMgr->GetString(static_cast<short>(nationSlot + 8000), ordinal, &provinceName);
    *dest = provinceName;
    return;
  }

  GenerateMappedFlavorTextUntilValidationPasses(
      dest, g_MappedFlavorTextNationVariantTable_0066EF30[nationSlot].variantIndex);
}

// FUNCTION: IMPERIALISM 0x005d46b0
void GenerateMappedFlavorTextByTableSlot(CString* dest, short tableSlot) {
  GenerateMappedFlavorTextUntilValidationPasses(
      dest, g_MappedFlavorTextNationVariantTable_0066EF30[tableSlot].variantIndex);
}

// FUNCTION: IMPERIALISM 0x005d46e0
void GenerateMappedFlavorTextByCurrentContextNation(CString* dest) {
  short nationIndex = (g_pLanguageMgr == 0) ? 2 : static_cast<short>(g_pLanguageMgr->field30);
  GenerateMappedFlavorTextUntilValidationPasses(
      dest, g_MappedFlavorTextNationVariantTable_0066EF30[nationIndex].variantIndex);
}

// FUNCTION: IMPERIALISM 0x005d4720
void GenerateMappedFlavorTextUntilValidationPasses(CString* dest, short variantIndex) {
  bool retry;
  do {
    switch (static_cast<int>(variantIndex) % 0x12) {
    case 0:
      AppendRandomMapContextStatusSuffixWithProbability(dest);
      break;
    case 1:
      GenerateMappedFlavorTextVariantC_005cf1b0(dest);
      break;
    case 2:
      GenerateMappedFlavorTextVariantE_005ccce0(dest);
      break;
    case 3:
      GenerateMappedFlavorTextVariantA_005d13d0(dest);
      break;
    case 4:
      GenerateMappedFlavorTextVariantB_005cfc40(dest);
      break;
    case 5:
      BuildMapContextStatusStringVariantH(dest);
      break;
    case 6:
      BuildMapContextStatusStringVariantK(dest);
      break;
    case 7:
      BuildMapContextStatusStringVariantB(dest);
      break;
    case 8:
      GenerateMappedFlavorTextVariantD_005d33a0(dest);
      break;
    case 9:
      BuildMapContextStatusStringVariantI(dest);
      break;
    case 10:
      BuildMapContextStatusStringVariantG(dest);
      break;
    case 0xb:
      BuildMapContextStatusStringVariantF(dest);
      break;
    case 0xc:
      BuildMapContextStatusStringVariantJ(dest);
      break;
    case 0xd:
      BuildMapContextStatusStringVariantC(dest);
      break;
    case 0xe:
      BuildMapContextStatusStringVariantE(dest);
      break;
    case 0xf:
      BuildMapContextStatusStringVariantL(dest);
      break;
    case 0x10:
      BuildMapContextStatusStringVariantD(dest);
      break;
    case 0x11:
      BuildMapContextStatusStringVariantA(dest);
      break;
    }
    retry = ShouldRetryMappedFlavorTextGeneration(dest);
  } while (retry != 0);
}

// FUNCTION: IMPERIALISM 0x005d4890
bool IsMappedShortcutKeyPressed(short nShortcutCode) {
  if (nShortcutCode == 2) {
    nShortcutCode = 0x44;
  }
  return (static_cast<unsigned int>(GetAsyncKeyState(nShortcutCode)) >> 0xf) & 1;
}
