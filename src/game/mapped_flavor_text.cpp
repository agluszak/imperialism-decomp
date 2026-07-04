#include "game/mapped_flavor_text.h"

#include "game/CString.h"
#include "game/global_data_tables.h"
#include "game/TLanguageMgr.h"
#include "game/TSimMgr.h"

extern "C" char DAT_006a43f0;

undefined4 AppendRandomMapContextStatusSuffixWithProbability(void);
undefined4 GenerateMappedFlavorTextVariantE_005ccce0(void);
undefined4 GenerateMappedFlavorTextVariantA_005d13d0(void);
undefined4 GenerateMappedFlavorTextVariantB_005cfc40(void);
undefined4 GenerateMappedFlavorTextVariantD_005d33a0(void);
undefined4 ShouldRetryMappedFlavorTextGeneration(void);

// FUNCTION: IMPERIALISM 0x0057fef0
void scanBracketExpressions(void* ctx, void* out, const char* input, ...) {
  (void)ctx;
  CString* result = static_cast<CString*>(out);
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
            *result +=
                g_pLanguageMgr->BuildMappedSharedStringFromByteStateTable(args[ch - '0'], letter);
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

// FUNCTION: IMPERIALISM 0x005d4410
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot) {
  if (g_pLocalizationTable->useLocalizedNameTables68 == '\0') {
    short variantIndex = g_MappedFlavorTextNationVariantTable_0066EF30[tableSlot].variantIndex;
    GenerateMappedFlavorTextUntilValidationPasses(dest, variantIndex);
    if (DAT_006a43f0 == '\0') {
      while (dest->GetLength() > 0xc) {
        GenerateMappedFlavorTextUntilValidationPasses(dest, variantIndex);
      }
    }
    return;
  }

  CString localizedName;
  g_pLocalizationTable->GetString(0x2715, tableSlot, &localizedName);
  *dest = localizedName;
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
  char retry;
  do {
    switch (static_cast<int>(variantIndex) % 0x12) {
    case 0:
      reinterpret_cast<void(__cdecl*)(CString*)>(AppendRandomMapContextStatusSuffixWithProbability)(
          dest);
      break;
    case 1:
      GenerateMappedFlavorTextVariantC_005cf1b0(dest);
      break;
    case 2:
      reinterpret_cast<void(__cdecl*)(CString*)>(GenerateMappedFlavorTextVariantE_005ccce0)(dest);
      break;
    case 3:
      reinterpret_cast<void(__cdecl*)(CString*)>(GenerateMappedFlavorTextVariantA_005d13d0)(dest);
      break;
    case 4:
      reinterpret_cast<void(__cdecl*)(CString*)>(GenerateMappedFlavorTextVariantB_005cfc40)(dest);
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
      reinterpret_cast<void(__cdecl*)(CString*)>(GenerateMappedFlavorTextVariantD_005d33a0)(dest);
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
    retry = reinterpret_cast<char(__cdecl*)(CString*)>(ShouldRetryMappedFlavorTextGeneration)(dest);
  } while (retry != 0);
}
