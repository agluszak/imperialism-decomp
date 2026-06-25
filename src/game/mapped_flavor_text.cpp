#include "game/mapped_flavor_text.h"

#include "game/CString.h"
#include "game/diplomacy_globals.h"
#include "game/TSimMgr.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

struct MappedFlavorTextNationVariantEntry {
  short variantIndex;
  short pad;
};

extern "C" MappedFlavorTextNationVariantEntry g_MappedFlavorTextNationVariantTable_0066EF30[32];
extern "C" char DAT_006a43f0;

undefined4 AppendRandomMapContextStatusSuffixWithProbability(void);
undefined4 GenerateMappedFlavorTextVariantC_005cf1b0(void);
undefined4 GenerateMappedFlavorTextVariantE_005ccce0(void);
undefined4 GenerateMappedFlavorTextVariantA_005d13d0(void);
undefined4 GenerateMappedFlavorTextVariantB_005cfc40(void);
undefined4 BuildMapContextStatusStringVariantH(void);
undefined4 BuildMapContextStatusStringVariantK(void);
undefined4 BuildMapContextStatusStringVariantB(void);
undefined4 GenerateMappedFlavorTextVariantD_005d33a0(void);
undefined4 BuildMapContextStatusStringVariantI(void);
undefined4 BuildMapContextStatusStringVariantG(void);
undefined4 BuildMapContextStatusStringVariantF(void);
undefined4 BuildMapContextStatusStringVariantJ(void);
undefined4 BuildMapContextStatusStringVariantC(void);
undefined4 BuildMapContextStatusStringVariantE(void);
undefined4 BuildMapContextStatusStringVariantL(void);
undefined4 BuildMapContextStatusStringVariantD(void);
undefined4 BuildMapContextStatusStringVariantA(void);
undefined4 ShouldRetryMappedFlavorTextGeneration(void);

static int MappedFlavorCStringLength(const CString* value) {
  LPCSTR text = static_cast<LPCSTR>(*value);
  if (text == 0) {
    return 0;
  }
  int length = 0;
  while (text[length] != '\0') {
    ++length;
  }
  return length;
}

// FUNCTION: IMPERIALISM 0x005d4410
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot) {
  if (reinterpret_cast<char*>(g_pLocalizationTable)[0x68] == '\0') {
    short variantIndex = g_MappedFlavorTextNationVariantTable_0066EF30[tableSlot].variantIndex;
    GenerateMappedFlavorTextUntilValidationPasses(dest, variantIndex);
    if (DAT_006a43f0 == '\0') {
      while (MappedFlavorCStringLength(dest) > 0xc) {
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

#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

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
      reinterpret_cast<void(__cdecl*)(CString*)>(GenerateMappedFlavorTextVariantC_005cf1b0)(dest);
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
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantH)(dest);
      break;
    case 6:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantK)(dest);
      break;
    case 7:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantB)(dest);
      break;
    case 8:
      reinterpret_cast<void(__cdecl*)(CString*)>(GenerateMappedFlavorTextVariantD_005d33a0)(dest);
      break;
    case 9:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantI)(dest);
      break;
    case 10:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantG)(dest);
      break;
    case 0xb:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantF)(dest);
      break;
    case 0xc:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantJ)(dest);
      break;
    case 0xd:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantC)(dest);
      break;
    case 0xe:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantE)(dest);
      break;
    case 0xf:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantL)(dest);
      break;
    case 0x10:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantD)(dest);
      break;
    case 0x11:
      reinterpret_cast<void(__cdecl*)(CString*)>(BuildMapContextStatusStringVariantA)(dest);
      break;
    }
    retry = reinterpret_cast<char(__cdecl*)(CString*)>(ShouldRetryMappedFlavorTextGeneration)(dest);
  } while (retry != 0);
}
