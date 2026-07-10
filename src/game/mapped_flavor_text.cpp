#include "game/mapped_flavor_text.h"

#include "game/CString.h"
#include "game/global_data_tables.h"
#include "game/TLanguageMgr.h"
#include "game/TSimMgr.h"

extern "C" char DAT_006a43f0;

// FUNCTION: IMPERIALISM 0x0056d5c0
CString BuildSharedStringFromMappedFlavorTextIndex(short variantIndex) {
  CString result;
  GenerateMappedFlavorTextUntilValidationPasses(&result, variantIndex);
  return result;
}

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

// FUNCTION: IMPERIALISM 0x00580060
void __cdecl BuildUiMessageTextFromBracketTemplate(TSimMgr* sim, CString* out, int groupA,
                                                   int indexA, int groupB, int indexB) {
  // TODO: port body @ 0x580060 (424 bytes; not yet ported). Declared for real so the
  // turn-event receive paths get correctly-typed call sites.
  (void)sim;
  (void)out;
  (void)groupA;
  (void)indexA;
  (void)groupB;
  (void)indexB;
}

// The generated flavor text is rejected (regenerate) if it contains any character from
// this banned set list; each entry is a FindOneOf char-set probe against the result.
// FUNCTION: IMPERIALISM 0x005d4240
char ShouldRetryMappedFlavorTextGeneration(CString* dest) {
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
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005d4410
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot) {
  if (g_pSimMgr->useLocalizedNameTables68 == '\0') {
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
  g_pSimMgr->GetString(0x2715, tableSlot, &localizedName);
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
