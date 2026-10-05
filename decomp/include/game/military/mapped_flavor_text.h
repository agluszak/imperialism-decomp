#pragma once

class CString;
class TSimMgr;

#include "compat.h"
#include "game/stretch.h"

char* __cdecl AppendInterNationEventSummaryTextEntry_Impl(TSimMgr* sim, const char* templateText,
                                                          const char* token1, const char* token2,
                                                          const char* token3, const char* token4);

void scanBracketExpressions(TSimMgr* ctx, CString* out, const char* input, ...);

void __cdecl BuildUiMessageTextFromBracketTemplate(TSimMgr* sim, CString* out, int groupA,
                                                   int indexA, int groupB, int indexB);
void GenerateMappedFlavorTextByCurrentContextNation(CString* dest);
void GenerateMappedFlavorTextVariantC(CString* out);
void GenerateMappedFlavorTextVariantE(CString* out);
void GenerateMappedFlavorTextVariantB(CString* out);
void GenerateMappedFlavorTextVariantA(CString* out);
void GenerateMappedFlavorTextVariantD(CString* out);
void BuildRandomMapContextStatusBaseString(CString* out);
CString AssignRandomMapContextStatusBaseString();
void AppendRandomMapContextStatusSuffixWithProbability(CString* dest);
void BuildMapContextStatusStringVariantA(CString* out);
void BuildMapContextStatusStringVariantB(CString* out);
void BuildMapContextStatusStringVariantC(CString* out);
void BuildMapContextStatusStringVariantD(CString* out);
void BuildMapContextStatusStringVariantE(CString* out);
void BuildMapContextStatusStringVariantF(CString* out);
void BuildMapContextStatusStringVariantG(CString* out);
void BuildMapContextStatusStringVariantH(CString* out);
void BuildMapContextStatusStringVariantI(CString* out);
void BuildMapContextStatusStringVariantJ(CString* out);
void BuildMapContextStatusStringVariantK(CString* out);
void BuildMapContextStatusStringVariantL(CString* out);
void GenerateMappedFlavorTextByTableSlot(CString* dest, short tableSlot);
CString BuildSharedStringFromMappedFlavorTextIndex(short variantIndex);
bool ShouldRetryMappedFlavorTextGeneration(CString* dest);
void GenerateMappedFlavorTextUntilValidationPasses(CString* dest, short variantIndex);
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot);
// nationSlot == -1 resets the per-nation localized province-name ordinals.
void __cdecl AssignNextProvinceNameForNationSlot(CString* dest, short nationSlot);

// 0x5d4890: GetAsyncKeyState pressed-bit for a shortcut code (code 2 remaps to 0x44).
bool IsMappedShortcutKeyPressed(short nShortcutCode);
