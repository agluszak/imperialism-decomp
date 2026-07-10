#pragma once

class CString;
class TSimMgr;

// Template expander: writes `input` into `out`, substituting each `[N]` bracket with the
// N-th variadic string argument (or, for `[Nx]` with a trailing letter, the news-table
// mapped form of that argument). `ctx` is unused. 0x0057fef0.
void scanBracketExpressions(void* ctx, void* out, const char* input, ...);

// 0x580060: load the (groupA, indexA) template and expand it into `out`; bracket
// digit [0] re-expands pair A, [1] expands (groupB, indexB), and a trailing lowercase
// letter routes the expansion through TLanguageMgr::BuildMappedSharedStringFromByte-
// StateTable (turn-event 0xA/0xC receive paths). Genuine __cdecl free function.
void __cdecl BuildUiMessageTextFromBracketTemplate(TSimMgr* sim, CString* out, int groupA,
                                                   int indexA, int groupB, int indexB);
void GenerateMappedFlavorTextByCurrentContextNation(CString* dest);
void GenerateMappedFlavorTextVariantC_005cf1b0(CString* out);
void GenerateMappedFlavorTextVariantE_005ccce0(CString* out);
void GenerateMappedFlavorTextVariantB_005cfc40(CString* out);
void GenerateMappedFlavorTextVariantA_005d13d0(CString* out);
void GenerateMappedFlavorTextVariantD_005d33a0(CString* out);
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
char ShouldRetryMappedFlavorTextGeneration(CString* dest);
void GenerateMappedFlavorTextUntilValidationPasses(CString* dest, short variantIndex);
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot);
