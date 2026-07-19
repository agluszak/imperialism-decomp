#pragma once

class CString;
class TSimMgr;

#include "compat.h"

// Growable realloc-backed byte sink with a single virtual appender. Stack-local
// instances drive the bracket-template flatteners (0x580280 and siblings); the
// caller frees the handed-out buffer with free(). The original vtable has exactly
// one slot -- no virtual destructor existed.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x00662b00
class TResizableByteSink {
public:
  virtual void AppendByteToResizableBuffer(char byteValue); // 0x580460
  char* buffer4; // 0x04 -- realloc-grown storage (returned to the caller)
  int capacity8; // 0x08
  int lengthC;   // 0x0c
  TResizableByteSink() : buffer4(0), capacity8(0), lengthC(0) {}
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

// 0x580280: flatten `templateText` into a fresh realloc'd buffer, substituting each
// [N] bracket with tokenN ([Nx] with a lowercase letter routes through
// TLanguageMgr::Localize). Caller owns (free()s) the returned buffer. `sim` is unused.
char* __cdecl AppendInterNationEventSummaryTextEntry_Impl(TSimMgr* sim, const char* templateText,
                                                          const char* token1, const char* token2,
                                                          const char* token3, const char* token4);

// Template expander: writes `input` into `out`, substituting each `[N]` bracket with the
// N-th variadic string argument (or, for `[Nx]` with a trailing letter, the news-table
// mapped form of that argument). `ctx` is always g_pSimMgr at every call site but unused
// in the body. 0x0057fef0.
void scanBracketExpressions(TSimMgr* ctx, CString* out, const char* input, ...);

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

// 0x5d4890: GetAsyncKeyState pressed-bit for a shortcut code (code 2 remaps to 0x44).
bool IsMappedShortcutKeyPressed(short nShortcutCode);
