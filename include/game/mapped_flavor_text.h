#pragma once

class CString;

// Template expander: writes `input` into `out`, substituting each `[N]` bracket with the
// N-th variadic string argument (or, for `[Nx]` with a trailing letter, the news-table
// mapped form of that argument). `ctx` is unused. 0x0057fef0.
void scanBracketExpressions(void* ctx, void* out, const char* input, ...);
void GenerateMappedFlavorTextByCurrentContextNation(CString* dest);
void BuildMapContextStatusStringVariantL(CString* out);
void GenerateMappedFlavorTextByTableSlot(CString* dest, short tableSlot);
void GenerateMappedFlavorTextUntilValidationPasses(CString* dest, short variantIndex);
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot);
