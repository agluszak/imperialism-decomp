#pragma once

class CString;

void GenerateMappedFlavorTextByCurrentContextNation(CString* dest);
void GenerateMappedFlavorTextByTableSlot(CString* dest, short tableSlot);
void GenerateMappedFlavorTextUntilValidationPasses(CString* dest, short variantIndex);
void SetSharedStringFromMappedFlavorTextWithLengthClamp(CString* dest, short tableSlot);
