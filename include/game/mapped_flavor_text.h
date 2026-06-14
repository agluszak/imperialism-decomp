#pragma once

class CString;

void GenerateMappedFlavorTextByTableSlot(CString* dest, short tableSlot);
void GenerateMappedFlavorTextUntilValidationPasses(CString* dest, short variantIndex);
