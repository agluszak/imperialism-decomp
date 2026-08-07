#pragma once

// Counts leading integer spans whose accumulated extent does not exceed position.
unsigned int CountLeadingSpansAtOrBeforePosition(const int* spans, int position);

// Tests the two code ranges accepted by this UI-layout dispatch helper.
bool __stdcall IsLayoutDispatchCodeAccepted(short code);
