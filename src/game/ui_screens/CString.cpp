#include "game/ui_screens/CString.h"

#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

#include <stdlib.h>
#include <string.h>

// LIBRARY: IMPERIALISM 0x004adc40
// CString::CString(const char*)

// LIBRARY: IMPERIALISM 0x004ae990
// CString::CString(const unsigned short*)

// LIBRARY: IMPERIALISM 0x00605791
// GetSharedEmptyStringRef -- a trivial `mov eax,const; ret` trampoline (returns the shared
// empty CStringData). Ambiguous in the object-matcher oracle (239 byte-identical strcore.obj
// candidates at this size); kept as a hedged description, not a reviewed exact symbol.

// LIBRARY: IMPERIALISM 0x00605797
// CString::CString

// LIBRARY: IMPERIALISM 0x006057a7
// CString::CString

// LIBRARY: IMPERIALISM 0x006057de
// CString::AllocBuffer

// LIBRARY: IMPERIALISM 0x0060584a
// CString::Release(CStringData*) -- protected static overload

// LIBRARY: IMPERIALISM 0x0060586d
// CString::Empty

// LIBRARY: IMPERIALISM 0x0060588b
// CString::CopyBeforeWrite

// LIBRARY: IMPERIALISM 0x006058b9
// CString::AllocBeforeWrite

// LIBRARY: IMPERIALISM 0x006058e2
// CString::~CString

// LIBRARY: IMPERIALISM 0x00605950
// CString::CString

// LIBRARY: IMPERIALISM 0x006059fc
// CString::AssignCopy

// LIBRARY: IMPERIALISM 0x00605a29
// CString::operator=

// LIBRARY: IMPERIALISM 0x00605a78
// CString::operator=

// LIBRARY: IMPERIALISM 0x00605ae0
// CString::ConcatCopy

// LIBRARY: IMPERIALISM 0x00605b21
// operator+(const CString&, const CString&)

// LIBRARY: IMPERIALISM 0x00605b87
// operator+(const CString&, const char*)

// LIBRARY: IMPERIALISM 0x00605bfb
// operator+(const char*, const CString&)

// LIBRARY: IMPERIALISM 0x00605c6f
// CString::ConcatInPlace

// LIBRARY: IMPERIALISM 0x00605cce
// CString::operator+=

// LIBRARY: IMPERIALISM 0x00605cf5
// CString::operator+=

// LIBRARY: IMPERIALISM 0x00605d0a
// CString::operator+=

// LIBRARY: IMPERIALISM 0x00605d22
// CString::GetBuffer

// LIBRARY: IMPERIALISM 0x00605d71
// CString::ReleaseBuffer

// LIBRARY: IMPERIALISM 0x00605d99
// CString::GetBufferSetLength

// LIBRARY: IMPERIALISM 0x00605dec
// CString::LockBuffer

// LIBRARY: IMPERIALISM 0x005ff15e
// CString::Format (LPCTSTR, ...) — AFX_CDECL member; va_start + FormatV

// Formats a nonnegative float into *outResult as a comma-grouped integer part (thousands, then
// millions --
// applied in that order using the string length computed before either insertion, matching the
// original's exact split points even though the first insertion already changes the string's
// length by the time the second one runs) plus, when the value has a fractional remainder, a
// "." and a 1-or-2-digit decimal part (a trailing-zero digit is stripped before formatting).
// The retail arithmetic subtracts the absolute integral part from `value`, so negative fractional
// inputs are intentionally outside this helper's domain rather than silently changing its body.
// FUNCTION: IMPERIALISM 0x0057fa30
void __stdcall FormatNonnegativeFloatToLocalizedSharedString(float value, CString* outResult) {
  CString thousandsSep(",");
  CString decimalPoint(".");

  int intPart = static_cast<int>(value);
  bool isNegative = intPart < 0;
  if (isNegative) {
    intPart = -intPart;
  }

  char* buf = outResult->GetBuffer(0x11);
  _itoa(intPart, buf, 10);
  outResult->ReleaseBuffer(-1);

  int len = outResult->GetLength();
  if (len > 6) {
    CString last6 = outResult->Right(6);
    CString firstRest = outResult->Left(len - 6);
    *outResult = firstRest + thousandsSep + last6;
  }
  if (len > 3) {
    CString last3 = outResult->Right(3);
    CString firstRest = outResult->Left(len - 3);
    *outResult = firstRest + thousandsSep + last3;
  }
  if (isNegative) {
    *outResult = '-' + *outResult;
  }

  int fracPart = static_cast<int>((value - static_cast<float>(intPart)) * 100.0f);
  if (fracPart > 0) {
    CString fracStr;
    if (fracPart % 10 == 0) {
      fracPart /= 10;
    }
    fracStr.Format(g_szDecimalFormat, fracPart);
    *outResult = *outResult + decimalPoint + fracStr;
  }
}
