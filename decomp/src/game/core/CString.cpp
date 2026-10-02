#include "game/core/CString.h"

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

// LIBRARY: IMPERIALISM 0x00605797 SYMBOL
// ??0CString@@QAE@XZ
// name: CString::CString
// prototype: public: __thiscall CString::CString(void)

// LIBRARY: IMPERIALISM 0x006057a7 SYMBOL
// ??0CString@@QAE@ABV0@@Z
// name: CString::CString
// prototype: public: __thiscall CString::CString(class CString const &)

// LIBRARY: IMPERIALISM 0x006057de SYMBOL
// ?AllocBuffer@CString@@IAEXH@Z
// name: CString::AllocBuffer
// prototype: protected: void __thiscall CString::AllocBuffer(int)

// LIBRARY: IMPERIALISM 0x0060584a SYMBOL
// ?Release@CString@@KGXPAUCStringData@@@Z
// name: CString::Release
// prototype: protected: static void __stdcall CString::Release(struct CStringData *)
// CString::Release(CStringData*) -- protected static overload

// LIBRARY: IMPERIALISM 0x0060586d SYMBOL
// ?Empty@CString@@QAEXXZ
// name: CString::Empty
// prototype: public: void __thiscall CString::Empty(void)

// LIBRARY: IMPERIALISM 0x0060588b SYMBOL
// ?CopyBeforeWrite@CString@@IAEXXZ
// name: CString::CopyBeforeWrite
// prototype: protected: void __thiscall CString::CopyBeforeWrite(void)

// LIBRARY: IMPERIALISM 0x006058b9 SYMBOL
// ?AllocBeforeWrite@CString@@IAEXH@Z
// name: CString::AllocBeforeWrite
// prototype: protected: void __thiscall CString::AllocBeforeWrite(int)

// LIBRARY: IMPERIALISM 0x006058e2 SYMBOL
// ??1CString@@QAE@XZ
// name: CString::~CString
// prototype: public: __thiscall CString::~CString(void)

// LIBRARY: IMPERIALISM 0x00605950 SYMBOL
// ??0CString@@QAE@PBD@Z
// name: CString::CString
// prototype: public: __thiscall CString::CString(char const *)

// LIBRARY: IMPERIALISM 0x006059fc SYMBOL
// ?AssignCopy@CString@@IAEXHPBD@Z
// name: CString::AssignCopy
// prototype: protected: void __thiscall CString::AssignCopy(int, char const *)

// LIBRARY: IMPERIALISM 0x00605a29 SYMBOL
// ??4CString@@QAEABV0@ABV0@@Z
// name: CString::operator=
// prototype: public: class CString const & __thiscall CString::operator=(class CString const &)

// LIBRARY: IMPERIALISM 0x00605a78 SYMBOL
// ??4CString@@QAEABV0@PBD@Z
// name: CString::operator=
// prototype: public: class CString const & __thiscall CString::operator=(char const *)

// LIBRARY: IMPERIALISM 0x00605ae0 SYMBOL
// ?ConcatCopy@CString@@IAEXHPBDH0@Z
// name: CString::ConcatCopy
// prototype: protected: void __thiscall CString::ConcatCopy(int, char const *, int, char const *)

// LIBRARY: IMPERIALISM 0x00605b21 SYMBOL
// ??H@YG?AVCString@@ABV0@0@Z
// name: operator+
// prototype: class CString __stdcall operator+(class CString const &, class CString const &)

// LIBRARY: IMPERIALISM 0x00605b87 SYMBOL
// ??H@YG?AVCString@@ABV0@PBD@Z
// name: operator+
// prototype: class CString __stdcall operator+(class CString const &, char const *)

// LIBRARY: IMPERIALISM 0x00605bfb SYMBOL
// ??H@YG?AVCString@@PBDABV0@@Z
// name: operator+
// prototype: class CString __stdcall operator+(char const *, class CString const &)

// LIBRARY: IMPERIALISM 0x00605c6f SYMBOL
// ?ConcatInPlace@CString@@IAEXHPBD@Z
// name: CString::ConcatInPlace
// prototype: protected: void __thiscall CString::ConcatInPlace(int, char const *)

// LIBRARY: IMPERIALISM 0x00605cce SYMBOL
// ??YCString@@QAEABV0@PBD@Z
// name: CString::operator+=
// prototype: public: class CString const & __thiscall CString::operator+=(char const *)

// LIBRARY: IMPERIALISM 0x00605cf5 SYMBOL
// ??YCString@@QAEABV0@D@Z
// name: CString::operator+=
// prototype: public: class CString const & __thiscall CString::operator+=(char)

// LIBRARY: IMPERIALISM 0x00605d0a SYMBOL
// ??YCString@@QAEABV0@ABV0@@Z
// name: CString::operator+=
// prototype: public: class CString const & __thiscall CString::operator+=(class CString const &)

// LIBRARY: IMPERIALISM 0x00605d22 SYMBOL
// ?GetBuffer@CString@@QAEPADH@Z
// name: CString::GetBuffer
// prototype: public: char * __thiscall CString::GetBuffer(int)

// LIBRARY: IMPERIALISM 0x00605d71 SYMBOL
// ?ReleaseBuffer@CString@@QAEXH@Z
// name: CString::ReleaseBuffer
// prototype: public: void __thiscall CString::ReleaseBuffer(int)

// LIBRARY: IMPERIALISM 0x00605d99 SYMBOL
// ?GetBufferSetLength@CString@@QAEPADH@Z
// name: CString::GetBufferSetLength
// prototype: public: char * __thiscall CString::GetBufferSetLength(int)

// LIBRARY: IMPERIALISM 0x00605dec SYMBOL
// ?LockBuffer@CString@@QAEPADXZ
// name: CString::LockBuffer
// prototype: public: char * __thiscall CString::LockBuffer(void)

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
