#include "game/mfc.h"
#include <new.h>
#include <ctype.h>

// The retail body emits `CALL _isdigit`, so undo the <ctype.h> macro to force the
// function-call form (the macro would inline the __pctype table test and drop the call).
#undef isdigit

// Variadic `[N]`-template substitutor. Copies `fmt` into the caller-provided return
// slot `out`, character by character; each `[N]` escape where N is a single ASCII
// digit is replaced by the N-th trailing string argument, counting from `fmt` itself
// ([0] = fmt, [1] = first vararg, ...). A bracket group whose first char is not a
// digit is skipped through its closing ']'. `param_1` is an unused leading argument.
// FUNCTION: IMPERIALISM 0x0049a7f0
CString* FilterStringByCharacterTypeFlag4AndAppend(int param_1, CString* out, char* fmt, ...) {
  (void)param_1;
  CString result;
  int i = 0;
  char c;
  if (fmt[0] != '\0') {
    do {
      c = fmt[i];
      if (c == '[') {
        while (c != '\0') {
          int d = fmt[i + 1];
          i++;
          if (isdigit(d)) {
            // args base is `&fmt`; the digit's numeric value selects the vararg.
            result += (&fmt)[fmt[i] - '0'];
            break;
          }
          c = fmt[i];
          if (c == ']') {
            break;
          }
        }
        c = fmt[i];
        while (c != ']' && c != '\0') {
          c = fmt[i + 1];
          i++;
        }
      } else {
        result += c;
      }
      c = fmt[i + 1];
      i++;
    } while (c != '\0');
  }
  new (out) CString(result);
  return out;
}
