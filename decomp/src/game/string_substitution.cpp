#include "game/mfc.h"
#include <new.h>
#include <ctype.h>

#undef isdigit

// FUNCTION: IMPERIALISM 0x0049a7f0
CString* FilterStringByCharacterTypeFlag4AndAppend(int, CString* out, char* fmt, ...) {
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
