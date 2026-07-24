#include "game/military/mapped_flavor_text.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

// Formats one army-action count row into the shared 0xff-char label accumulator: builds
// "<count> <action>" (when every unit is committed) or "<count> <action> (<remaining>
// <unit-kind>)" via the localized bracket-template expander, then appends it to outLabel
// with a ", " separator when the accumulator already holds text. 0x004a2610, __cdecl.
//
// FUNCTION: IMPERIALISM 0x004a2610
void __cdecl BuildArmyActionLabelFromLocalizationAndCounts(char* outLabel, int totalCount,
                                                           int doneCount, int unitIndex) {
  if (totalCount == 0) {
    return;
  }

  CString actionName;
  CString countStr;
  CString builtLabel;

  g_pSimMgr->GetString(0x2717, static_cast<short>(unitIndex), &actionName);
  countStr.Format(g_szDecimalFormat, totalCount);

  if (totalCount == doneCount) {
    scanBracketExpressions(g_pSimMgr, &builtLabel, "[1] [2]", &countStr, &actionName);
  } else {
    CString remainingStr;
    CString unitKind;
    remainingStr.Format(g_szDecimalFormat, totalCount - doneCount);
    g_pSimMgr->GetString(0x273d, 0xb, &unitKind);
    scanBracketExpressions(g_pSimMgr, &builtLabel, "[1] [2] ([3] [4])", &countStr, &actionName,
                           &remainingStr, &unitKind);
  }

  // Prepend a ", " separator when the accumulator already holds text.
  if (_mbscmp(reinterpret_cast<const unsigned char*>(outLabel),
              reinterpret_cast<const unsigned char*>(g_szEmptyString)) != 0) {
    CString separator(g_szListSeparator_00695760);
    int end = 0;
    while (end < 0xff && outLabel[end] != '\0') {
      end++;
    }
    if (end < 0xff) {
      const char* src = static_cast<const char*>(separator);
      int j = end;
      do {
        char c = src[j - end];
        outLabel[j] = c;
        if (c == '\0') {
          break;
        }
        j++;
      } while (j < 0xff);
    }
  }

  // Append the freshly built label.
  int end = 0;
  while (end < 0xff && outLabel[end] != '\0') {
    end++;
  }
  if (end < 0xff) {
    const char* src = static_cast<const char*>(builtLabel);
    int j = end;
    do {
      char c = src[j - end];
      outLabel[j] = c;
      if (c == '\0') {
        break;
      }
      j++;
    } while (j < 0xff);
  }
}
