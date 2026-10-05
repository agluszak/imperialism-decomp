#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/shared_globals.h"
#include "game/globals/global_types.h"

// FUNCTION: IMPERIALISM 0x005d48c0
void FormatAndAssignTurnStateSharedTextFromTemplate(int codeA, int codeB, char* sourceTag,
                                                    char* context, int lineNumber,
                                                    char* compileDate, char* compileTime) {
  CString codeAText;
  CString codeBText;
  CString lineText;
  codeAText.Format(g_szDecimalFormat, codeA);
  codeBText.Format(g_szDecimalFormat, codeB);
  lineText.Format(g_szDecimalFormat, lineNumber);

  CString message;
  message += "ERROR (";
  message += sourceTag;
  message += ",";
  message += codeAText;
  message += ",";
  message += codeBText;
  message += ")\n\n";
  message += "Please record this information:\n";
  message += "'";
  message += context;
  message += "' (line ";
  message += lineText;
  message += ") compiled ";
  message += compileDate;
  message += " at ";
  message += compileTime;

  g_pViewMgr->ModalMessage(message, g_ptFormattedErrorModalMessage);
}
