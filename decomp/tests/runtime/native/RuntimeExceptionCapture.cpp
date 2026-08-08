#include <string.h>

#include "game/mfc.h"

#include "RuntimeExceptionCapture.h"

#include "RuntimeObservations.h"
#include "RuntimeResultWriter.h"
#include "RuntimeRun.h"
#include "scenarios/RuntimeScenario.h"

#include "game/core/global_data_tables.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"

#include "game/globals/view_registries.h"

namespace {

RuntimeRun* g_exceptionRun = 0;
RuntimeScenario* g_exceptionScenario = 0;

JSON_Value* BuildExceptionValue(EXCEPTION_POINTERS* exception) {
  if (exception == 0 || exception->ExceptionRecord == 0) {
    return json_value_init_null();
  }
  JSON_Value* value = json_value_init_object();
  JSON_Object* details = value != 0 ? json_value_get_object(value) : 0;
  char code[16];
  char address[32];
  wsprintfA(code, "0x%08lx", exception->ExceptionRecord->ExceptionCode);
  wsprintfA(address, "%p", exception->ExceptionRecord->ExceptionAddress);
  if (details == 0 || json_object_set_string(details, "code", code) != JSONSuccess ||
      json_object_set_string(details, "address", address) != JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

bool WriteJsonValueAtomically(const char* path, JSON_Value* value) {
  char* text = value != 0 ? json_serialize_to_string(value) : 0;
  if (text == 0) {
    return false;
  }
  bool written = WriteRuntimeBytesAtomically(path, text, static_cast<unsigned long>(strlen(text)));
  json_free_serialized_string(text);
  return written;
}

LONG WINAPI RuntimeUnhandledExceptionFilter(EXCEPTION_POINTERS* info) {
  if (g_exceptionRun != 0 && g_exceptionScenario != 0 && !g_exceptionRun->IsFinished() &&
      info != 0 && info->ExceptionRecord != 0) {
    const char* failure = "unhandled exception";
    g_exceptionRun->RecordAssertion("process.unhandled_exception", failure, true);
    RuntimeExceptionCapture::Trap(*g_exceptionRun, *g_exceptionScenario,
                                  kRuntimeDebugUnhandledException, failure, info);
    g_exceptionRun->Finish();
    WriteRuntimeResult(*g_exceptionRun, "failed");
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

void RuntimeExceptionCapture::Install(RuntimeRun& run, RuntimeScenario& scenario) {
  g_exceptionRun = &run;
  g_exceptionScenario = &scenario;
  SetUnhandledExceptionFilter(RuntimeUnhandledExceptionFilter);
}

void RuntimeExceptionCapture::Trap(RuntimeRun& run, RuntimeScenario& scenario,
                                   RuntimeDebugReason reason, const char* failure,
                                   EXCEPTION_POINTERS* exception) {
  (void)scenario;
  TView* activeModal = g_ModalViewStack.IsEmpty() ? 0 : g_ModalViewStack.GetHead();
  RuntimeDebugRecord record;
  record.reason = reason;
  record.elapsedMs = run.ElapsedMs();
  record.testName = run.TestName();
  record.phase = run.PhaseName();
  record.lastAction = run.LastAction();
  record.turnEvent = g_pViewMgr != 0 ? g_pViewMgr->currentTurnEventCode : -1;
  record.modalDepth = g_ModalViewStack.GetCount();
  record.mainView = RuntimeMainView();
  record.activeModal = activeModal;
  record.simMgr = g_pSimMgr;
  record.exceptionPointers = exception;

  if (run.DebugRecordPath()[0] != 0) {
    JSON_Value* value = json_value_init_object();
    JSON_Object* debug = value != 0 ? json_value_get_object(value) : 0;
    JSON_Value* exceptionValue = BuildExceptionValue(exception);
    if (debug != 0 && exceptionValue != 0 &&
        json_object_set_number(debug, "reason", static_cast<int>(reason)) == JSONSuccess &&
        json_object_set_string(debug, "test", run.TestName()) == JSONSuccess &&
        json_object_set_string(debug, "phase", run.PhaseName()) == JSONSuccess &&
        json_object_set_string(debug, "last_action", run.LastAction()) == JSONSuccess &&
        json_object_set_number(debug, "elapsed_ms", record.elapsedMs) == JSONSuccess &&
        json_object_set_number(debug, "turn_event", record.turnEvent) == JSONSuccess &&
        json_object_set_number(debug, "modal_depth", record.modalDepth) == JSONSuccess &&
        json_object_set_string(debug, "assertion_id", run.FirstAssertionId()) == JSONSuccess &&
        json_object_set_string(debug, "failure", failure != 0 ? failure : "") == JSONSuccess &&
        json_object_set_value(debug, "exception", exceptionValue) == JSONSuccess) {
      WriteJsonValueAtomically(run.DebugRecordPath(), value);
    } else {
      json_value_free(exceptionValue);
    }
    json_value_free(value);
  }
  ImperialismRuntimeDebuggerTrap(&record);
}
