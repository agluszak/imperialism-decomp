#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeJson is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

class RuntimeAwaitState;

namespace RuntimeJson {

void AppendArrayItem(CString& array, const CString& item);
void AppendString(CString& json, const char* value);
bool WriteFileAtomically(const char* path, const CString& json);

} // namespace RuntimeJson

// The "await" object shared by the heartbeat and the result file: what the scenario is
// waiting for, where that wait is written, and which observations would satisfy it.
// Renders JSON `null` when nothing is armed, so a reader can tell "not waiting" from
// "waiting on something unnamed".
CString RuntimeAwaitStateJson(const RuntimeAwaitState& state);
