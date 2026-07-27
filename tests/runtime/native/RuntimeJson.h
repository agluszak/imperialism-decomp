#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeJson is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

namespace RuntimeJson {

void AppendArrayItem(CString& array, const CString& item);
void AppendString(CString& json, const char* value);
bool WriteFileAtomically(const char* path, const CString& json);

} // namespace RuntimeJson
