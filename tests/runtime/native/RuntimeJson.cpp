#include "RuntimeJson.h"

#include "RuntimeHarnessCore.h"

#include <string.h>
#include <windows.h>

namespace RuntimeJson {

void AppendArrayItem(CString& array, const CString& item) {
  if (array.GetLength() > 1) {
    array += ", ";
  }
  array += item;
}

void AppendString(CString& json, const char* value) {
  const unsigned long capacity = static_cast<unsigned long>(strlen(value)) * 6 + 3;
  char* escaped = new char[capacity];
  if (EscapeRuntimeJsonString(value, escaped, capacity)) {
    json += escaped;
  }
  delete[] escaped;
}

bool WriteFileAtomically(const char* path, const CString& json) {
  const char* bytes = static_cast<LPCSTR>(json);
  return WriteRuntimeBytesAtomically(path, bytes, static_cast<unsigned long>(json.GetLength()));
}

} // namespace RuntimeJson
