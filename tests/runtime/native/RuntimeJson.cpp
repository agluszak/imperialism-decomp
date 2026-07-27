#include "RuntimeJson.h"

#include <windows.h>

namespace RuntimeJson {

void AppendArrayItem(CString& array, const CString& item) {
  if (array.GetLength() > 1) {
    array += ", ";
  }
  array += item;
}

void AppendString(CString& json, const char* value) {
  json += '"';
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor != 0;
       ++cursor) {
    char escaped[7];
    switch (*cursor) {
    case '"':
      json += "\\\"";
      break;
    case '\\':
      json += "\\\\";
      break;
    case '\n':
      json += "\\n";
      break;
    case '\r':
      json += "\\r";
      break;
    case '\t':
      json += "\\t";
      break;
    default:
      if (*cursor < 0x20) {
        wsprintfA(escaped, "\\u%04x", static_cast<unsigned int>(*cursor));
        json += escaped;
      } else {
        json += static_cast<char>(*cursor);
      }
      break;
    }
  }
  json += '"';
}

namespace {

bool WriteAll(HANDLE file, const char* bytes, DWORD size) {
  DWORD written = 0;
  return WriteFile(file, bytes, size, &written, 0) != 0 && written == size;
}

} // namespace

bool WriteFileAtomically(const char* path, const CString& json) {
  CString temporaryPath(path);
  temporaryPath += ".tmp";
  HANDLE file =
      CreateFileA(temporaryPath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  const char* bytes = static_cast<LPCSTR>(json);
  bool wrote = WriteAll(file, bytes, static_cast<DWORD>(json.GetLength()));
  if (wrote) {
    wrote = FlushFileBuffers(file) != 0;
  }
  CloseHandle(file);
  if (!wrote) {
    DeleteFileA(temporaryPath);
    return false;
  }
  if (MoveFileExA(temporaryPath, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    DeleteFileA(temporaryPath);
    return false;
  }
  return true;
}

} // namespace RuntimeJson
