#ifndef IMPERIALISM_RUNTIME_JSON_OBJECT_H
#define IMPERIALISM_RUNTIME_JSON_OBJECT_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error JsonObject is test-only and must not be included in the production build
#endif

#include "parson.h"

// Tiny VC5-compatible ownership wrapper around Parson objects. Allocation failures abort;
// this is test infrastructure inside a game process, not a recoverable runtime path.
class JsonObject {
public:
  JsonObject();
  // Takes ownership of an existing JSON object value.
  explicit JsonObject(JSON_Value* existing);
  ~JsonObject();

  void Set(const char* name, int value);
  void Set(const char* name, unsigned int value);
  void Set(const char* name, bool value);
  void Set(const char* name, const char* value);
  void SetNull(const char* name);
  // Takes ownership of value.
  void Set(const char* name, JSON_Value* value);
  // Writes null when value < 0; otherwise writes the number.
  void SetOptional(const char* name, int value);

  // Transfers ownership of the underlying JSON value. The wrapper becomes empty.
  JSON_Value* Release();

private:
  JsonObject(const JsonObject&);
  JsonObject& operator=(const JsonObject&);

  void EnsureLive() const;

  JSON_Value* value_;
  JSON_Object* object_;
};

JSON_Value* JsonNullValue();
void JsonFreeValue(JSON_Value* value);
JSON_Value* JsonDeepCopy(const JSON_Value* value);

#endif
