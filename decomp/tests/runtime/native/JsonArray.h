#ifndef IMPERIALISM_RUNTIME_JSON_ARRAY_H
#define IMPERIALISM_RUNTIME_JSON_ARRAY_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error JsonArray is test-only and must not be included in the production build
#endif

#include "parson.h"

// Tiny VC5-compatible ownership wrapper around Parson arrays. Allocation failures abort;
// this is test infrastructure inside a game process, not a recoverable runtime path.
class JsonArray {
public:
  JsonArray();
  ~JsonArray();

  void Add(int value);
  void Add(unsigned int value);
  void Add(bool value);
  void Add(const char* value);
  void AddNull();
  // Takes ownership of value.
  void Add(JSON_Value* value);

  // Transfers ownership of the underlying JSON value. The wrapper becomes empty.
  JSON_Value* Release();

private:
  JsonArray(const JsonArray&);
  JsonArray& operator=(const JsonArray&);

  void EnsureLive() const;

  JSON_Value* value_;
  JSON_Array* array_;
};

#endif
