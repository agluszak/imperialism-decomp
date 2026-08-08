#include "JsonArray.h"

#include <stdio.h>
#include <stdlib.h>

namespace {

void FailJson(const char* what) {
  fprintf(stderr, "runtime capture JSON failure: %s\n", what);
  abort();
}

} // namespace

JsonArray::JsonArray() : value_(0), array_(0) {
  value_ = json_value_init_array();
  array_ = value_ != 0 ? json_value_get_array(value_) : 0;
  if (value_ == 0 || array_ == 0) {
    FailJson("json_value_init_array");
  }
}

JsonArray::~JsonArray() {
  if (value_ != 0) {
    json_value_free(value_);
    value_ = 0;
    array_ = 0;
  }
}

void JsonArray::EnsureLive() const {
  if (value_ == 0 || array_ == 0) {
    FailJson("JsonArray used after Release");
  }
}

void JsonArray::Add(int value) {
  EnsureLive();
  if (json_array_append_number(array_, value) != JSONSuccess) {
    FailJson("json_array_append_number(int)");
  }
}

void JsonArray::Add(unsigned int value) {
  EnsureLive();
  if (json_array_append_number(array_, value) != JSONSuccess) {
    FailJson("json_array_append_number(unsigned)");
  }
}

void JsonArray::Add(bool value) {
  EnsureLive();
  if (json_array_append_boolean(array_, value ? 1 : 0) != JSONSuccess) {
    FailJson("json_array_append_boolean");
  }
}

void JsonArray::Add(const char* value) {
  EnsureLive();
  if (value == 0 || json_array_append_string(array_, value) != JSONSuccess) {
    FailJson("json_array_append_string");
  }
}

void JsonArray::AddNull() {
  EnsureLive();
  if (json_array_append_null(array_) != JSONSuccess) {
    FailJson("json_array_append_null");
  }
}

void JsonArray::Add(JSON_Value* value) {
  EnsureLive();
  if (value == 0) {
    FailJson("json_array_append_value null");
  }
  if (json_array_append_value(array_, value) != JSONSuccess) {
    json_value_free(value);
    FailJson("json_array_append_value");
  }
}

JSON_Value* JsonArray::Release() {
  EnsureLive();
  JSON_Value* released = value_;
  value_ = 0;
  array_ = 0;
  return released;
}
