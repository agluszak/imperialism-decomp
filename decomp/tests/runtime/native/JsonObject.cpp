#include "JsonObject.h"

#include <stdio.h>
#include <stdlib.h>

namespace {

void FailJson(const char* what) {
  fprintf(stderr, "runtime capture JSON failure: %s\n", what);
  abort();
}

} // namespace

JsonObject::JsonObject() : value_(0), object_(0) {
  value_ = json_value_init_object();
  object_ = value_ != 0 ? json_value_get_object(value_) : 0;
  if (value_ == 0 || object_ == 0) {
    FailJson("json_value_init_object");
  }
}

JsonObject::JsonObject(JSON_Value* existing) : value_(existing), object_(0) {
  object_ = value_ != 0 ? json_value_get_object(value_) : 0;
  if (value_ == 0 || object_ == 0) {
    json_value_free(value_);
    value_ = 0;
    FailJson("JsonObject from existing object value");
  }
}

JsonObject::~JsonObject() {
  if (value_ != 0) {
    json_value_free(value_);
    value_ = 0;
    object_ = 0;
  }
}

void JsonObject::EnsureLive() const {
  if (value_ == 0 || object_ == 0) {
    FailJson("JsonObject used after Release");
  }
}

void JsonObject::Set(const char* name, int value) {
  EnsureLive();
  if (name == 0 || json_object_set_number(object_, name, value) != JSONSuccess) {
    FailJson("json_object_set_number(int)");
  }
}

void JsonObject::Set(const char* name, unsigned int value) {
  EnsureLive();
  if (name == 0 || json_object_set_number(object_, name, value) != JSONSuccess) {
    FailJson("json_object_set_number(unsigned)");
  }
}

void JsonObject::Set(const char* name, double value) {
  EnsureLive();
  if (name == 0 || json_object_set_number(object_, name, value) != JSONSuccess) {
    FailJson("json_object_set_number(double)");
  }
}

void JsonObject::Set(const char* name, bool value) {
  EnsureLive();
  if (name == 0 || json_object_set_boolean(object_, name, value ? 1 : 0) != JSONSuccess) {
    FailJson("json_object_set_boolean");
  }
}

void JsonObject::Set(const char* name, const char* value) {
  EnsureLive();
  if (name == 0 || value == 0 || json_object_set_string(object_, name, value) != JSONSuccess) {
    FailJson("json_object_set_string");
  }
}

void JsonObject::SetNull(const char* name) {
  EnsureLive();
  if (name == 0 || json_object_set_null(object_, name) != JSONSuccess) {
    FailJson("json_object_set_null");
  }
}

void JsonObject::Set(const char* name, JSON_Value* value) {
  EnsureLive();
  if (name == 0 || value == 0) {
    json_value_free(value);
    FailJson("json_object_set_value args");
  }
  if (json_object_set_value(object_, name, value) != JSONSuccess) {
    json_value_free(value);
    FailJson("json_object_set_value");
  }
}

void JsonObject::SetOptional(const char* name, int value) {
  if (value == -1) {
    SetNull(name);
  } else if (value < -1) {
    FailJson("optional semantic value is below the -1 sentinel");
  } else {
    Set(name, value);
  }
}

JSON_Value* JsonObject::Release() {
  EnsureLive();
  JSON_Value* released = value_;
  value_ = 0;
  object_ = 0;
  return released;
}

JSON_Value* JsonNullValue() {
  JSON_Value* value = json_value_init_null();
  if (value == 0) {
    FailJson("json_value_init_null");
  }
  return value;
}

void JsonFreeValue(JSON_Value* value) {
  if (value != 0) {
    json_value_free(value);
  }
}

JSON_Value* JsonDeepCopy(const JSON_Value* value) {
  if (value == 0) {
    return 0;
  }
  JSON_Value* copy = json_value_deep_copy(value);
  if (copy == 0) {
    FailJson("json_value_deep_copy");
  }
  return copy;
}
