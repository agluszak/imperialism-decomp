#include "RuntimeSemanticCapture.h"

#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

bool CaptureNamedGameState(RuntimeRun& run, const char* name) {
  JSON_Value* state = 0;
  if (name == 0 || !BuildRuntimeGameState(run, &state)) {
    json_value_free(state);
    return false;
  }
  run.SetCapture(name, state);
  return true;
}

JSON_Value* BuildAcceptedOpResult() {
  JSON_Value* value = json_value_init_object();
  JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
  if (object == 0 || json_object_set_string(object, "status", "accepted") != JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}

JSON_Value* BuildRejectedNotMajorOpResult(int nationSlot) {
  JSON_Value* value = json_value_init_object();
  JSON_Object* object = value != 0 ? json_value_get_object(value) : 0;
  if (object == 0 ||
      json_object_set_string(object, "status", "rejected") != JSONSuccess ||
      json_object_set_string(object, "reason", "not_major_nation") != JSONSuccess ||
      json_object_set_number(object, "nation", nationSlot) != JSONSuccess) {
    json_value_free(value);
    return 0;
  }
  return value;
}
