#include "RuntimeContext.h"

#include "RuntimeRun.h"

RuntimeContext::RuntimeContext(RuntimeRun& value) : run(&value) {}

void RuntimeContext::InitializeFromEnvironment() {
  run->InitializeFromEnvironment();
}

const char* RuntimeContext::TestName() const {
  return run->TestName();
}

unsigned int RuntimeContext::Seed() const {
  return run->Seed();
}

RuntimeRun& RuntimeContext::Run() const {
  return *run;
}
