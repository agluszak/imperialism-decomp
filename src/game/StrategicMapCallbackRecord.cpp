#include "game/StrategicMapCallbackRecord.h"

#include <cstdlib>

// FUNCTION: IMPERIALISM 0x00430750
StrategicMapCallbackRecord::~StrategicMapCallbackRecord() {}

// FUNCTION: IMPERIALISM 0x004307a0
unsigned char* StrategicMapOpcodeByteStretch::Add(unsigned char value) {
  int index = Count();
  if (index >= Capacity()) {
    unsigned int requestedCount = index + 1;
    unsigned int doubledCapacity = requestedCount * 2;
    if (doubledCapacity > 0x7fffffffU) {
      doubledCapacity = 0x7fffffffU;
    }
    void* grown = realloc(Data(), requestedCount * 2);
    if (grown == 0) {
      Data() = static_cast<unsigned char*>(realloc(Data(), requestedCount));
      Capacity() = requestedCount;
    } else {
      Data() = static_cast<unsigned char*>(grown);
      Capacity() = static_cast<int>(doubledCapacity);
    }
  }
  if (index >= Count()) {
    Count() = index + 1;
  }
  Data()[index] = value;
  return &Data()[index];
}

// FUNCTION: IMPERIALISM 0x00430830
int* StrategicMapCursorStretch::Add(int value) {
  int index = Count();
  if (index >= Capacity()) {
    unsigned int requestedCount = index + 1;
    unsigned int doubledCapacity = requestedCount * 2;
    if (doubledCapacity > 0x7fffffffU) {
      doubledCapacity = 0x7fffffffU;
    }
    void* grown = realloc(Data(), requestedCount * sizeof(int) * 2);
    if (grown == 0) {
      Data() = static_cast<int*>(realloc(Data(), requestedCount * sizeof(int)));
      Capacity() = requestedCount;
    } else {
      Data() = static_cast<int*>(grown);
      Capacity() = static_cast<int>(doubledCapacity);
    }
  }
  if (index >= Count()) {
    Count() = index + 1;
  }
  Data()[index] = value;
  return &Data()[index];
}

// FUNCTION: IMPERIALISM 0x004d4b90
StrategicMapCallbackRecord::StrategicMapCallbackRecord()
    : opcodeAppendCursor10(0), opcodeAlignmentOffset14(0), hadTrailingPadding18(0),
      destinationRowStride2c(0) {}

// FUNCTION: IMPERIALISM 0x004d4dd0
void StrategicMapOpcodeByteStretch::OverStretch(unsigned int requestedCount) {
  unsigned int doubledCapacity = requestedCount * 2;
  if (doubledCapacity > 0x7fffffffU) {
    doubledCapacity = 0x7fffffffU;
  }
  void* grown = realloc(Data(), requestedCount * 2);
  if (grown == 0) {
    Data() = static_cast<unsigned char*>(realloc(Data(), requestedCount));
    Capacity() = requestedCount;
  } else {
    Data() = static_cast<unsigned char*>(grown);
    Capacity() = static_cast<int>(doubledCapacity);
  }
}

// FUNCTION: IMPERIALISM 0x004d4e40
unsigned char& StrategicMapOpcodeByteStretch::operator[](unsigned int index) {
  if (index >= static_cast<unsigned int>(Capacity())) {
    unsigned int requestedCount = index + 1;
    unsigned int doubledCapacity = requestedCount * 2;
    if (doubledCapacity > 0x7fffffffU) {
      doubledCapacity = 0x7fffffffU;
    }
    void* grown = realloc(Data(), requestedCount * 2);
    if (grown == 0) {
      Data() = static_cast<unsigned char*>(realloc(Data(), requestedCount));
      Capacity() = requestedCount;
    } else {
      Data() = static_cast<unsigned char*>(grown);
      Capacity() = static_cast<int>(doubledCapacity);
    }
  }
  if (index >= static_cast<unsigned int>(Count())) {
    Count() = index + 1;
  }
  return Data()[index];
}

// FUNCTION: IMPERIALISM 0x004d4ed0
void StrategicMapCursorStretch::OverStretch(unsigned int requestedCount) {
  unsigned int doubledCapacity = requestedCount * 2;
  if (doubledCapacity > 0x7fffffffU) {
    doubledCapacity = 0x7fffffffU;
  }
  void* grown = realloc(Data(), requestedCount * sizeof(int) * 2);
  if (grown == 0) {
    Data() = static_cast<int*>(realloc(Data(), requestedCount * sizeof(int)));
    Capacity() = requestedCount;
  } else {
    Data() = static_cast<int*>(grown);
    Capacity() = static_cast<int>(doubledCapacity);
  }
}

// FUNCTION: IMPERIALISM 0x004d4f50
int& StrategicMapCursorStretch::operator[](unsigned int index) {
  if (index >= static_cast<unsigned int>(Capacity())) {
    unsigned int requestedCount = index + 1;
    unsigned int doubledCapacity = requestedCount * 2;
    if (doubledCapacity > 0x7fffffffU) {
      doubledCapacity = 0x7fffffffU;
    }
    void* grown = realloc(Data(), requestedCount * sizeof(int) * 2);
    if (grown == 0) {
      Data() = static_cast<int*>(realloc(Data(), requestedCount * sizeof(int)));
      Capacity() = requestedCount;
    } else {
      Data() = static_cast<int*>(grown);
      Capacity() = static_cast<int>(doubledCapacity);
    }
  }
  if (index >= static_cast<unsigned int>(Count())) {
    Count() = index + 1;
  }
  return Data()[index];
}
