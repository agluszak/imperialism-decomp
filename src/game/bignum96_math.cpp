#include "compat.h"

// Big-endian multi-word integer helpers (word 0 is most significant). Used by the
// 96-bit fixed-point accumulators in the strategic scoring/statistics paths.

// Adds two 32-bit words, stores the sum through `out`, and returns the carry-out (1 on
// unsigned overflow, else 0).
int AddUintWithCarryOutFlag(unsigned int a, unsigned int b, unsigned int* out);

// Sets bit `bitIndex` (counted from the most-significant bit of word 0) in the multi-word
// integer at `value`, propagating the carry toward the more-significant (lower-index)
// the bit is masked to the bits strictly below it, and all more-significant words must be
// zero.
// FUNCTION: IMPERIALISM 0x005F4370
int Is96BitIntegerZeroAtOrAboveBitIndex(int* value, int bitIndex) {
  int wordIndex = bitIndex / 32;
  int bitInWord = 0x1f - bitIndex % 32;
  if ((static_cast<unsigned int>(value[wordIndex]) & ~(-1 << bitInWord)) != 0) {
    return 0;
  }
  wordIndex++;
  if (wordIndex < 3) {
    int* word = value + wordIndex;
    do {
      if (*word != 0) {
        return 0;
      }
      wordIndex++;
      word++;
    } while (wordIndex < 3);
    return 1;
  }
  return 1;
}
// words.
// FUNCTION: IMPERIALISM 0x005F43E0
int SetBitIn96BitIntegerWithCarry(int* value, int bitIndex) {
  int wordIndex = bitIndex / 32;
  int bitInWord = 0x1f - bitIndex % 32;
  int carry = AddUintWithCarryOutFlag(value[wordIndex], 1 << bitInWord,
                                      reinterpret_cast<unsigned int*>(&value[wordIndex]));
  wordIndex--;
  if (wordIndex >= 0) {
    unsigned int* word = reinterpret_cast<unsigned int*>(&value[wordIndex]);
    do {
      if (carry == 0) {
        return 0;
      }
      carry = AddUintWithCarryOutFlag(*word, 1, word);
      wordIndex--;
      word--;
    } while (wordIndex >= 0);
  }
  return carry;
}
// if the bit at bitIndex is set and anything above the next bit is nonzero, it rounds up
// by setting bitIndex-1 (propagating carry), then clears bitIndex and every
// less-significant word. Returns the top carry-out from the round-up.
// FUNCTION: IMPERIALISM 0x005F4450
int Truncate96BitIntegerAtBitWithRounding(int* value, int bitIndex) {
  int carry = 0;
  int bitInWord = 0x1f - bitIndex % 32;
  int wordIndex = bitIndex / 32;
  if ((static_cast<unsigned int>(value[wordIndex]) & 1 << (bitInWord & 0x1f)) != 0 &&
      Is96BitIntegerZeroAtOrAboveBitIndex(value, bitIndex + 1) == 0) {
    carry = SetBitIn96BitIntegerWithCarry(value, bitIndex + -1);
  }
  value[wordIndex] = value[wordIndex] & -1 << (bitInWord & 0x1f);
  wordIndex++;
  if (wordIndex < 3) {
    unsigned int* word = reinterpret_cast<unsigned int*>(&value[wordIndex]);
    for (int remaining = 3 - wordIndex; remaining != 0; remaining = remaining + -1) {
      *word = 0;
      word++;
    }
  }
  return carry;
}
// FUNCTION: IMPERIALISM 0x005F44F0
void Copy96BitIntegerWords(unsigned int* dest, unsigned int* src) {
  int offset = reinterpret_cast<int>(dest) - reinterpret_cast<int>(src);
  int count = 3;
  do {
    *reinterpret_cast<unsigned int*>(reinterpret_cast<int>(src) + offset) = *src;
    src = src + 1;
    count = count - 1;
  } while (count != 0);
}

// Zeroes the three words of a 96-bit integer.
// FUNCTION: IMPERIALISM 0x005F4510
void Zero96BitIntegerWords(unsigned int* value) {
  value[0] = 0;
  value[1] = 0;
  value[2] = 0;
}

// Returns 1 when all three words are zero, else 0.
// FUNCTION: IMPERIALISM 0x005F4520
int Is96BitIntegerZero(int* value) {
  int i = 0;
  do {
    if (*value != 0) {
      return 0;
    }
    i = i + 1;
    value = value + 1;
  } while (i < 3);
  return 1;
}
// bitCount%32 carrying between words, then a whole-word shift down by bitCount/32,
// zero-filling the vacated high words.
// FUNCTION: IMPERIALISM 0x005F4540
void ShiftRight96BitIntegerByBitCount(unsigned int* value, int bitCount) {
  int wordShift = bitCount / 32;
  int bitShift = bitCount % 32;
  unsigned int carry = 0;
  int count = 3;
  unsigned int* word = value;
  do {
    unsigned int shifted = *word >> (bitShift & 0x1f) | carry;
    carry = (~(-1 << (bitShift & 0x1f)) & *word) << (0x20 - bitShift & 0x1f);
    *word = shifted;
    count = count - 1;
    word = word + 1;
  } while (count != 0);
  int i = 2;
  int byteOffset = 8;
  do {
    if (i < wordShift) {
      *reinterpret_cast<unsigned int*>(reinterpret_cast<int>(value) + byteOffset) = 0;
    } else {
      *reinterpret_cast<unsigned int*>(reinterpret_cast<int>(value) + byteOffset) =
          *reinterpret_cast<unsigned int*>(reinterpret_cast<int>(value) + byteOffset +
                                           wordShift * -4);
    }
    i = i - 1;
    byteOffset = byteOffset - 4;
  } while (byteOffset >= 0);
}

// Converts an IEEE-754 double to an 80-bit extended float (64-bit mantissa in words 0/1,
// 15-bit exponent + sign in the low half of word 2): rebiases the exponent, expands the
// 52-bit mantissa with its implicit integer bit, and left-normalizes denormals.
// FUNCTION: IMPERIALISM 0x005F4A80
void ConvertFpMantissaTo96BitIntegerAndExponent(unsigned int* out, unsigned int* dbl) {
  unsigned int intBit = 0x80000000;
  unsigned short highWord = *reinterpret_cast<unsigned short*>(reinterpret_cast<int>(dbl) + 6);
  unsigned int lowDword = dbl[0];
  unsigned int expBits = (highWord & 0x7ff0) >> 4;
  int exp;
  if (expBits == 0) {
    intBit = 0;
    if ((dbl[1] & 0xfffff) == 0 && lowDword == 0) {
      out[1] = 0;
      out[0] = 0;
      *reinterpret_cast<unsigned short*>(out + 2) = 0;
      return;
    }
    exp = 0x3c01;
  } else if (expBits == 0x7ff) {
    exp = 0x7fff;
  } else {
    exp = expBits + 0x3c00;
  }
  unsigned short expWord = static_cast<unsigned short>(exp);
  unsigned int mantHi = lowDword >> 0x15 | (dbl[1] & 0xfffff) << 0xb | intBit;
  out[1] = mantHi;
  out[0] = lowDword << 0xb;
  for (; intBit == 0; intBit = intBit & 0x80000000) {
    intBit = mantHi * 2;
    mantHi = out[0] >> 0x1f | intBit;
    exp = exp + 0xffff;
    expWord = static_cast<unsigned short>(exp);
    out[1] = mantHi;
    out[0] = out[0] * 2;
  }
  *reinterpret_cast<unsigned short*>(out + 2) = expWord | highWord & 0x8000;
}

// FUNCTION: IMPERIALISM 0x005F7830
int AddUintWithCarryOutFlag(unsigned int a, unsigned int b, unsigned int* out) {
  int carry = 0;
  unsigned int sum = b + a;
  if (sum < a || sum < b) {
    carry = 1;
  }
  *out = sum;
  return carry;
}

// Adds the 96-bit integer `addend` into `acc` in place (word 0 processed first with full
// carry propagation, then words 1 and 2), using the single-word carry-add helper.
// FUNCTION: IMPERIALISM 0x005F7860
void Add96BitIntegerWithCarry(unsigned int* acc, unsigned int* addend) {
  int carry = AddUintWithCarryOutFlag(acc[0], addend[0], &acc[0]);
  if (carry != 0) {
    carry = AddUintWithCarryOutFlag(acc[1], 1, &acc[1]);
    if (carry != 0) {
      acc[2] = acc[2] + 1;
    }
  }
  carry = AddUintWithCarryOutFlag(acc[1], addend[1], &acc[1]);
  if (carry != 0) {
    acc[2] = acc[2] + 1;
  }
  AddUintWithCarryOutFlag(acc[2], addend[2], &acc[2]);
}

// Copies three consecutive words from `src` to `dest`.

// Shifts the 96-bit integer left by one bit.
// FUNCTION: IMPERIALISM 0x005F78D0
void ShiftLeft96BitIntegerBy1(unsigned int* value) {
  unsigned int w0 = value[0];
  unsigned int w1 = value[1];
  value[0] = w0 * 2;
  value[1] = w1 * 2 | w0 >> 0x1f;
  value[2] = value[2] << 1 | w1 >> 0x1f;
}

// Shifts the 96-bit integer right by one bit.
// FUNCTION: IMPERIALISM 0x005F7900
void ShiftRight96BitIntegerBy1(unsigned int* value) {
  unsigned int w1 = value[1];
  value[1] = w1 >> 1 | value[2] << 0x1f;
  value[2] = value[2] >> 1;
  value[0] = value[0] >> 1 | w1 << 0x1f;
}

// Returns 1 when every bit at or above `bitIndex` (MSB-relative) is zero: the word holding

// Truncates the 96-bit integer to `bitIndex` bits (MSB-relative), rounding to nearest:

// Shifts the 96-bit integer right by `bitCount` bits: first a within-word bit shift by

// Builds a normalized 80-bit extended float from `count` decimal digit bytes: accumulates
// value = value*10 + digit across the 96-bit mantissa (each *10 via <<1,<<1,+self,<<1),
// then left-normalizes so the top mantissa bit is set, tracking the biased exponent.
// FUNCTION: IMPERIALISM 0x005F7930
void Build96BitIntegerFromDigitBytesAndNormalize(char* digits, int count, unsigned int* out) {
  unsigned int* acc = out;
  short exponent = 0x404e;
  out[0] = 0;
  out[1] = 0;
  out[2] = 0;
  if (count != 0) {
    int remaining = count;
    do {
      unsigned int saved[3];
      saved[0] = acc[0];
      saved[1] = acc[1];
      saved[2] = acc[2];
      ShiftLeft96BitIntegerBy1(acc);
      ShiftLeft96BitIntegerBy1(acc);
      Add96BitIntegerWithCarry(acc, saved);
      ShiftLeft96BitIntegerBy1(acc);
      saved[0] = static_cast<unsigned int>(*digits);
      saved[1] = 0;
      saved[2] = 0;
      Add96BitIntegerWithCarry(acc, saved);
      digits = digits + 1;
      remaining = remaining - 1;
    } while (remaining != 0);
  }
  unsigned int top = acc[2];
  while (top == 0) {
    exponent = exponent - 0x10;
    acc[2] = acc[1] >> 0x10;
    top = acc[2];
    acc[1] = acc[0] >> 0x10 | acc[1] << 0x10;
    acc[0] = acc[0] << 0x10;
  }
  top = acc[2];
  while ((top & 0x8000) == 0) {
    ShiftLeft96BitIntegerBy1(acc);
    exponent = exponent - 1;
    top = acc[2];
  }
  *reinterpret_cast<short*>(reinterpret_cast<int>(acc) + 10) = exponent;
}
