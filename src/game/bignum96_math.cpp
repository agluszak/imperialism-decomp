#include "compat.h"

// Big-endian multi-word integer helpers (word 0 is most significant). Used by the
// 96-bit fixed-point accumulators in the strategic scoring/statistics paths.

// Adds two 32-bit words, stores the sum through `out`, and returns the carry-out (1 on
// unsigned overflow, else 0).
int AddUintWithCarryOutFlag(unsigned int a, unsigned int b, unsigned int* out);

// Sets bit `bitIndex` (counted from the most-significant bit of word 0) in the multi-word
// integer at `value`, propagating the carry toward the more-significant (lower-index)
// words.
// FUNCTION: IMPERIALISM 0x005F43E0
void SetBitIn96BitIntegerWithCarry(int* value, int bitIndex) {
  int wordIndex = bitIndex / 32;
  int bitInWord = 0x1f - bitIndex % 32;
  int carry = AddUintWithCarryOutFlag(value[wordIndex], 1 << bitInWord,
                                      reinterpret_cast<unsigned int*>(&value[wordIndex]));
  wordIndex--;
  if (wordIndex >= 0) {
    unsigned int* word = reinterpret_cast<unsigned int*>(&value[wordIndex]);
    do {
      if (carry == 0) {
        return;
      }
      carry = AddUintWithCarryOutFlag(*word, 1, word);
      wordIndex--;
      word--;
    } while (wordIndex >= 0);
  }
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
