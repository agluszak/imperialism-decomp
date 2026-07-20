// Procedural map-context flavor-text builders (BuildMapContextStatusStringVariant*). Each is a
// weighted-grammar expander: pick a token-letter template with a weighted PRNG draw, then walk
// the template and, for each token letter (K/V/k/v/w/l), draw a weighted syllable and append it.
// The syllable/template strings live in the map-context flavor string pool (global_data_tables).

#include "game/mapped_flavor_text.h"

#include "game/CString.h"
#include "game/global_data_tables.h"

namespace {

// One weighted draw over `strings` using per-entry `weights` (weights[0]..weights[n-1] sum to the
// draw range). `range` is the modulus (useMask=false) or mask (useMask=true) applied to the raw
// 15-bit PRNG sample. Advances the shared flavor PRNG once per draw.
inline const char* PickWeighted(const char* const* strings, const int* weights, int range,
                                bool useMask) {
  g_zoneStatusCodePrngSeed_006a5aec = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
  int sample = static_cast<int>((g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 0x7fff);
  int remaining = (useMask ? (sample & range) : (sample % range)) - weights[0];
  int index = 0;
  while (remaining >= 0) {
    index = index + 1;
    remaining = remaining - weights[index];
  }
  return strings[index];
}

// Advance the flavor PRNG twice: the first (intermediate) value drives a boolean
// length-class gate, the second value is stored as the live seed for the following
// no-step count draw. Returns 1 if the gated sample is below `threshold`, else 0.
inline int FlavorGateFlag(int range, int threshold) {
  unsigned int intermediate = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
  int flag = static_cast<int>((intermediate >> 0xc) & 0x7fff) % range < threshold;
  g_zoneStatusCodePrngSeed_006a5aec = intermediate * 0x15a4e35 + 1;
  return flag;
}

// Draw a token count from an interleaved weight array using the CURRENT seed WITHOUT
// advancing it (the gate already advanced it). The returned index counts every entry
// (including zero-weight padding) consumed before the running remainder goes negative.
inline int DrawCountNoStep(const int* weights, int range) {
  int remaining =
      static_cast<int>((g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 0x7fff) % range - weights[0];
  int index = 0;
  while (remaining >= 0) {
    index = index + 1;
    remaining = remaining - weights[index];
  }
  return index;
}

} // namespace

// FUNCTION: IMPERIALISM 0x005c4c60
void BuildMapContextStatusStringVariantA(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[7] = {s_mcflavor_0069ac90, s_mcflavor_0069ac88, s_mcflavor_0069ac80,
                              s_mcflavor_0069ac74, s_mcflavor_0069ac6c, s_mcflavor_0069ac60,
                              s_mcflavor_0069ac5c};
  const int templateWeights[7] = {0x13, 2, 4, 0xd, 2, 1, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x2a, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[20] = {
          s_mcflavor_0069ac58, s_mcflavor_0069ac54,   s_mcflavor_0069ac50, s_mcflavor_0069ac4c,
          s_mcflavor_0069ac48, s_mcflavor_0069ac44,   s_mcflavor_0069ac40, s_mcflavor_0069ac3c,
          s_mcflavor_0069ac38, g_szLiteralL_00694250, s_mcflavor_0069ac30, s_mcflavor_0069ac2c,
          s_mcflavor_0069ac28, s_mcflavor_0069ac24,   s_mcflavor_0069ac20, s_mcflavor_0069ac1c,
          s_mcflavor_0069ac18, s_mcflavor_0069ac14,   s_mcflavor_0069ac10, s_mcflavor_0069ac0c};
      const int weights[20] = {4, 3, 2, 1, 1, 4, 1, 1, 3, 1, 1, 4, 1, 1, 2, 2, 1, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x25, false);
      break;
    }
    case 'V': {
      const char* strings[5] = {s_mcflavor_0069ac08, s_mcflavor_0069ac04, s_mcflavor_0069ac00,
                                s_mcflavor_0069abfc, s_mcflavor_0069abf8};
      const int weights[5] = {1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 5, false);
      break;
    }
    case 'k': {
      const char* strings[40] = {
          s_mcflavor_0069abf4, s_mcflavor_0069abf0, s_mcflavor_0069abec, s_mcflavor_0069abe8,
          s_mcflavor_0069abe4, s_mcflavor_0069abe0, s_mcflavor_0069abdc, s_mcflavor_0069abd8,
          s_mcflavor_0069abd4, s_mcflavor_0069abd0, s_mcflavor_0069abcc, s_mcflavor_0069abc4,
          s_mcflavor_0069abc0, s_mcflavor_0069abbc, s_mcflavor_0069abb8, s_mcflavor_0069abb4,
          s_mcflavor_0069abb0, s_mcflavor_0069abac, s_mcflavor_0069aba8, s_mcflavor_0069aba4,
          s_mcflavor_0069aba0, s_mcflavor_0069ab9c, s_mcflavor_0069ab98, s_mcflavor_0069ab94,
          s_mcflavor_0069ab90, s_mcflavor_0069ab8c, s_mcflavor_0069ab88, g_szLiteralRb_00698720,
          s_mcflavor_0069ab84, s_mcflavor_0069ab80, s_mcflavor_0069ab7c, s_mcflavor_0069ab78,
          s_mcflavor_0069ab74, s_mcflavor_0069ab70, s_mcflavor_0069ab6c, s_mcflavor_0069ab68,
          s_mcflavor_0069ab64, s_mcflavor_0069ab60, s_mcflavor_0069ab5c, s_mcflavor_0069ab58};
      const int weights[40] = {2, 2, 1, 1, 1, 3, 1, 1, 1, 2, 2, 1, 7, 1, 2, 1, 1, 1, 2, 2,
                               2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x3a, false);
      break;
    }
    case 'l': {
      const char* strings[13] = {s_mcflavor_0069ab54, s_mcflavor_0069ab70, s_mcflavor_0069ab50,
                                 s_mcflavor_0069ab4c, s_mcflavor_0069ab48, s_mcflavor_0069ab5c,
                                 s_mcflavor_0069ab44, s_mcflavor_0069ab40, s_mcflavor_00696d10,
                                 s_mcflavor_0069ab3c, s_mcflavor_0069ab38, s_mcflavor_0069ab34,
                                 s_mcflavor_0069ab30};
      const int weights[13] = {9, 0xc, 2, 2, 3, 1, 3, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x26, false);
      break;
    }
    case 'v': {
      const char* strings[12] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab28, s_mcflavor_0069ab24,
                                 s_mcflavor_0069ab20, s_mcflavor_0069ab1c, s_mcflavor_0069ab18,
                                 s_mcflavor_0069ab14, s_mcflavor_0069ab10, s_mcflavor_0069ab0c,
                                 s_mcflavor_0069ab08, s_mcflavor_0069ab04, s_mcflavor_0069ab00};
      const int weights[12] = {0x13, 7, 0x1c, 0xb, 3, 6, 8, 1, 2, 1, 3, 2};
      text = PickWeighted(strings, weights, 0x5b, false);
      break;
    }
    case 'w':
      text = s_mcflavor_0069ab08;
      break;
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005c57f0
void BuildMapContextStatusStringVariantB(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[10] = {s_mcflavor_0069ad14, s_mcflavor_0069ac90, s_mcflavor_0069ac5c,
                               s_mcflavor_0069ac80, s_mcflavor_0069ac74, s_mcflavor_0069ad0c,
                               s_mcflavor_0069ac6c, s_mcflavor_0069ac88, s_mcflavor_0069ad04,
                               s_mcflavor_0069ac60};
  const int templateWeights[10] = {3, 0xc, 1, 5, 6, 2, 1, 2, 2, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x23, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[14] = {s_mcflavor_0069ac10, s_mcflavor_0069ad00, s_mcflavor_0069acfc,
                                 s_mcflavor_0069acf8, s_mcflavor_0069ac44, s_mcflavor_0069ac14,
                                 s_mcflavor_0069ac40, s_mcflavor_0069ac38, s_mcflavor_0069acf4,
                                 s_mcflavor_0069acf0, s_mcflavor_0069ac28, g_szLiteralL_00694250,
                                 s_mcflavor_0069ac24, s_mcflavor_0069acec};
      const int weights[14] = {3, 3, 2, 2, 2, 7, 3, 1, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x1d, false);
      break;
    }
    case 'V': {
      const char* strings[3] = {g_szLiteralA_0069872C, s_mcflavor_0069ace8, s_mcflavor_0069ac00};
      const int weights[3] = {4, 1, 1};
      text = PickWeighted(strings, weights, 6, false);
      break;
    }
    case 'k': {
      const char* strings[25] = {
          s_mcflavor_0069ab40, s_mcflavor_0069ab70, s_mcflavor_0069ace4, s_mcflavor_0069abd0,
          s_mcflavor_0069ab50, s_mcflavor_0069ace0, s_mcflavor_00696d10, s_mcflavor_0069acdc,
          s_mcflavor_0069acd8, s_mcflavor_0069acd4, s_mcflavor_0069acd0, s_mcflavor_0069accc,
          s_mcflavor_0069ab90, s_mcflavor_0069acc8, s_mcflavor_0069ab54, s_mcflavor_0069acc4,
          s_mcflavor_0069acc0, s_mcflavor_0069acbc, s_mcflavor_0069ab98, s_mcflavor_0069acb8,
          s_mcflavor_0069acb4, s_mcflavor_00698b0c, s_mcflavor_0069ab48, s_mcflavor_0069acb0,
          s_mcflavor_0069acac};
      const int weights[25] = {5, 7, 3, 1, 2, 4, 9, 2, 1, 1, 1, 1, 2,
                               1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x35, false);
      break;
    }
    case 'l': {
      const char* strings[3] = {s_mcflavor_0069abd0, s_mcflavor_0069ab70, s_mcflavor_0069ab40};
      const int weights[3] = {0x11, 5, 1};
      text = PickWeighted(strings, weights, 0x17, false);
      break;
    }
    case 'v': {
      const char* strings[7] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab18, s_mcflavor_0069ab20,
                                s_mcflavor_0069aca8, s_mcflavor_0069aca4, s_mcflavor_0069aca0,
                                s_mcflavor_0069ab24};
      const int weights[7] = {0xe, 0x19, 0x16, 3, 1, 1, 4};
      text = PickWeighted(strings, weights, 0x46, false);
      break;
    }
    case 'w': {
      const char* strings[4] = {s_mcflavor_0069ab2c, s_mcflavor_0069ac9c, s_mcflavor_0069ab20,
                                s_mcflavor_0069ac98};
      const int weights[4] = {6, 2, 3, 1};
      text = PickWeighted(strings, weights, 0xc, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005c61a0
void BuildMapContextStatusStringVariantC(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[8] = {s_mcflavor_0069ad84, s_mcflavor_0069ad78, s_mcflavor_0069ad70,
                              s_mcflavor_0069ad68, s_mcflavor_0069ad60, s_mcflavor_0069ad58,
                              s_mcflavor_0069ac90, s_mcflavor_0069ac80};
  const int templateWeights[8] = {7, 0xa, 8, 1, 1, 1, 2, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x1f, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case '/':
      text = s_szSpaceSeparator_00695794;
      break;
    case 'G': {
      const char* strings[14] = {s_mcflavor_0069ac1c, s_mcflavor_0069ac58, g_szLiteralL_00694250,
                                 s_mcflavor_0069ac0c, s_mcflavor_0069ac38, s_mcflavor_0069ad00,
                                 s_mcflavor_0069acf4, s_mcflavor_0069ad54, s_mcflavor_0069acec,
                                 s_mcflavor_0069ad50, s_mcflavor_0069ac24, s_mcflavor_0069ac54,
                                 s_mcflavor_0069ad4c, s_mcflavor_0069ac44};
      const int weights[14] = {1, 3, 5, 3, 1, 1, 2, 2, 2, 1, 3, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x1b, false);
      break;
    }
    case 'K': {
      const char* strings[14] = {s_mcflavor_0069ac38, s_mcflavor_0069acfc, s_mcflavor_0069ad48,
                                 s_mcflavor_0069ac28, s_mcflavor_0069ac1c, s_mcflavor_0069ac0c,
                                 s_mcflavor_0069ad4c, s_mcflavor_0069ad54, s_mcflavor_0069ac58,
                                 s_mcflavor_0069ac10, s_mcflavor_0069ad00, s_mcflavor_0069ac24,
                                 s_mcflavor_0069ac54, s_mcflavor_0069ad44};
      const int weights[14] = {1, 1, 4, 3, 1, 4, 2, 1, 6, 2, 1, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x1e, false);
      break;
    }
    case 'R':
    case 'V':
      text = g_szLiteralA_0069872C;
      break;
    case 'j': {
      const char* strings[7] = {s_mcflavor_0069ab3c, s_mcflavor_0069abcc, s_mcflavor_0069ab70,
                                s_mcflavor_0069abc0, s_mcflavor_0069ab48, s_mcflavor_0069ad40,
                                s_mcflavor_0069ad3c};
      const int weights[7] = {1, 5, 5, 3, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x12, false);
      break;
    }
    case 'k': {
      const char* strings[3] = {s_mcflavor_0069abb4, s_mcflavor_0069ab70, s_mcflavor_0069ad38};
      const int weights[3] = {1, 1, 1};
      text = PickWeighted(strings, weights, 3, false);
      break;
    }
    case 'l': {
      const char* strings[7] = {s_mcflavor_0069abc0, s_mcflavor_0069abcc, s_mcflavor_0069ad3c,
                                s_mcflavor_0069ab70, s_mcflavor_0069ad40, s_mcflavor_0069ad34,
                                s_mcflavor_0069ab48};
      const int weights[7] = {8, 6, 1, 4, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x16, false);
      break;
    }
    case 'u': {
      const char* strings[6] = {s_mcflavor_0069ac9c, s_mcflavor_0069ab2c, s_mcflavor_0069ad30,
                                s_mcflavor_0069ad2c, s_mcflavor_0069ad28, s_mcflavor_0069ab18};
      const int weights[6] = {1, 5, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 10, false);
      break;
    }
    case 'v': {
      const char* strings[7] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab28, s_mcflavor_0069ad24,
                                s_mcflavor_0069ab18, s_mcflavor_0069ab20, s_mcflavor_0069ab00,
                                s_mcflavor_0069ac98};
      const int weights[7] = {0xe, 2, 3, 9, 9, 2, 2};
      text = PickWeighted(strings, weights, 0x29, false);
      break;
    }
    case 'w': {
      const char* strings[6] = {s_mcflavor_0069ac9c, s_mcflavor_0069ad28, s_mcflavor_0069ac98,
                                s_mcflavor_0069ab20, s_mcflavor_0069ad20, s_mcflavor_0069ab2c};
      const int weights[6] = {1, 3, 2, 1, 1, 1};
      text = PickWeighted(strings, weights, 9, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005c6c40
void BuildMapContextStatusStringVariantD(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[12] = {s_mcflavor_0069ac6c, s_mcflavor_0069ac88, s_mcflavor_0069ad04,
                               s_mcflavor_0069ac80, s_mcflavor_0069ac90, s_mcflavor_0069ad0c,
                               s_mcflavor_0069ac74, s_mcflavor_0069ac60, s_mcflavor_0069ae24,
                               s_mcflavor_0069ad14, s_mcflavor_0069ae18, s_mcflavor_0069ae14};
  const int templateWeights[12] = {5, 6, 4, 6, 6, 3, 3, 2, 2, 1, 1, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x28, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[11] = {s_mcflavor_0069ac14, s_mcflavor_0069ac54, s_mcflavor_0069ac1c,
                                 s_mcflavor_0069acf0, s_mcflavor_0069ad44, s_mcflavor_0069ac44,
                                 s_mcflavor_0069ac10, s_mcflavor_0069ac38, s_mcflavor_0069ac48,
                                 s_mcflavor_0069ac28, s_mcflavor_0069acec};
      const int weights[11] = {2, 3, 4, 1, 1, 2, 4, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x15, false);
      break;
    }
    case 'V': {
      const char* strings[9] = {s_mcflavor_0069abfc,   s_mcflavor_0069ac00, s_mcflavor_0069ae10,
                                g_szLiteralA_0069872C, s_mcflavor_0069abf8, s_mcflavor_0069ae0c,
                                s_mcflavor_0069ae08,   s_mcflavor_0069ae04, s_mcflavor_0069ae00};
      const int weights[9] = {1, 4, 1, 6, 1, 1, 3, 1, 1};
      text = PickWeighted(strings, weights, 0x13, false);
      break;
    }
    case 'k': {
      const char* strings[39] = {
          s_mcflavor_0069adfc, s_mcflavor_0069aba4, s_mcflavor_0069adf8, s_mcflavor_0069abb8,
          s_mcflavor_00696d10, s_mcflavor_0069adf4, s_mcflavor_0069adf0, s_mcflavor_0069adec,
          s_mcflavor_0069ade8, s_mcflavor_0069ade4, s_mcflavor_0069ab48, s_mcflavor_0069ade0,
          s_mcflavor_0069abc0, s_mcflavor_0069addc, s_mcflavor_0069add8, s_mcflavor_0069abd0,
          s_mcflavor_0069add4, s_mcflavor_0069add0, s_mcflavor_0069adcc, s_mcflavor_0069adc8,
          s_mcflavor_0069adc4, s_mcflavor_0069adc0, s_mcflavor_0069ab70, s_mcflavor_0069adbc,
          s_mcflavor_0069ab40, s_mcflavor_0069adb8, s_mcflavor_0069ab98, s_mcflavor_0069adb4,
          s_mcflavor_0069adb0, s_mcflavor_0069ace4, s_mcflavor_0069adac, s_mcflavor_0069ace0,
          s_mcflavor_0069ada8, s_mcflavor_0069ab7c, s_mcflavor_0069ada4, s_mcflavor_0069ab9c,
          s_mcflavor_0069ada0, s_mcflavor_0069acc0, s_mcflavor_0069ab4c};
      const int weights[39] = {3, 4, 2, 1, 5, 1, 1, 2, 2, 1, 3, 1, 1, 1, 2, 4, 3, 1, 1, 1,
                               1, 2, 1, 1, 6, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x43, false);
      break;
    }
    case 'l': {
      const char* strings[9] = {s_mcflavor_00696d10, s_mcflavor_0069ad3c, s_mcflavor_0069ace4,
                                s_mcflavor_0069adc4, s_mcflavor_0069ad40, s_mcflavor_0069ab70,
                                s_mcflavor_0069ab48, s_mcflavor_0069ab50, s_mcflavor_0069abd0};
      const int weights[9] = {8, 2, 4, 1, 2, 3, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x17, false);
      break;
    }
    case 'v': {
      const char* strings[9] = {s_mcflavor_0069ab1c, s_mcflavor_0069ab2c, s_mcflavor_0069ab20,
                                s_mcflavor_0069ab28, s_mcflavor_0069ab24, s_mcflavor_0069ab18,
                                s_mcflavor_0069ad9c, s_mcflavor_0069ab04, s_mcflavor_0069ad98};
      const int weights[9] = {5, 0x19, 0x11, 9, 9, 2, 1, 2, 1};
      text = PickWeighted(strings, weights, 0x47, false);
      break;
    }
    case 'w': {
      const char* strings[6] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab24, s_mcflavor_0069ab1c,
                                s_mcflavor_0069ad94, s_mcflavor_0069ad90, s_mcflavor_0069ad8c};
      const int weights[6] = {7, 3, 2, 2, 2, 1};
      text = PickWeighted(strings, weights, 0x11, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005c77f0
void BuildMapContextStatusStringVariantE(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[9] = {s_mcflavor_0069ac74, s_mcflavor_0069ac90, s_mcflavor_0069ac6c,
                              s_mcflavor_0069ac80, s_mcflavor_0069ac5c, s_mcflavor_0069ae14,
                              s_mcflavor_0069ad14, s_mcflavor_0069ad04, s_mcflavor_0069ae24};
  const int templateWeights[9] = {4, 8, 3, 7, 1, 1, 5, 5, 2};
  const char* p = PickWeighted(templates, templateWeights, 0x24, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[15] = {s_mcflavor_0069ac10, s_mcflavor_0069ac40, s_mcflavor_0069ac14,
                                 s_mcflavor_0069ac54, s_mcflavor_0069ac18, s_mcflavor_0069ae78,
                                 s_mcflavor_0069ae74, s_mcflavor_0069ac24, s_mcflavor_0069ae70,
                                 s_mcflavor_0069ac1c, s_mcflavor_0069ae6c, s_mcflavor_0069ac0c,
                                 s_mcflavor_0069ac38, s_mcflavor_0069ac44, s_mcflavor_0069ae68};
      const int weights[15] = {3, 3, 5, 1, 4, 1, 1, 2, 1, 2, 1, 2, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x1e, false);
      break;
    }
    case 'V': {
      const char* strings[3] = {g_szLiteralA_0069872C, s_mcflavor_0069ae64, s_mcflavor_0069ac00};
      const int weights[3] = {2, 1, 3};
      text = PickWeighted(strings, weights, 6, false);
      break;
    }
    case 'k': {
      const char* strings[28] = {
          s_mcflavor_00696d10, s_mcflavor_0069ad3c, s_mcflavor_0069ae60, s_mcflavor_0069adf0,
          s_mcflavor_0069adac, s_mcflavor_0069abd0, s_mcflavor_0069ab48, s_mcflavor_0069ae5c,
          s_mcflavor_0069ae58, s_mcflavor_0069ae54, s_mcflavor_0069add8, s_mcflavor_0069ade8,
          s_mcflavor_0069ab34, s_mcflavor_0069acc0, s_mcflavor_0069ab3c, s_mcflavor_0069ab40,
          s_mcflavor_0069acbc, s_mcflavor_0069ab70, s_mcflavor_0069adb8, s_mcflavor_0069ab50,
          s_mcflavor_0069abf0, s_mcflavor_0069ae50, s_mcflavor_0069acd8, s_mcflavor_0069acc8,
          s_mcflavor_0069ae4c, s_mcflavor_0069aba4, s_mcflavor_0069ae48, s_mcflavor_0069ae44};
      const int weights[28] = {3, 3, 2, 1, 1, 1, 6, 1, 1, 1, 8, 3, 1, 1,
                               2, 3, 1, 5, 1, 1, 1, 7, 1, 1, 1, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x3d, false);
      break;
    }
    case 'l': {
      const char* strings[5] = {s_mcflavor_0069add8, s_mcflavor_0069ae40, s_mcflavor_0069ae3c,
                                s_mcflavor_0069ae38, s_mcflavor_0069adfc};
      const int weights[5] = {7, 3, 3, 2, 1};
      text = PickWeighted(strings, weights, 0xf, true);
      break;
    }
    case 'v': {
      const char* strings[8] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab18, s_mcflavor_0069ab24,
                                s_mcflavor_0069ab28, s_mcflavor_0069ab20, s_mcflavor_0069ad34,
                                s_mcflavor_0069ad98, s_mcflavor_0069ad90};
      const int weights[8] = {0xe, 0x1e, 0xd, 4, 6, 1, 1, 2};
      text = PickWeighted(strings, weights, 0x47, false);
      break;
    }
    case 'w': {
      const char* strings[7] = {s_mcflavor_0069ad34, s_mcflavor_0069ad8c, s_mcflavor_0069ab2c,
                                s_mcflavor_0069ae34, s_mcflavor_0069ab20, s_mcflavor_0069ab18,
                                s_mcflavor_0069ae30};
      const int weights[7] = {1, 2, 9, 1, 2, 2, 3};
      text = PickWeighted(strings, weights, 0x14, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005c81f0
void BuildMapContextStatusStringVariantF(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[7] = {s_mcflavor_0069af0c, s_mcflavor_0069af08, s_mcflavor_0069af00,
                              s_mcflavor_0069aef8, s_mcflavor_0069aeec, s_mcflavor_0069aee4,
                              s_mcflavor_0069aee0};
  const int templateWeights[7] = {1, 2, 1, 0x16, 5, 0x10, 4};
  const char* p = PickWeighted(templates, templateWeights, 0x33, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'C': {
      const char* strings[7] = {g_szLiteralL_00694250, s_mcflavor_0069ac2c, s_mcflavor_0069ac24,
                                s_mcflavor_0069ac40,   s_mcflavor_0069ac44, s_mcflavor_0069ac14,
                                s_mcflavor_0069ac58};
      const int weights[7] = {2, 3, 3, 0xa, 5, 0xe, 0xa};
      text = PickWeighted(strings, weights, 0x2f, false);
      break;
    }
    case 'V': {
      const char* strings[3] = {s_mcflavor_0069aedc, g_szLiteralA_0069872C, s_mcflavor_0069aed8};
      const int weights[3] = {1, 2, 1};
      text = PickWeighted(strings, weights, 3, true);
      break;
    }
    case 'c': {
      const char* strings[7] = {s_mcflavor_00697238, s_mcflavor_0069ab48, s_mcflavor_0069ab70,
                                s_mcflavor_0069acc8, s_mcflavor_0069ace4, s_mcflavor_0069ab40,
                                s_mcflavor_0069add4};
      const int weights[7] = {1, 2, 0xa, 0xe, 9, 0x1b, 0xd};
      text = PickWeighted(strings, weights, 0x4c, false);
      break;
    }
    case 'u': {
      const char* strings[23] = {
          s_mcflavor_0069ab20, s_mcflavor_0069ac9c, s_mcflavor_0069aea0, s_mcflavor_0069ac98,
          s_mcflavor_0069ae98, s_mcflavor_0069ae94, s_mcflavor_0069ae90, s_mcflavor_0069aec8,
          s_mcflavor_0069aca8, s_mcflavor_0069aec0, s_mcflavor_0069ad24, s_mcflavor_0069ab28,
          s_mcflavor_0069ae88, s_mcflavor_0069ae84, s_mcflavor_0069ae80, s_mcflavor_0069aed0,
          s_mcflavor_0069ab24, s_mcflavor_0069ad20, s_mcflavor_0069ab18, s_mcflavor_0069ab08,
          s_mcflavor_0069aeb4, s_mcflavor_0069ab2c, s_mcflavor_0069ae7c};
      const int weights[23] = {1, 1, 1, 2, 1, 1, 1, 1, 1, 1,   3, 4,
                               1, 1, 1, 1, 1, 4, 5, 2, 2, 0xe, 1};
      text = PickWeighted(strings, weights, 0x33, false);
      break;
    }
    case 'v': {
      const char* strings[19] = {
          s_mcflavor_0069aed4, s_mcflavor_0069aed0, s_mcflavor_0069aecc, s_mcflavor_0069aec8,
          s_mcflavor_0069ad24, s_mcflavor_0069ab28, s_mcflavor_0069aec4, s_mcflavor_0069aec0,
          s_mcflavor_0069aebc, s_mcflavor_0069aeb8, s_mcflavor_0069ab24, s_mcflavor_0069ab20,
          s_mcflavor_0069aeb4, s_mcflavor_0069aeac, s_mcflavor_0069aea8, s_mcflavor_0069ac98,
          s_mcflavor_0069ab08, s_mcflavor_0069ab2c, s_mcflavor_0069ab18};
      const int weights[19] = {1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 4, 3, 2, 1, 1, 5, 2, 0x1d, 0xc};
      text = PickWeighted(strings, weights, 0x48, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005c8ae0
void BuildMapContextStatusStringVariantG(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[18] = {s_mcflavor_0069b010, s_mcflavor_0069ad60, s_mcflavor_0069b004,
                               s_mcflavor_0069aff4, s_mcflavor_0069ac5c, s_mcflavor_0069ac88,
                               s_mcflavor_0069ac90, s_mcflavor_0069ad04, s_mcflavor_0069afec,
                               s_mcflavor_0069afdc, s_mcflavor_0069afd0, s_mcflavor_0069ac74,
                               s_mcflavor_0069ac80, s_mcflavor_0069afc0, s_mcflavor_0069afb0,
                               s_mcflavor_0069ae14, s_mcflavor_0069ac6c, s_mcflavor_0069afa0};
  const int templateWeights[18] = {4, 3, 0xb, 1, 5, 3, 9, 1, 1, 6, 1, 1, 3, 1, 1, 1, 1, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x36, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case '/':
      text = s_szSpaceSeparator_00695794;
      break;
    case 'G': {
      const char* strings[14] = {s_mcflavor_0069ac38, s_mcflavor_0069ac58, s_mcflavor_0069ac44,
                                 s_mcflavor_0069acf0, s_mcflavor_0069ac10, s_mcflavor_0069af9c,
                                 s_mcflavor_0069ac14, s_mcflavor_0069acec, s_mcflavor_0069ae74,
                                 s_mcflavor_0069af98, s_mcflavor_0069ac0c, g_szLiteralL_00694250,
                                 s_mcflavor_0069ac54, s_mcflavor_0069ad48};
      const int weights[14] = {1, 4, 7, 1, 4, 1, 1, 1, 1, 1, 2, 1, 1, 2};
      text = PickWeighted(strings, weights, 0x1c, false);
      break;
    }
    case 'K': {
      const char* strings[12] = {s_mcflavor_0069ac44, s_mcflavor_0069af98, s_mcflavor_0069ac10,
                                 s_mcflavor_0069ac0c, s_mcflavor_0069ac38, g_szLiteralL_00694250,
                                 s_mcflavor_0069af94, s_mcflavor_0069ad48, s_mcflavor_0069af9c,
                                 s_mcflavor_0069ac48, s_mcflavor_0069ac58, s_mcflavor_0069acec};
      const int weights[12] = {4, 3, 2, 1, 2, 2, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x14, false);
      break;
    }
    case 'R': {
      const char* strings[2] = {g_szLiteralA_0069872C, s_mcflavor_0069af90};
      const int weights[2] = {1, 1};
      text = PickWeighted(strings, weights, 1, true);
      break;
    }
    case 'V': {
      const char* strings[3] = {g_szLiteralA_0069872C, s_mcflavor_0069ac00, s_mcflavor_0069af8c};
      const int weights[3] = {0x1f, 1, 2};
      text = PickWeighted(strings, weights, 0x22, false);
      break;
    }
    case 'j': {
      const char* strings[6] = {s_mcflavor_00696d10, s_mcflavor_0069ab40, s_mcflavor_0069abd0,
                                s_mcflavor_0069ad3c, s_mcflavor_0069af88, s_mcflavor_0069aba4};
      const int weights[6] = {1, 0xf, 5, 3, 1, 4};
      text = PickWeighted(strings, weights, 0x1d, false);
      break;
    }
    case 'k': {
      const char* strings[38] = {
          s_mcflavor_0069af84, s_mcflavor_0069af80,    s_mcflavor_0069af7c, s_mcflavor_0069af78,
          s_mcflavor_0069af74, g_szLiteralRb_00698720, s_mcflavor_00696d10, s_mcflavor_0069af70,
          s_mcflavor_0069add4, s_mcflavor_0069aba4,    s_mcflavor_0069ab9c, s_mcflavor_0069af6c,
          s_mcflavor_0069adc4, s_mcflavor_0069acbc,    s_mcflavor_0069af68, s_mcflavor_0069ab40,
          s_mcflavor_006976e0, s_mcflavor_0069ace4,    s_mcflavor_0069af64, s_mcflavor_0069ab70,
          s_mcflavor_0069adb4, s_mcflavor_0069ad34,    s_mcflavor_0069af60, s_mcflavor_0069af5c,
          s_mcflavor_0069ae34, s_mcflavor_0069af88,    s_mcflavor_0069af58, s_mcflavor_0069af54,
          s_mcflavor_0069af50, s_mcflavor_0069adbc,    s_mcflavor_0069af4c, s_mcflavor_0069af48,
          s_mcflavor_0069af44, s_mcflavor_0069af40,    s_mcflavor_0069aba8, s_mcflavor_0069af3c,
          s_mcflavor_0069ab90, s_mcflavor_0069af38};
      const int weights[38] = {1, 1, 1, 1, 2, 1, 4, 2, 2, 3, 6, 1, 1, 3, 1, 4, 1, 2, 1,
                               3, 1, 1, 2, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x3e, false);
      break;
    }
    case 'l': {
      const char* strings[18] = {s_mcflavor_0069ae4c, s_mcflavor_0069af74, s_mcflavor_0069af34,
                                 s_mcflavor_0069add8, s_mcflavor_0069aba4, s_mcflavor_0069af88,
                                 s_mcflavor_0069ab70, s_mcflavor_0069ab9c, s_mcflavor_0069add4,
                                 s_mcflavor_0069ace4, s_mcflavor_00696d10, s_mcflavor_0069af30,
                                 s_mcflavor_0069acbc, s_mcflavor_0069ab48, s_mcflavor_0069adc4,
                                 s_mcflavor_0069ab40, s_mcflavor_0069abd0, s_mcflavor_0069af2c};
      const int weights[18] = {1, 3, 1, 1, 2, 1, 5, 1, 0x11, 2, 1, 1, 1, 2, 1, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x2c, false);
      break;
    }
    case 'u': {
      const char* strings[1] = {s_mcflavor_0069ab28};
      const int weights[1] = {1};
      text = PickWeighted(strings, weights, 1, false);
      break;
    }
    case 'v': {
      const char* strings[9] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab20, s_mcflavor_0069ab18,
                                s_mcflavor_0069af28, s_mcflavor_0069af24, s_mcflavor_0069af20,
                                s_mcflavor_0069ab28, s_mcflavor_0069af1c, s_mcflavor_0069ad24};
      const int weights[9] = {0x3f, 0xe, 2, 4, 1, 2, 10, 2, 1};
      text = PickWeighted(strings, weights, 0x63, false);
      break;
    }
    case 'w': {
      const char* strings[4] = {s_mcflavor_0069ab2c, s_mcflavor_0069ad24, s_mcflavor_0069ab20,
                                s_mcflavor_0069af18};
      const int weights[4] = {7, 1, 1, 1};
      text = PickWeighted(strings, weights, 0xa, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005c9b20
void BuildMapContextStatusStringVariantH(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[5] = {s_mcflavor_0069ac80, s_mcflavor_0069ac90, s_mcflavor_0069ad04,
                              s_mcflavor_0069ac74, s_mcflavor_0069ae18};
  const int templateWeights[5] = {0x2a, 0x28, 8, 0xe, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x69, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[18] = {s_mcflavor_0069af98, s_mcflavor_00696674, g_szLiteralL_00694250,
                                 s_mcflavor_0069b0a4, s_mcflavor_0069ac44, s_mcflavor_0069ac54,
                                 s_mcflavor_0069ac58, s_mcflavor_0069ac2c, s_mcflavor_0069acec,
                                 s_mcflavor_0069ac1c, s_mcflavor_0069b0a0, s_mcflavor_0069ae74,
                                 s_mcflavor_0069ac10, s_mcflavor_0069ac14, s_mcflavor_0069ad48,
                                 s_mcflavor_0069ac48, s_mcflavor_0069ac24, s_mcflavor_0069af9c};
      const int weights[18] = {10, 0xd, 9, 7, 4, 4, 6, 5, 8, 6, 3, 6, 5, 2, 3, 4, 6, 4};
      text = PickWeighted(strings, weights, 0x69, false);
      break;
    }
    case 'k': {
      const char* strings[49] = {
          s_mcflavor_0069adc4, s_mcflavor_0069b09c, s_mcflavor_0069b098, s_mcflavor_0069b090,
          s_mcflavor_00698b0c, s_mcflavor_0069af38, s_mcflavor_0069b08c, s_mcflavor_0069add4,
          s_mcflavor_0069b088, s_mcflavor_0069ab3c, s_mcflavor_0069af88, s_mcflavor_0069b084,
          s_mcflavor_0069ab40, s_mcflavor_0069b07c, s_mcflavor_0069b078, s_mcflavor_0069b070,
          s_mcflavor_0069b06c, s_mcflavor_0069b068, s_mcflavor_0069aba4, s_mcflavor_0069abb8,
          s_mcflavor_0069b064, s_mcflavor_0069b060, s_mcflavor_00697238, s_mcflavor_0069ad3c,
          s_mcflavor_0069acbc, s_mcflavor_0069abc0, s_mcflavor_0069ad34, s_mcflavor_0069ada8,
          s_mcflavor_0069b05c, s_mcflavor_0069ab9c, s_mcflavor_0069b058, s_mcflavor_0069b054,
          s_mcflavor_0069b050, s_mcflavor_0069ad40, s_mcflavor_0069ab38, s_mcflavor_0069b04c,
          s_mcflavor_0069b048, s_mcflavor_0069b044, s_mcflavor_0069b040, s_mcflavor_0069b03c,
          s_mcflavor_0069abcc, s_mcflavor_0069b038, s_mcflavor_0069ab60, s_mcflavor_0069b034,
          s_mcflavor_0069b030, s_mcflavor_0069ab48, s_mcflavor_0069b02c, s_mcflavor_0069abd0,
          s_mcflavor_0069ace4};
      const int weights[49] = {1, 4, 5, 5, 4, 6, 1, 5, 6, 1, 6, 3, 6, 4, 5, 1, 7,
                               2, 4, 1, 2, 1, 2, 2, 2, 2, 2, 1, 3, 3, 4, 2, 1, 1,
                               1, 1, 1, 4, 1, 1, 1, 4, 1, 1, 2, 2, 1, 1, 2};
      text = PickWeighted(strings, weights, 0x81, false);
      break;
    }
    case 'l': {
      const char* strings[2] = {s_mcflavor_0069abc0, s_mcflavor_0069ab70};
      const int weights[2] = {0x21, 0x16};
      text = PickWeighted(strings, weights, 0x37, false);
      break;
    }
    case 'v': {
      const char* strings[17] = {s_mcflavor_0069b028, s_mcflavor_0069ab20, s_mcflavor_0069ac9c,
                                 s_mcflavor_0069ab2c, s_mcflavor_0069ab24, s_mcflavor_0069ab14,
                                 s_mcflavor_0069b024, s_mcflavor_0069ab28, s_mcflavor_0069ab00,
                                 s_mcflavor_0069ad24, s_mcflavor_0069ab18, s_mcflavor_0069b020,
                                 s_mcflavor_0069ac98, s_mcflavor_0069ad30, s_mcflavor_0069b01c,
                                 s_mcflavor_0069ae84, s_mcflavor_0069aca8};
      const int weights[17] = {2, 0x20, 0x15, 0x34, 0x15, 6, 2, 0x13, 1, 4, 9, 3, 6, 3, 1, 1, 1};
      text = PickWeighted(strings, weights, 0xb8, false);
      break;
    }
    case 'w': {
      const char* strings[14] = {s_mcflavor_0069b024, s_mcflavor_0069ae84, s_mcflavor_0069b028,
                                 s_mcflavor_0069ab24, s_mcflavor_0069ab28, s_mcflavor_0069ab20,
                                 s_mcflavor_0069ab2c, s_mcflavor_0069b020, s_mcflavor_0069ad30,
                                 s_mcflavor_0069ac98, s_mcflavor_0069ab14, s_mcflavor_0069ab18,
                                 s_mcflavor_0069ad24, s_mcflavor_0069ac9c};
      const int weights[14] = {2, 0xe, 3, 2, 7, 9, 1, 1, 1, 3, 3, 1, 2, 1};
      text = PickWeighted(strings, weights, 0x32, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005ca860
void BuildMapContextStatusStringVariantI(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[7] = {s_mcflavor_0069ad04, s_mcflavor_0069ad0c, s_mcflavor_0069ae24,
                              s_mcflavor_0069ac80, s_mcflavor_0069ad14, s_mcflavor_0069ae14,
                              s_mcflavor_0069b0c8};
  const int templateWeights[7] = {0xc, 6, 6, 0xd, 7, 2, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x2f, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[11] = {s_mcflavor_0069ac58, s_mcflavor_0069ac44, s_mcflavor_0069ac24,
                                 s_mcflavor_0069ac48, s_mcflavor_0069ac10, s_mcflavor_0069b0a0,
                                 s_mcflavor_0069acec, s_mcflavor_0069ac1c, s_mcflavor_0069ac14,
                                 s_mcflavor_0069ae74, s_mcflavor_0069ac2c};
      const int weights[11] = {3, 3, 4, 3, 2, 1, 5, 2, 6, 3, 1};
      text = PickWeighted(strings, weights, 0x21, false);
      break;
    }
    case 'V': {
      const char* strings[8] = {s_mcflavor_0069b0c4, g_szLiteralA_0069872C, s_mcflavor_0069ac00,
                                s_mcflavor_0069ae0c, s_mcflavor_0069b0c0,   s_mcflavor_0069b0bc,
                                s_mcflavor_0069abf8, s_mcflavor_0069b0b8};
      const int weights[8] = {1, 1, 3, 3, 1, 3, 1, 1};
      text = PickWeighted(strings, weights, 0xe, false);
      break;
    }
    case 'k': {
      const char* strings[18] = {s_mcflavor_0069adbc, s_mcflavor_0069aba4, s_mcflavor_0069ab48,
                                 s_mcflavor_00696d10, s_mcflavor_0069ace4, s_mcflavor_0069ad3c,
                                 s_mcflavor_00697238, s_mcflavor_0069abb4, s_mcflavor_0069af88,
                                 s_mcflavor_0069ab9c, s_mcflavor_0069ab3c, s_mcflavor_0069b03c,
                                 s_mcflavor_0069ab70, s_mcflavor_0069adc4, s_mcflavor_0069acbc,
                                 s_mcflavor_0069abd0, s_mcflavor_0069ab5c, s_mcflavor_0069add4};
      const int weights[18] = {1, 1, 0x10, 5, 0x10, 8, 5, 0xd, 6, 2, 4, 1, 5, 2, 1, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x5a, false);
      break;
    }
    case 'v': {
      const char* strings[11] = {s_mcflavor_0069ab18, s_mcflavor_0069ac98, s_mcflavor_0069ab20,
                                 s_mcflavor_0069ab2c, s_mcflavor_0069b0b4, s_mcflavor_0069b0b0,
                                 s_mcflavor_0069ab28, s_mcflavor_0069b0ac, s_mcflavor_0069b024,
                                 s_mcflavor_0069b0a8, s_mcflavor_0069ae30};
      const int weights[11] = {0xb, 2, 0xf, 0x1e, 2, 1, 8, 1, 2, 2, 2};
      text = PickWeighted(strings, weights, 0x4c, false);
      break;
    }
    case 'w': {
      const char* strings[8] = {s_mcflavor_0069ab18, s_mcflavor_0069ab20, s_mcflavor_0069ab2c,
                                s_mcflavor_0069ab24, s_mcflavor_0069b0a8, s_mcflavor_0069ab28,
                                s_mcflavor_0069ad30, s_mcflavor_0069ab00};
      const int weights[8] = {5, 0xb, 0x18, 3, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x2f, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005cb100
void BuildMapContextStatusStringVariantJ(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[5] = {s_mcflavor_0069ac80, s_mcflavor_0069ac90, s_mcflavor_0069ae14,
                              s_mcflavor_0069ac88, s_mcflavor_0069ac5c};
  const int templateWeights[5] = {0x10, 0x11, 1, 5, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x28, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[10] = {s_mcflavor_0069ac2c, s_mcflavor_0069b0a0, s_mcflavor_0069ac40,
                                 s_mcflavor_0069ac44, s_mcflavor_0069ac24, s_mcflavor_0069b0c8,
                                 s_mcflavor_0069ac10, s_mcflavor_0069ac14, s_mcflavor_0069acec,
                                 s_mcflavor_0069b0e4};
      const int weights[10] = {2, 9, 3, 1, 1, 1, 6, 8, 2, 1};
      text = PickWeighted(strings, weights, 0x22, false);
      break;
    }
    case 'V': {
      const char* strings[4] = {s_mcflavor_0069ae10, s_mcflavor_0069ae08, g_szLiteralA_0069872C,
                                s_mcflavor_0069ae0c};
      const int weights[4] = {1, 3, 1, 1};
      text = PickWeighted(strings, weights, 6, false);
      break;
    }
    case 'k': {
      const char* strings[22] = {
          s_mcflavor_0069abb8, s_mcflavor_0069abd0, s_mcflavor_0069b0e0, s_mcflavor_0069af38,
          s_mcflavor_0069b054, s_mcflavor_0069ab60, s_mcflavor_0069ab70, s_mcflavor_0069b060,
          s_mcflavor_0069abb4, s_mcflavor_0069b0dc, s_mcflavor_0069abcc, s_mcflavor_0069b030,
          s_mcflavor_0069add4, s_mcflavor_00696d10, s_mcflavor_0069b0d8, s_mcflavor_0069b0d4,
          s_mcflavor_0069b08c, s_mcflavor_0069b0d0, s_mcflavor_0069abc0, s_mcflavor_0069b0cc,
          s_mcflavor_0069ada0, s_mcflavor_0069ab3c};
      const int weights[22] = {3, 4, 1, 2, 4, 2, 2, 1, 1, 2, 1, 4, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x27, false);
      break;
    }
    case 'l': {
      const char* strings[4] = {s_mcflavor_0069abc0, s_mcflavor_0069ab70, s_mcflavor_0069ace4,
                                s_mcflavor_0069ab40};
      const int weights[4] = {8, 0xd, 1, 1};
      text = PickWeighted(strings, weights, 0x17, false);
      break;
    }
    case 'v': {
      const char* strings[9] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab20, s_mcflavor_0069ab18,
                                s_mcflavor_0069ab28, s_mcflavor_0069ad8c, s_mcflavor_0069aecc,
                                s_mcflavor_0069b0a8, s_mcflavor_0069ae84, s_mcflavor_0069ab24};
      const int weights[9] = {0xf, 4, 0x14, 8, 2, 3, 2, 1, 1};
      text = PickWeighted(strings, weights, 0x38, false);
      break;
    }
    case 'w': {
      const char* strings[3] = {s_mcflavor_0069ab18, s_mcflavor_0069ab28, s_mcflavor_0069aecc};
      const int weights[3] = {3, 0xd, 1};
      text = PickWeighted(strings, weights, 0x11, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005cb960
void BuildMapContextStatusStringVariantK(CString* out) {
  *out = CString(g_szEmptyString);
  const char* templates[15] = {s_mcflavor_0069ac90, s_mcflavor_0069ac88, s_mcflavor_0069ac74,
                               s_mcflavor_0069ac80, s_mcflavor_0069ac60, s_mcflavor_0069ad0c,
                               s_mcflavor_0069ae24, s_mcflavor_0069ac6c, s_mcflavor_0069b14c,
                               s_mcflavor_0069ae18, s_mcflavor_0069ad04, s_mcflavor_0069ad14,
                               s_mcflavor_0069ac5c, s_mcflavor_0069b13c, s_mcflavor_0069ae14};
  const int templateWeights[15] = {0xb, 0xa, 0xe, 3, 3, 6, 2, 9, 1, 5, 3, 2, 3, 1, 1};
  const char* p = PickWeighted(templates, templateWeights, 0x4a, false);
  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case '/':
      text = s_szSpaceSeparator_00695794;
      break;
    case 'K': {
      const char* strings[10] = {s_mcflavor_0069ac24, s_mcflavor_0069ac14, s_mcflavor_0069ac10,
                                 s_mcflavor_0069acec, s_mcflavor_0069ad48, s_mcflavor_0069af9c,
                                 s_mcflavor_0069b0a0, s_mcflavor_0069acfc, s_mcflavor_0069ac40,
                                 s_mcflavor_0069ac44};
      const int weights[10] = {0xd, 7, 3, 2, 8, 1, 1, 1, 3, 4};
      text = PickWeighted(strings, weights, 0x2b, false);
      break;
    }
    case 'V': {
      const char* strings[6] = {s_mcflavor_0069ac00, s_mcflavor_0069b0c0, g_szLiteralA_0069872C,
                                s_mcflavor_0069b138, s_mcflavor_0069abf8, s_mcflavor_0069ae08};
      const int weights[6] = {9, 2, 0xd, 1, 1, 6};
      text = PickWeighted(strings, weights, 0x1f, true);
      break;
    }
    case 'k': {
      const char* strings[36] = {
          s_mcflavor_0069abc0, s_mcflavor_0069ab70, s_mcflavor_0069ace4, s_mcflavor_0069ab50,
          s_mcflavor_0069b134, s_mcflavor_0069add8, s_mcflavor_0069ab40, s_mcflavor_0069af38,
          s_mcflavor_0069abb4, s_mcflavor_0069b130, s_mcflavor_0069ad3c, s_mcflavor_0069add4,
          s_mcflavor_0069b12c, s_mcflavor_0069acc8, s_mcflavor_00696d10, s_mcflavor_0069abd0,
          s_mcflavor_0069add0, s_mcflavor_0069af88, s_mcflavor_0069ab98, s_mcflavor_0069b128,
          s_mcflavor_0069b0cc, s_mcflavor_0069b124, s_mcflavor_0069b120, s_mcflavor_0069af74,
          s_mcflavor_0069b11c, s_mcflavor_0069b118, s_mcflavor_0069b114, s_mcflavor_0069b110,
          s_mcflavor_0069b10c, s_mcflavor_0069b108, s_mcflavor_0069b0e0, s_mcflavor_0069b104,
          s_mcflavor_0069ab48, s_mcflavor_00697238, s_mcflavor_0069ab5c, s_mcflavor_0069af60};
      const int weights[36] = {6, 0x10, 10, 2, 1, 9, 0xd, 7, 10, 2, 0xc, 1, 1, 3, 5, 2, 1, 2,
                               2, 2,    1,  2, 1, 2, 1,   2, 1,  1, 3,   1, 1, 1, 5, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x84, false);
      break;
    }
    case 'l': {
      const char* strings[8] = {s_mcflavor_0069af74, s_mcflavor_0069ace4, s_mcflavor_0069ad3c,
                                s_mcflavor_0069b088, s_mcflavor_0069b100, s_mcflavor_0069b0f8,
                                s_mcflavor_0069b0f4, s_mcflavor_0069ab70};
      const int weights[8] = {8, 0x1e, 0xe, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x39, false);
      break;
    }
    case 'v': {
      const char* strings[15] = {s_mcflavor_0069ab28, s_mcflavor_0069ab2c, s_mcflavor_0069ab20,
                                 s_mcflavor_0069ab24, s_mcflavor_0069ac9c, s_mcflavor_0069ab18,
                                 s_mcflavor_0069aeb4, s_mcflavor_0069b0f0, s_mcflavor_0069ad30,
                                 s_mcflavor_0069ac98, s_mcflavor_0069b0ec, s_mcflavor_0069ad24,
                                 s_mcflavor_0069b0e8, s_mcflavor_0069ab08, s_mcflavor_0069b0b0};
      const int weights[15] = {0x29, 0x30, 0x16, 5, 7, 8, 7, 4, 3, 2, 1, 3, 1, 3, 2};
      text = PickWeighted(strings, weights, 0x9d, false);
      break;
    }
    case 'w': {
      const char* strings[4] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab20, s_mcflavor_0069ab18,
                                s_mcflavor_0069ab28};
      const int weights[4] = {0xb, 5, 1, 1};
      text = PickWeighted(strings, weights, 0x12, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005cc590
void BuildMapContextStatusStringVariantL(CString* out) {
  *out = CString(g_szEmptyString);

  const char* templates[5] = {s_mcflavor_0069ac80, s_mcflavor_0069ad04, s_mcflavor_0069ad14,
                              s_mcflavor_0069ae14, s_mcflavor_0069ad0c};
  const int templateWeights[5] = {0xd, 0x15, 2, 1, 3};
  const char* p = PickWeighted(templates, templateWeights, 0x28, false);

  for (char token = *p; token != '\0'; token = *p) {
    const char* text = 0;
    switch (token) {
    case 'K': {
      const char* strings[10] = {s_mcflavor_0069ac44,   s_mcflavor_0069ac14, s_mcflavor_0069ac10,
                                 s_mcflavor_0069ac40,   s_mcflavor_0069b0a0, s_mcflavor_0069acf0,
                                 g_szLiteralL_00694250, s_mcflavor_0069ac54, s_mcflavor_0069ac0c,
                                 s_mcflavor_0069ac2c};
      const int weights[10] = {8, 9, 2, 1, 1, 1, 2, 6, 4, 2};
      text = PickWeighted(strings, weights, 0x24, false);
      break;
    }
    case 'V': {
      const char* strings[4] = {s_mcflavor_0069b0bc, g_szLiteralA_0069872C, s_mcflavor_0069ac00,
                                s_mcflavor_0069ae08};
      const int weights[4] = {1, 1, 1, 1};
      text = PickWeighted(strings, weights, 3, true);
      break;
    }
    case 'k': {
      const char* strings[18] = {s_mcflavor_0069abc0, s_mcflavor_0069ab40, s_mcflavor_0069ab9c,
                                 s_mcflavor_0069ab70, s_mcflavor_0069adc4, s_mcflavor_0069abf4,
                                 s_mcflavor_0069ab48, s_mcflavor_0069abd0, s_mcflavor_00696d10,
                                 s_mcflavor_0069b15c, s_mcflavor_0069ad3c, s_mcflavor_0069aba4,
                                 s_mcflavor_0069ace4, s_mcflavor_0069b108, s_mcflavor_0069add4,
                                 s_mcflavor_0069abb4, s_mcflavor_0069b158, s_mcflavor_0069abb8};
      const int weights[18] = {0xc, 0xc, 7, 1, 1, 0xb, 2, 6, 2, 1, 2, 1, 3, 1, 1, 1, 1, 3};
      text = PickWeighted(strings, weights, 0x44, false);
      break;
    }
    case 'v': {
      const char* strings[5] = {s_mcflavor_0069ab18, s_mcflavor_0069ab2c, s_mcflavor_0069ab24,
                                s_mcflavor_0069ab28, s_mcflavor_0069ab20};
      const int weights[5] = {0xe, 0x19, 7, 0xb, 7};
      text = PickWeighted(strings, weights, 0x3f, true);
      break;
    }
    case 'w': {
      const char* strings[5] = {s_mcflavor_0069ab28, s_mcflavor_0069ab18, s_mcflavor_0069ab2c,
                                s_mcflavor_0069ab20, s_mcflavor_0069ab24};
      const int weights[5] = {5, 0xb, 0xe, 5, 5};
      text = PickWeighted(strings, weights, 0x28, false);
      break;
    }
    default:
      break;
    }
    if (text != 0) {
      *out += text;
    }
    p = p + 1;
  }
}

// FUNCTION: IMPERIALISM 0x005ccce0
void GenerateMappedFlavorTextVariantE_005ccce0(CString* out) {
  int flag = FlavorGateFlag(0xd3, 0xc4);
  int count;
  if (flag == 0) {
    const int countWeights[8] = {0, 8, 2, 5, 0, 0, 0, 0};
    count = DrawCountNoStep(countWeights, 0xf);
  } else {
    const int countWeights[8] = {0x33, 0xa, 0x55, 0xe, 0x1e, 5, 1, 0};
    count = DrawCountNoStep(countWeights, 0xc4);
  }
  count = count + 3;

  *out = CString(g_szEmptyString);

  if (flag == 0) {
    const char* strings[5] = {g_szLiteralA_0069872C, s_mcflavor_0069abf8, s_mcflavor_0069b26c,
                              s_mcflavor_0069ae08, s_mcflavor_0069b268};
    const int weights[5] = {5, 3, 2, 2, 2};
    *out += PickWeighted(strings, weights, 0xe, false);
  } else {
    const char* strings[28] = {
        s_mcflavor_0069ac58, s_mcflavor_0069ac2c, s_mcflavor_0069ac24, s_mcflavor_0069ac54,
        s_mcflavor_0069ac14, s_mcflavor_0069ac10, s_mcflavor_0069ac44, s_mcflavor_0069ac40,
        s_mcflavor_0069ad44, s_mcflavor_0069ac48, s_mcflavor_0069b290, g_szLiteralL_00694250,
        s_mcflavor_0069ac0c, s_mcflavor_0069ac38, s_mcflavor_0069b28c, s_mcflavor_0069b0a0,
        s_mcflavor_0069acec, s_mcflavor_0069ac28, s_mcflavor_0069ac1c, s_mcflavor_0069b288,
        s_mcflavor_0069b284, s_mcflavor_0069ac4c, s_mcflavor_0069ae74, s_mcflavor_0069b280,
        s_mcflavor_0069b27c, s_mcflavor_0069b278, s_mcflavor_0069b274, s_mcflavor_0069b270};
    const int weights[28] = {0x18, 0x16, 0x10, 0xb, 0xa, 0xa, 0xa, 0xa, 9, 8, 6, 6, 5, 5,
                             4,    4,    4,    3,   3,   3,   3,   3,   2, 2, 2, 1, 1, 1};
    *out += PickWeighted(strings, weights, 0xbc, false);
  }

  if (1 < count - 1) {
    count = count - 2;
    do {
      flag = (flag == 0);
      if (flag == 0) {
        const char* strings[8] = {s_mcflavor_0069ab18, s_mcflavor_0069ab24, s_mcflavor_0069ab2c,
                                  s_mcflavor_0069ab20, s_mcflavor_0069aec8, s_mcflavor_0069ab28,
                                  s_mcflavor_0069ae84, s_mcflavor_0069aed0};
        const int weights[8] = {0x61, 0x5a, 0x53, 0x3e, 0xc, 0xc, 0xb, 8};
        *out += PickWeighted(strings, weights, 0x174, false);
      } else {
        const char* strings[107] = {
            s_mcflavor_0069ad3c, s_mcflavor_00696d10, s_mcflavor_0069b038, s_mcflavor_00697238,
            s_mcflavor_0069ab70, s_mcflavor_0069b060, s_mcflavor_0069af5c, s_mcflavor_0069ab5c,
            s_mcflavor_0069ace0, s_mcflavor_0069b264, s_mcflavor_0069aba4, s_mcflavor_0069ab98,
            s_mcflavor_0069aba0, s_mcflavor_0069ab40, s_mcflavor_0069b040, s_mcflavor_0069abf4,
            s_mcflavor_0069b260, s_mcflavor_0069ab90, s_mcflavor_0069b25c, s_mcflavor_0069ab84,
            s_mcflavor_0069abcc, s_mcflavor_0069ada8, s_mcflavor_0069b254, s_mcflavor_0069af70,
            s_mcflavor_0069b24c, s_mcflavor_0069b248, s_mcflavor_0069ad38, s_mcflavor_0069b244,
            s_mcflavor_0069add8, s_mcflavor_0069b130, s_mcflavor_0069af88, s_mcflavor_0069acd8,
            s_mcflavor_0069b240, s_mcflavor_0069b23c, s_mcflavor_0069abf0, s_mcflavor_0069b238,
            s_mcflavor_0069b234, s_mcflavor_0069b22c, s_mcflavor_0069abb4, s_mcflavor_0069b228,
            s_mcflavor_0069ab50, s_mcflavor_0069ab48, s_mcflavor_0069b224, s_mcflavor_0069ace4,
            s_mcflavor_0069b220, s_mcflavor_0069b21c, s_mcflavor_0069af44, s_mcflavor_0069b218,
            s_mcflavor_0069abc0, s_mcflavor_0069b214, s_mcflavor_0069b210, s_mcflavor_0069b20c,
            s_mcflavor_0069b208, s_mcflavor_0069b204, s_mcflavor_0069ab9c, g_szLiteralRb_00698720,
            s_mcflavor_0069b1fc, s_mcflavor_0069b1f8, s_mcflavor_0069b1f4, s_mcflavor_0069acc0,
            s_mcflavor_0069b1f0, s_mcflavor_0069add4, s_mcflavor_0069b1ec, s_mcflavor_0069af3c,
            s_mcflavor_0069ae58, s_mcflavor_0069abd0, s_mcflavor_0069b1e8, s_mcflavor_0069b128,
            s_mcflavor_0069b1e4, s_mcflavor_0069b1e0, s_mcflavor_0069b1dc, s_mcflavor_0069b1d8,
            s_mcflavor_0069abb8, s_mcflavor_0069ab54, s_mcflavor_0069adf4, s_mcflavor_0069b1d4,
            s_mcflavor_0069b1d0, s_mcflavor_0069b1cc, s_mcflavor_0069b1c4, s_mcflavor_0069b1c0,
            s_mcflavor_0069b1bc, s_mcflavor_0069b1b8, s_mcflavor_0069abbc, s_mcflavor_0069b1b4,
            s_mcflavor_0069b1b0, s_mcflavor_0069b1ac, s_mcflavor_0069acc8, s_mcflavor_0069ab3c,
            s_mcflavor_0069b1a8, s_mcflavor_0069addc, s_mcflavor_0069b0dc, s_mcflavor_0069b1a0,
            s_mcflavor_0069b19c, s_mcflavor_0069b198, s_mcflavor_0069af68, s_mcflavor_0069b194,
            s_mcflavor_0069b190, s_mcflavor_0069b12c, s_mcflavor_0069b18c, s_mcflavor_0069b188,
            s_mcflavor_0069b184, s_mcflavor_0069b17c, s_mcflavor_0069b178, s_mcflavor_0069b048,
            s_mcflavor_0069b174, s_mcflavor_0069adc8, s_mcflavor_0069b170};
        const int weights[107] = {
            0xc, 8, 8, 6, 6, 5, 5, 5, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2,
            2,   2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
            1,   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1,   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        *out += PickWeighted(strings, weights, 0xd6, false);
      }
      count = count - 1;
    } while (count != 0);
  }

  if (flag == 0) {
    const char* strings[26] = {
        s_mcflavor_0069ab70, s_mcflavor_0069ad34, s_mcflavor_0069ab48, s_mcflavor_0069ace0,
        s_mcflavor_0069ab98, s_mcflavor_0069aba4, s_mcflavor_0069b16c, s_mcflavor_00696d10,
        s_mcflavor_0069ab90, s_mcflavor_0069adac, s_mcflavor_0069ab3c, s_mcflavor_0069abc0,
        s_mcflavor_0069b168, s_mcflavor_00697238, s_mcflavor_0069acc0, s_mcflavor_0069ab40,
        s_mcflavor_0069b130, s_mcflavor_0069abe0, s_mcflavor_0069af88, s_mcflavor_0069adf4,
        s_mcflavor_0069abd0, s_mcflavor_0069ae48, s_mcflavor_0069b164, s_mcflavor_0069ad3c,
        s_mcflavor_0069ade8, s_mcflavor_0069b160};
    const int weights[26] = {0x26, 0xd, 0xc, 0xc, 0xc, 0xb, 0xa, 8, 7, 6, 5, 5, 5,
                             4,    4,   3,   3,   3,   2,   2,   2, 1, 1, 1, 1, 1};
    *out += PickWeighted(strings, weights, 0xac, false);
  } else {
    const char* strings[3] = {s_mcflavor_0069ab24, s_mcflavor_0069ac9c, s_mcflavor_0069aed0};
    const int weights[3] = {0x18, 3, 2};
    *out += PickWeighted(strings, weights, 0x1d, false);
  }
}

// FUNCTION: IMPERIALISM 0x005ce110
CString* GenerateMappedFlavorTextVariantEToSharedString(CString* out) {
  CString temp;
  GenerateMappedFlavorTextVariantE_005ccce0(&temp);
  *out = temp;
  return out;
}

// FUNCTION: IMPERIALISM 0x005ce1b0
void BuildRandomMapContextStatusBaseString(CString* out) {
  int flag = FlavorGateFlag(0x55a, 0x3c3);
  int count;
  if (flag == 0) {
    const int countWeights[8] = {0x5c, 0x85, 0x91, 0xe, 0xe, 9, 0, 0};
    count = DrawCountNoStep(countWeights, 0x197);
  } else {
    const int countWeights[8] = {0x164, 0x148, 0x50, 0x87, 0x28, 0x14, 4, 0};
    count = DrawCountNoStep(countWeights, 0x3c3);
  }

  *out = CString(g_szEmptyString);

  if (flag == 0) {
    const char* strings[8] = {g_szLiteralA_0069872C, s_mcflavor_0069b0bc, s_mcflavor_0069abf8,
                              s_mcflavor_0069b26c,   s_mcflavor_0069ac00, s_mcflavor_0069ac08,
                              s_mcflavor_0069b268,   s_mcflavor_0069b0b8};
    const int weights[8] = {0x62, 0x55, 0x42, 0x42, 0x1f, 0x13, 0x12, 0xe};
    *out += PickWeighted(strings, weights, 0x186, false);
  } else {
    const char* strings[18] = {g_szLiteralL_00694250, s_mcflavor_0069ac44, s_mcflavor_0069ac38,
                               s_mcflavor_0069ac58,   s_mcflavor_0069ac10, s_mcflavor_0069ac28,
                               s_mcflavor_0069ad44,   s_mcflavor_0069ac1c, s_mcflavor_0069b0a0,
                               s_mcflavor_0069ac40,   s_mcflavor_0069ac0c, s_mcflavor_0069ac54,
                               s_mcflavor_0069acec,   s_mcflavor_0069ac24, s_mcflavor_0069b2c0,
                               s_mcflavor_0069b2bc,   s_mcflavor_0069ac50, s_mcflavor_0069b27c};
    const int weights[18] = {0x80, 0x73, 0x6c, 0x5b, 0x51, 0x4f, 0x32, 0x30, 0x2a,
                             0x25, 0x1d, 0x1c, 0x1a, 0xf,  0xe,  0xd,  0xc,  8};
    *out += PickWeighted(strings, weights, 0x39c, false);
  }

  if (1 < count + 2) {
    count = count + 1;
    do {
      flag = (flag == 0);
      if (flag == 0) {
        const char* strings[11] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab24, s_mcflavor_0069ab20,
                                   s_mcflavor_0069ab18, s_mcflavor_0069ad28, s_mcflavor_0069ab08,
                                   s_mcflavor_0069ab28, s_mcflavor_0069ac98, s_mcflavor_0069ae84,
                                   s_mcflavor_0069ab14, s_mcflavor_0069ab00};
        const int weights[11] = {0x171, 0x162, 0xdf, 0xdb, 0x6c, 0x69,
                                 0x64,  0x2c,  0x28, 0x1f, 0x1d};
        *out += PickWeighted(strings, weights, 0x644, false);
      } else {
        const char* strings[37] = {
            s_mcflavor_0069ad3c, s_mcflavor_00696d10, s_mcflavor_0069ad40, s_mcflavor_0069add8,
            s_mcflavor_0069ab70, s_mcflavor_0069acd8, s_mcflavor_0069b2b8, s_mcflavor_0069abd0,
            s_mcflavor_0069ada8, s_mcflavor_0069b130, s_mcflavor_0069b2b4, s_mcflavor_0069ab98,
            s_mcflavor_0069aba4, s_mcflavor_0069ab40, s_mcflavor_0069b2b0, s_mcflavor_0069adac,
            s_mcflavor_0069af74, s_mcflavor_0069b034, s_mcflavor_0069ab48, s_mcflavor_0069abb8,
            s_mcflavor_0069abe0, s_mcflavor_0069acac, s_mcflavor_0069b16c, s_mcflavor_0069b2ac,
            s_mcflavor_0069b128, s_mcflavor_0069af60, s_mcflavor_0069ab60, s_mcflavor_0069adf4,
            s_mcflavor_0069ad34, s_mcflavor_0069af4c, s_mcflavor_0069b2a8, s_mcflavor_0069ae4c,
            s_mcflavor_0069b2a4, s_mcflavor_0069ab9c, s_mcflavor_0069b2a0, s_mcflavor_0069adc4,
            s_mcflavor_0069af70};
        const int weights[37] = {0xb4, 0xb3, 0x99, 0x61, 0x51, 0x49, 0x3a, 0x34, 0x2d, 0x2b,
                                 0x21, 0x1f, 0x1d, 0x1c, 0x19, 0x17, 0x15, 0x14, 0x14, 0x13,
                                 0x12, 0x10, 0xe,  0xd,  0xc,  0xc,  0xb,  0xa,  9,    9,
                                 8,    8,    8,    7,    7,    7,    7};
        *out += PickWeighted(strings, weights, 0x568, false);
      }
      count = count - 1;
    } while (count != 0);
  }

  if (flag == 0) {
    const char* strings[20] = {
        s_mcflavor_0069abd0, s_mcflavor_0069acbc, s_mcflavor_0069b29c, s_mcflavor_00696d10,
        s_mcflavor_0069ab70, s_mcflavor_0069ad3c, s_mcflavor_0069ab40, s_mcflavor_0069adac,
        s_mcflavor_0069b130, s_mcflavor_0069b108, s_mcflavor_0069ada8, s_mcflavor_0069ad34,
        s_mcflavor_0069af60, s_mcflavor_0069adf4, s_mcflavor_00698b0c, s_mcflavor_0069adc4,
        s_mcflavor_0069af34, s_mcflavor_0069b298, s_mcflavor_0069ad40, s_mcflavor_0069ab50};
    const int weights[20] = {0xa0, 0x60, 0x50, 0x48, 0x29, 0x1f, 0x16, 0x10, 0xf, 9,
                             8,    8,    8,    8,    8,    7,    6,    6,    6,   6};
    *out += PickWeighted(strings, weights, 0x262, false);
  } else {
    const char* strings[4] = {s_mcflavor_0069ab24, s_mcflavor_0069ab20, s_mcflavor_0069ab00,
                              s_mcflavor_0069b294};
    const int weights[4] = {0x2a5, 0xe, 0xb, 0xb};
    *out += PickWeighted(strings, weights, 0x2c0, false);
  }
}

// FUNCTION: IMPERIALISM 0x005cef20
CString AssignRandomMapContextStatusBaseString() {
  CString base;
  BuildRandomMapContextStatusBaseString(&base);
  return base;
}

// FUNCTION: IMPERIALISM 0x005cefc0
void AppendRandomMapContextStatusSuffixWithProbability(CString* dest) {
  BuildRandomMapContextStatusBaseString(dest);
  if (dest->GetLength() < 9) {
    g_zoneStatusCodePrngSeed_006a5aec = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
    if (static_cast<int>((g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 0x7fff) % 10 == 0) {
      *dest += s_mcflavor_0069b2c4;
      *dest += AssignRandomMapContextStatusBaseString();
    }
  }
}

// FUNCTION: IMPERIALISM 0x005cf090
CString* BuildMapContextStatusStringWithRandomSuffix(CString* out) {
  CString local;
  BuildRandomMapContextStatusBaseString(&local);
  if (local.GetLength() < 9) {
    g_zoneStatusCodePrngSeed_006a5aec = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
    if (static_cast<int>((g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 0x7fff) % 10 == 0) {
      local += s_mcflavor_0069b2c4;
      local += AssignRandomMapContextStatusBaseString();
    }
  }
  *out = local;
  return out;
}

// FUNCTION: IMPERIALISM 0x005cf1b0
void GenerateMappedFlavorTextVariantC_005cf1b0(CString* out) {
  int flag = FlavorGateFlag(0xeb, 0xc5);
  int count;
  if (flag == 0) {
    const int countWeights[8] = {8, 0, 0x1a, 0, 4, 0, 0, 0};
    count = DrawCountNoStep(countWeights, 0x26);
  } else {
    const int countWeights[8] = {0, 0x35, 0, 0x89, 0, 7, 0, 0};
    count = DrawCountNoStep(countWeights, 0xc5);
  }
  count = count + 3;

  *out = CString(g_szEmptyString);

  if (flag == 0) {
    const char* strings[5] = {g_szLiteralA_0069872C, s_mcflavor_0069abf8, s_mcflavor_0069ae08,
                              s_mcflavor_0069b0bc, s_mcflavor_0069b0c4};
    const int weights[5] = {0x10, 0xc, 4, 2, 2};
    *out += PickWeighted(strings, weights, 0x24, false);
  } else {
    const char* strings[14] = {g_szLiteralL_00694250, s_mcflavor_0069ac40, s_mcflavor_0069ad44,
                               s_mcflavor_0069ac28,   s_mcflavor_0069ac10, s_mcflavor_0069ac38,
                               s_mcflavor_0069acec,   s_mcflavor_0069ac44, s_mcflavor_0069ac54,
                               s_mcflavor_0069acf4,   s_mcflavor_0069ac1c, s_mcflavor_0069ac50,
                               s_mcflavor_0069ac48,   s_mcflavor_0069ac24};
    const int weights[14] = {0x1a, 0x19, 0x16, 0x15, 0x13, 0x12, 0xf, 0xd, 9, 6, 6, 5, 4, 3};
    *out += PickWeighted(strings, weights, 0xc0, false);
  }

  if (1 < count - 1) {
    count = count - 2;
    do {
      flag = (flag == 0);
      if (flag == 0) {
        const char* strings[6] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab24, s_mcflavor_0069ab18,
                                  s_mcflavor_0069ab20, s_mcflavor_0069ab28, s_mcflavor_0069ab00};
        const int weights[6] = {0x7a, 0x53, 0x4c, 0x46, 0x12, 0xd};
        *out += PickWeighted(strings, weights, 0x17a, false);
      } else {
        const char* strings[34] = {
            s_mcflavor_0069ab70,    s_mcflavor_0069ab40, s_mcflavor_0069ab48, s_mcflavor_00696d10,
            s_mcflavor_0069ad3c,    s_mcflavor_0069abd0, s_mcflavor_0069adac, s_mcflavor_0069ad40,
            s_mcflavor_0069ada8,    s_mcflavor_0069b2b0, s_mcflavor_0069b2e0, s_mcflavor_0069adc4,
            s_mcflavor_0069add8,    s_mcflavor_0069abf4, s_mcflavor_0069b2dc, s_mcflavor_0069abb4,
            s_mcflavor_0069abe0,    s_mcflavor_0069b2d8, s_mcflavor_0069aba4, s_mcflavor_0069ab90,
            s_mcflavor_0069ab38,    s_mcflavor_0069adb0, s_mcflavor_0069b2d4, s_mcflavor_0069ab98,
            s_mcflavor_0069abd4,    s_mcflavor_0069b130, s_mcflavor_0069af34, s_mcflavor_0069b2d0,
            g_szLiteralRb_00698720, s_mcflavor_0069b2cc, s_mcflavor_0069ab9c, s_mcflavor_0069af60,
            s_mcflavor_0069acd8,    s_mcflavor_0069b2c8};
        const int weights[34] = {0x3c, 0x30, 0x23, 0x1c, 0x15, 0x10, 0x10, 0x10, 0x10,
                                 0xf,  0xd,  0xc,  0xc,  0xb,  0xa,  0xa,  8,    7,
                                 6,    6,    6,    5,    5,    5,    4,    4,    3,
                                 3,    3,    3,    2,    2,    2,    2};
        *out += PickWeighted(strings, weights, 0x19e, false);
      }
      count = count - 1;
    } while (count != 0);
  }

  if (flag != 0) {
    const char* strings[5] = {s_mcflavor_0069ac9c, s_mcflavor_0069ab2c, s_mcflavor_0069ab18,
                              s_mcflavor_0069ab24, s_mcflavor_0069ab20};
    const int weights[5] = {0x48, 0x3e, 0x2e, 0x1a, 0x13};
    *out += PickWeighted(strings, weights, 0xe1, false);
  }
}

// FUNCTION: IMPERIALISM 0x005cfba0
CString* GenerateMappedFlavorTextVariantCToSharedString(CString* out) {
  CString temp;
  GenerateMappedFlavorTextVariantC_005cf1b0(&temp);
  *out = temp;
  return out;
}

// FUNCTION: IMPERIALISM 0x005cfc40
void GenerateMappedFlavorTextVariantB_005cfc40(CString* out) {
  int flag = FlavorGateFlag(0xd48, 0xcac);
  int count;
  if (flag == 0) {
    const int countWeights[8] = {0xa, 0x27, 0x3b, 0xf, 0x1f, 2, 0, 0};
    count = DrawCountNoStep(countWeights, 0x9c);
  } else {
    const int countWeights[8] = {0x18a, 0x2e9, 0x23f, 0x39d, 0x111, 0x139, 0x13, 0};
    count = DrawCountNoStep(countWeights, 0xcac);
  }

  *out = CString(g_szEmptyString);

  if (flag == 0) {
    const char* strings[4] = {s_mcflavor_0069b0bc, s_mcflavor_0069ae08, s_mcflavor_0069ac00,
                              g_szLiteralA_0069872C};
    const int weights[4] = {0x5d, 0x1c, 0x1a, 8};
    *out += PickWeighted(strings, weights, 0x95, false);
  } else {
    const char* strings[55] = {
        s_mcflavor_0069ac24, g_szLiteralL_00694250, s_mcflavor_0069ac40, s_mcflavor_0069ac28,
        s_mcflavor_0069ac44, s_mcflavor_0069ac54,   s_mcflavor_0069ac14, s_mcflavor_0069ac58,
        s_mcflavor_0069ac10, s_mcflavor_0069ac0c,   s_mcflavor_0069ac38, s_mcflavor_0069acec,
        s_mcflavor_0069ad44, s_mcflavor_0069acf0,   s_mcflavor_0069af98, s_mcflavor_0069b28c,
        s_mcflavor_0069b408, s_mcflavor_0069ac18,   s_mcflavor_0069b2c0, s_mcflavor_0069ac4c,
        s_mcflavor_0069b404, s_mcflavor_0069acf4,   s_mcflavor_0069b284, s_mcflavor_0069ae78,
        s_mcflavor_0069ac1c, s_mcflavor_0069b400,   s_mcflavor_0069b3f8, s_mcflavor_0069ae68,
        s_mcflavor_0069acf8, s_mcflavor_0069b3f4,   s_mcflavor_0069b274, s_mcflavor_0069ae70,
        s_mcflavor_0069b3f0, s_mcflavor_0069b278,   s_mcflavor_0069ac48, s_mcflavor_0069b3ec,
        s_mcflavor_0069b3e8, s_mcflavor_0069b3e4,   s_mcflavor_0069b0a0, s_mcflavor_0069b3e0,
        s_mcflavor_0069b3dc, s_mcflavor_0069b270,   s_mcflavor_0069b3d4, s_mcflavor_0069b3d0,
        s_mcflavor_0069b3cc, s_mcflavor_0069b3c8,   s_mcflavor_0069b3c4, s_mcflavor_0069b3bc,
        s_mcflavor_0069b290, s_mcflavor_0069b3b8,   s_mcflavor_0069b3b4, s_mcflavor_0069b3b0,
        s_mcflavor_0069b3ac, s_mcflavor_0069b3a8,   s_mcflavor_0069b3a4};
    const int weights[55] = {0xda, 0xd7, 0xc3, 0xbe, 0xbb, 0xba, 0xb7, 0xa0, 0x9d, 0x92, 0x8d,
                             0x74, 0x6c, 0x67, 0x47, 0x46, 0x43, 0x3b, 0x3a, 0x35, 0x28, 0x21,
                             0x20, 0x1f, 0x1a, 0x16, 0x16, 0x15, 0x14, 0x12, 0x11, 0xd,  0xc,
                             0xb,  9,    9,    8,    8,    8,    8,    8,    8,    7,    7,
                             7,    6,    5,    5,    5,    5,    5,    4,    4,    4,    4};
    *out += PickWeighted(strings, weights, 0xc3e, false);
  }

  if (1 < count + 2) {
    count = count + 1;
    do {
      flag = (flag == 0);
      if (flag == 0) {
        const char* strings[5] = {s_mcflavor_0069ab18, s_mcflavor_0069ab2c, s_mcflavor_0069ab20,
                                  s_mcflavor_0069ab24, s_mcflavor_0069ab28};
        const int weights[5] = {0x77c, 0x666, 0x40e, 0x3db, 0x1de};
        *out += PickWeighted(strings, weights, 0x1772, false);
      } else {
        const char* strings[86] = {
            s_mcflavor_0069add8, s_mcflavor_0069ad40, s_mcflavor_0069ab70, s_mcflavor_0069ab40,
            s_mcflavor_0069b3a0, s_mcflavor_00696d10, s_mcflavor_0069abd0, s_mcflavor_0069ad3c,
            s_mcflavor_0069ace4, s_mcflavor_0069aba4, s_mcflavor_0069ab9c, s_mcflavor_0069ab48,
            s_mcflavor_0069adc4, s_mcflavor_0069ab90, s_mcflavor_0069b130, s_mcflavor_0069b39c,
            s_mcflavor_0069acc8, s_mcflavor_0069add4, s_mcflavor_0069b398, s_mcflavor_0069ab3c,
            s_mcflavor_0069ae40, s_mcflavor_0069adfc, s_mcflavor_0069ab30, s_mcflavor_0069ab34,
            s_mcflavor_0069b034, s_mcflavor_0069adf0, s_mcflavor_0069af38, s_mcflavor_0069ab7c,
            s_mcflavor_0069ade8, s_mcflavor_0069ae60, s_mcflavor_0069b394, s_mcflavor_0069b2dc,
            s_mcflavor_0069b390, s_mcflavor_0069b134, s_mcflavor_0069b1d4, s_mcflavor_0069ae4c,
            s_mcflavor_0069b38c, s_mcflavor_0069ab50, s_mcflavor_0069b388, s_mcflavor_0069b384,
            s_mcflavor_0069ae58, s_mcflavor_0069b380, s_mcflavor_0069b29c, s_mcflavor_0069ae38,
            s_mcflavor_0069b1b4, s_mcflavor_0069acd8, s_mcflavor_0069ab68, s_mcflavor_0069accc,
            s_mcflavor_0069ada8, s_mcflavor_0069ae50, s_mcflavor_0069b37c, s_mcflavor_0069b378,
            s_mcflavor_0069adb4, s_mcflavor_0069b374, s_mcflavor_0069b124, s_mcflavor_0069acc0,
            s_mcflavor_0069abb8, s_mcflavor_0069b370, s_mcflavor_0069adac, s_mcflavor_0069acd0,
            s_mcflavor_0069adc0, s_mcflavor_0069b36c, s_mcflavor_0069b368, s_mcflavor_0069b0dc,
            s_mcflavor_0069abf0, s_mcflavor_0069af34, s_mcflavor_0069acbc, s_mcflavor_0069b364,
            s_mcflavor_0069b360, s_mcflavor_0069abf4, s_mcflavor_0069abb4, s_mcflavor_0069adf8,
            s_mcflavor_0069b35c, s_mcflavor_0069b358, s_mcflavor_0069b128, s_mcflavor_0069af44,
            s_mcflavor_0069b354, s_mcflavor_0069b2ac, s_mcflavor_0069b350, s_mcflavor_0069acac,
            s_mcflavor_0069b34c, s_mcflavor_0069b348, s_mcflavor_0069acd4, s_mcflavor_0069b344,
            s_mcflavor_0069b340, s_mcflavor_0069b1a8};
        const int weights[86] = {
            0x228, 0x178, 0x155, 0x13d, 0x112, 0xfd, 0xc2, 0xae, 0x9d, 0x8e, 0x88, 0x6a, 0x67,
            0x61,  0x5b,  0x58,  0x57,  0x53,  0x42, 0x37, 0x36, 0x35, 0x35, 0x34, 0x31, 0x2d,
            0x2b,  0x23,  0x23,  0x22,  0x21,  0x1e, 0x1d, 0x1d, 0x1c, 0x1a, 0x1a, 0x17, 0x15,
            0x14,  0x14,  0x13,  0x13,  0x12,  0x11, 0x11, 0x10, 0x10, 0x10, 0x10, 0xe,  0xe,
            0xe,   0xd,   0xd,   0xd,   0xd,   0xc,  0xc,  0xb,  0xa,  0xa,  0xa,  8,    8,
            8,     8,     8,     8,     8,     7,    6,    6,    6,    6,    6,    6,    6,
            6,     6,     6,     5,     5,     5,    5,    5};
        *out += PickWeighted(strings, weights, 0x1318, false);
      }
      count = count - 1;
    } while (count != 0);
  }

  if (flag == 0) {
    const char* strings[37] = {
        s_mcflavor_0069b088, s_mcflavor_0069add8, s_mcflavor_0069aba4, s_mcflavor_0069ab70,
        s_mcflavor_0069ad40, s_mcflavor_0069ace4, s_mcflavor_0069abd0, s_mcflavor_0069ab48,
        s_mcflavor_00696d10, s_mcflavor_0069b33c, s_mcflavor_0069ab40, s_mcflavor_0069b338,
        s_mcflavor_0069b334, s_mcflavor_0069af38, s_mcflavor_0069b32c, s_mcflavor_0069b328,
        s_mcflavor_0069b324, s_mcflavor_0069b168, s_mcflavor_0069b320, s_mcflavor_0069b31c,
        s_mcflavor_0069b318, s_mcflavor_0069b314, s_mcflavor_0069adc4, s_mcflavor_0069b310,
        s_mcflavor_0069b30c, s_mcflavor_0069ad3c, s_mcflavor_0069b308, s_mcflavor_0069b304,
        s_mcflavor_0069b2fc, s_mcflavor_0069ab3c, s_mcflavor_0069ab9c, s_mcflavor_0069b2f8,
        s_mcflavor_0069ab90, s_mcflavor_0069b2f0, s_mcflavor_0069b2e8, s_mcflavor_0069b2e4,
        s_mcflavor_0069add4};
    const int weights[37] = {0xbc, 0xbc, 0x79, 0x70, 0x6d, 0x63, 0x43, 0x42, 0x2b, 0x1a,
                             0x18, 0x12, 0x10, 0xf,  0xd,  0xc,  0xb,  0xb,  0xa,  9,
                             9,    9,    9,    8,    8,    8,    8,    6,    6,    6,
                             6,    5,    4,    4,    4,    4,    4};
    *out += PickWeighted(strings, weights, 0x4f0, false);
  } else {
    const char* strings[4] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab24, s_mcflavor_0069ab18,
                              s_mcflavor_0069ae84};
    const int weights[4] = {0x424, 0x332, 0x68, 0x2d};
    *out += PickWeighted(strings, weights, 1999, false);
  }
}

// FUNCTION: IMPERIALISM 0x005d1330
CString* GenerateMappedFlavorTextVariantBToSharedString(CString* out) {
  CString temp;
  GenerateMappedFlavorTextVariantB_005cfc40(&temp);
  *out = temp;
  return out;
}

// FUNCTION: IMPERIALISM 0x005d13d0
void GenerateMappedFlavorTextVariantA_005d13d0(CString* out) {
  int flag = FlavorGateFlag(0x2a6, 0x24a);
  int count;
  if (flag == 0) {
    const int countWeights[8] = {7, 0x1f, 8, 0x15, 0xf, 7, 3, 0};
    count = DrawCountNoStep(countWeights, 0x5c);
  } else {
    const int countWeights[8] = {0x8f, 0x49, 0xe0, 0x38, 0x3f, 0x17, 4, 0};
    count = DrawCountNoStep(countWeights, 0x24a);
  }
  count = count + 3;

  *out = CString(g_szEmptyString);

  if (flag == 0) {
    const char* strings[6] = {g_szLiteralA_0069872C, s_mcflavor_0069b0bc, s_mcflavor_0069abf8,
                              s_mcflavor_0069ac00,   s_mcflavor_0069ae08, s_mcflavor_0069ac08};
    const int weights[6] = {0x2c, 0xf, 0xc, 0xb, 4, 4};
    *out += PickWeighted(strings, weights, 0x59, false);
  } else {
    const char* strings[36] = {
        s_mcflavor_0069ad44, s_mcflavor_0069ac54,   s_mcflavor_0069ac44, s_mcflavor_0069ac10,
        s_mcflavor_0069ac58, s_mcflavor_0069ac40,   s_mcflavor_0069ac38, s_mcflavor_0069af98,
        s_mcflavor_0069ac1c, g_szLiteralL_00694250, s_mcflavor_0069ac0c, s_mcflavor_0069acec,
        s_mcflavor_0069ac14, s_mcflavor_0069ac24,   s_mcflavor_0069ac2c, s_mcflavor_0069ac48,
        s_mcflavor_0069b0a0, s_mcflavor_0069b290,   s_mcflavor_0069ac28, s_mcflavor_0069ac4c,
        s_mcflavor_0069b28c, s_mcflavor_0069acf4,   s_mcflavor_0069ac50, s_mcflavor_0069b528,
        s_mcflavor_0069af9c, s_mcflavor_0069ad00,   s_mcflavor_0069ad4c, s_mcflavor_0069b288,
        s_mcflavor_0069ae74, s_mcflavor_0069acf8,   s_mcflavor_0069b280, s_mcflavor_0069b2c0,
        s_mcflavor_0069b524, s_mcflavor_0069b520,   s_mcflavor_0069b274, s_mcflavor_0069b51c};
    const int weights[36] = {0x2e, 0x2b, 0x28, 0x26, 0x22, 0x21, 0x1f, 0x1a, 0x1a, 0x19, 0x15, 0x14,
                             0x14, 0x13, 0x13, 0x10, 0xc,  0xb,  0xb,  0xa,  6,    6,    6,    5,
                             5,    5,    4,    4,    4,    4,    4,    3,    3,    3,    2,    2};
    *out += PickWeighted(strings, weights, 0x237, false);
  }

  if (1 < count - 1) {
    count = count - 2;
    do {
      flag = (flag == 0);
      if (flag == 0) {
        const char* strings[13] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab24, s_mcflavor_0069ab18,
                                   s_mcflavor_0069ab20, s_mcflavor_0069ab28, s_mcflavor_0069ae84,
                                   s_mcflavor_0069aed0, s_mcflavor_0069aec8, s_mcflavor_0069ac9c,
                                   s_mcflavor_0069ab00, s_mcflavor_0069ad24, s_mcflavor_0069ac98,
                                   s_mcflavor_0069aca8};
        const int weights[13] = {0x14f, 0x104, 0xd7, 0xc7, 0x3f, 0x12, 0xf, 0xe, 0xd, 0xa, 9, 9, 8};
        *out += PickWeighted(strings, weights, 0x48f, false);
      } else {
        const char* strings[162] = {
            s_mcflavor_0069ab40,    s_mcflavor_0069ab70, s_mcflavor_0069ab48, s_mcflavor_00696d10,
            s_mcflavor_0069ab98,    s_mcflavor_0069add8, s_mcflavor_0069ad3c, s_mcflavor_0069ad40,
            s_mcflavor_0069b034,    s_mcflavor_0069abd0, s_mcflavor_0069ada8, s_mcflavor_0069abb4,
            s_mcflavor_0069aba4,    s_mcflavor_0069acc8, s_mcflavor_0069abb8, s_mcflavor_0069ab9c,
            s_mcflavor_0069add4,    s_mcflavor_0069af60, s_mcflavor_0069ab54, s_mcflavor_0069abe0,
            s_mcflavor_0069ace4,    s_mcflavor_00697238, s_mcflavor_0069acbc, s_mcflavor_0069ab90,
            s_mcflavor_0069acd8,    s_mcflavor_0069b130, s_mcflavor_0069abc0, s_mcflavor_0069af88,
            s_mcflavor_0069ab50,    s_mcflavor_0069b060, s_mcflavor_0069ab3c, s_mcflavor_0069ab68,
            s_mcflavor_0069b518,    s_mcflavor_0069b2d8, s_mcflavor_0069ab5c, s_mcflavor_0069b128,
            s_mcflavor_0069b188,    s_mcflavor_0069abf0, s_mcflavor_0069af34, s_mcflavor_00698b0c,
            s_mcflavor_0069adf4,    s_mcflavor_0069b370, s_mcflavor_0069ad34, s_mcflavor_0069adac,
            s_mcflavor_0069adfc,    s_mcflavor_0069b2dc, s_mcflavor_0069b0dc, s_mcflavor_0069ae60,
            s_mcflavor_0069b514,    s_mcflavor_0069b510, s_mcflavor_0069b2e0, s_mcflavor_0069af40,
            s_mcflavor_0069b2ac,    s_mcflavor_0069aba0, s_mcflavor_0069ab84, s_mcflavor_0069acdc,
            s_mcflavor_0069b50c,    s_mcflavor_0069b508, s_mcflavor_0069b34c, s_mcflavor_0069b160,
            s_mcflavor_0069ada0,    s_mcflavor_0069b124, s_mcflavor_0069abcc, s_mcflavor_0069b504,
            s_mcflavor_0069af70,    s_mcflavor_0069b500, s_mcflavor_0069b25c, s_mcflavor_0069b1f0,
            s_mcflavor_0069b260,    s_mcflavor_0069addc, s_mcflavor_0069b054, s_mcflavor_0069b234,
            g_szLiteralRb_00698720, s_mcflavor_0069ab7c, s_mcflavor_0069b4fc, s_mcflavor_0069acc0,
            s_mcflavor_0069ab4c,    s_mcflavor_0069abd4, s_mcflavor_0069b2d0, s_mcflavor_0069acac,
            s_mcflavor_0069af38,    s_mcflavor_0069af74, s_mcflavor_0069b4f8, s_mcflavor_0069b4f4,
            s_mcflavor_0069b038,    s_mcflavor_0069ae4c, s_mcflavor_0069adcc, s_mcflavor_0069ae48,
            s_mcflavor_0069aba8,    s_mcflavor_0069b378, s_mcflavor_0069b4f0, s_mcflavor_0069b4ec,
            s_mcflavor_0069b078,    s_mcflavor_0069b4e8, s_mcflavor_0069adb0, s_mcflavor_0069b4e4,
            s_mcflavor_0069b228,    s_mcflavor_0069b20c, s_mcflavor_0069b208, s_mcflavor_0069b4e0,
            s_mcflavor_0069b4dc,    s_mcflavor_0069b4d8, s_mcflavor_0069b1c0, s_mcflavor_0069b248,
            s_mcflavor_0069b4d4,    s_mcflavor_0069b4d0, s_mcflavor_0069ae58, s_mcflavor_0069b064,
            s_mcflavor_0069b1dc,    s_mcflavor_0069b354, s_mcflavor_0069b4cc, s_mcflavor_0069b4c8,
            s_mcflavor_0069b1ec,    s_mcflavor_0069b4c4, s_mcflavor_0069b4bc, s_mcflavor_0069b4b8,
            s_mcflavor_006976e0,    s_mcflavor_0069af3c, s_mcflavor_0069b4b4, s_mcflavor_0069b198,
            s_mcflavor_0069b4b0,    s_mcflavor_0069b2a8, s_mcflavor_0069acd4, s_mcflavor_0069ade8,
            s_mcflavor_0069ab30,    s_mcflavor_0069b4ac, s_mcflavor_0069b4a8, s_mcflavor_0069b218,
            s_mcflavor_0069b4a4,    s_mcflavor_0069b4a0, s_mcflavor_0069abbc, s_mcflavor_0069b264,
            s_mcflavor_0069b058,    s_mcflavor_0069b49c, s_mcflavor_0069b498, s_mcflavor_0069b490,
            s_mcflavor_0069b340,    s_mcflavor_0069b48c, s_mcflavor_0069b488, s_mcflavor_0069b484,
            s_mcflavor_0069adc4,    s_mcflavor_0069b480, s_mcflavor_0069b47c, s_mcflavor_0069b478,
            s_mcflavor_0069b474,    s_mcflavor_0069ace0, s_mcflavor_0069b134, s_mcflavor_0069acb8,
            s_mcflavor_0069b470,    s_mcflavor_0069b46c, s_mcflavor_0069b468, s_mcflavor_0069b1d4,
            s_mcflavor_0069b464,    s_mcflavor_0069b460, s_mcflavor_0069b1e0, s_mcflavor_0069b16c,
            s_mcflavor_0069b1d8,    s_mcflavor_0069b29c, s_mcflavor_0069b45c, s_mcflavor_0069b458,
            s_mcflavor_0069b454,    s_mcflavor_0069b44c};
        const int weights[162] = {
            0x31, 0x2c, 0x27, 0x23, 0x21, 0x19, 0x19, 0x16, 0x15, 0x14, 0x14, 0x13, 0x12, 0x11,
            0x11, 0xe,  0xc,  0xb,  0xb,  0xb,  9,    9,    9,    9,    9,    8,    7,    7,
            7,    6,    6,    6,    5,    5,    5,    5,    5,    5,    5,    5,    4,    4,
            4,    4,    4,    4,    3,    3,    3,    3,    3,    3,    3,    3,    3,    2,
            2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,
            2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,    1,
            1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
            1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
            1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
            1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
            1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
            1,    1,    1,    1,    1,    1,    1,    1};
        *out += PickWeighted(strings, weights, 0x30d, false);
      }
      count = count - 1;
    } while (count != 0);
  }

  if (flag == 0) {
    const char* strings[64] = {
        s_mcflavor_0069ab70, s_mcflavor_00696d10, s_mcflavor_0069abd0, s_mcflavor_0069ad34,
        s_mcflavor_0069ab98, s_mcflavor_0069ab40, s_mcflavor_0069abc0, s_mcflavor_0069af88,
        s_mcflavor_0069abb8, s_mcflavor_0069ab50, s_mcflavor_0069ab48, s_mcflavor_0069ad3c,
        s_mcflavor_0069aba4, s_mcflavor_0069ada8, s_mcflavor_0069b448, s_mcflavor_0069ab5c,
        s_mcflavor_0069ab30, s_mcflavor_0069adac, s_mcflavor_0069ab90, s_mcflavor_0069b308,
        s_mcflavor_00698b0c, s_mcflavor_0069adf4, s_mcflavor_0069b168, s_mcflavor_0069acc0,
        s_mcflavor_0069b130, s_mcflavor_00697238, s_mcflavor_0069b444, s_mcflavor_0069add4,
        s_mcflavor_0069ad40, s_mcflavor_0069b060, s_mcflavor_0069b440, s_mcflavor_0069b43c,
        s_mcflavor_0069af34, s_mcflavor_0069ace0, s_mcflavor_0069ab3c, s_mcflavor_0069acc4,
        s_mcflavor_0069b438, s_mcflavor_0069ab54, s_mcflavor_0069b434, s_mcflavor_0069b1e4,
        s_mcflavor_0069add8, s_mcflavor_0069b100, s_mcflavor_0069addc, s_mcflavor_0069abb4,
        s_mcflavor_0069b398, s_mcflavor_0069b430, s_mcflavor_0069b4b0, s_mcflavor_0069b320,
        s_mcflavor_0069b42c, s_mcflavor_0069b428, s_mcflavor_0069ae48, s_mcflavor_0069ace4,
        s_mcflavor_0069b424, s_mcflavor_0069abe0, s_mcflavor_0069acc8, s_mcflavor_0069af60,
        s_mcflavor_0069abf0, s_mcflavor_0069b420, s_mcflavor_0069ada0, s_mcflavor_0069b41c,
        s_mcflavor_0069af40, s_mcflavor_0069b418, s_mcflavor_0069b410, s_mcflavor_0069ade8};
    const int weights[64] = {0x5b, 0x30, 0x2d, 0x13, 0x10, 0x10, 0xc, 0xc, 0xb, 0xb, 0xb, 0xa, 0xa,
                             0xa,  9,    9,    9,    8,    6,    6,   6,   5,   5,   5,   5,   5,
                             4,    4,    4,    4,    3,    3,    3,   3,   3,   2,   2,   2,   2,
                             2,    2,    2,    2,    2,    2,    2,   2,   2,   1,   1,   1,   1,
                             1,    1,    1,    1,    1,    1,    1,   1,   1,   1,   1,   1};
    *out += PickWeighted(strings, weights, 0x1d9, false);
  } else {
    const char* strings[10] = {s_mcflavor_0069ab24, s_mcflavor_0069ab2c, s_mcflavor_0069ab18,
                               s_mcflavor_0069ac9c, s_mcflavor_0069ab20, s_mcflavor_0069aec4,
                               s_mcflavor_0069aec0, s_mcflavor_0069b40c, s_mcflavor_0069ab08,
                               s_mcflavor_0069aca8};
    const int weights[10] = {0x56, 0x2b, 0x18, 9, 5, 3, 2, 2, 2, 2};
    *out += PickWeighted(strings, weights, 0xb1, false);
  }
}

// FUNCTION: IMPERIALISM 0x005d3300
CString* GenerateMappedFlavorTextVariantAToSharedString(CString* out) {
  CString temp;
  GenerateMappedFlavorTextVariantA_005d13d0(&temp);
  *out = temp;
  return out;
}

// FUNCTION: IMPERIALISM 0x005d33a0
void GenerateMappedFlavorTextVariantD_005d33a0(CString* out) {
  int flag = FlavorGateFlag(0x11e, 0xfd);
  int count;
  if (flag == 0) {
    const int countWeights[8] = {4, 4, 0x12, 3, 4, 0, 0, 0};
    count = DrawCountNoStep(countWeights, 0x21);
  } else {
    const int countWeights[8] = {0, 0x37, 0x12, 0x6a, 0x24, 0x1e, 8, 0};
    count = DrawCountNoStep(countWeights, 0xfd);
  }
  count = count + 3;

  *out = CString(g_szEmptyString);

  if (flag == 0) {
    // NOTE: this draw MASKS the sample (& 0x1f) instead of taking a modulus.
    const char* strings[5] = {g_szLiteralA_0069872C, s_mcflavor_0069b0bc, s_mcflavor_0069ac00,
                              s_mcflavor_0069abf8, s_mcflavor_0069b0c4};
    const int weights[5] = {0x10, 0xa, 4, 1, 1};
    *out += PickWeighted(strings, weights, 0x1f, true);
  } else {
    const char* strings[20] = {
        s_mcflavor_0069ac44, s_mcflavor_0069ad44, g_szLiteralL_00694250, s_mcflavor_0069ac40,
        s_mcflavor_0069ac28, s_mcflavor_0069ac48, s_mcflavor_0069ac38,   s_mcflavor_0069ac54,
        s_mcflavor_0069ac10, s_mcflavor_0069ac1c, s_mcflavor_0069acec,   s_mcflavor_0069ac24,
        s_mcflavor_0069acf4, s_mcflavor_0069ac0c, s_mcflavor_0069b28c,   s_mcflavor_0069b0a0,
        s_mcflavor_0069b290, s_mcflavor_0069b2c0, s_mcflavor_0069acf8,   s_mcflavor_0069ac4c};
    const int weights[20] = {0x1d, 0x1b, 0x18, 0x14, 0x13, 0x12, 0x12, 0x11, 0xd, 0xc,
                             0xa,  9,    8,    6,    4,    4,    3,    3,    3,   2};
    *out += PickWeighted(strings, weights, 0xf8, false);
  }

  if (1 < count - 1) {
    count = count - 2;
    do {
      flag = (flag == 0);
      if (flag == 0) {
        const char* strings[7] = {s_mcflavor_0069ab2c, s_mcflavor_0069ab18, s_mcflavor_0069ab24,
                                  s_mcflavor_0069ab20, s_mcflavor_0069ac9c, s_mcflavor_0069ab28,
                                  s_mcflavor_0069aca8};
        const int weights[7] = {0xa1, 0x89, 0x88, 0x5f, 0x18, 0xd, 0xc};
        *out += PickWeighted(strings, weights, 0x23f, false);
      } else {
        const char* strings[50] = {
            s_mcflavor_0069ab70, s_mcflavor_00696d10,   s_mcflavor_0069add8, s_mcflavor_0069ab40,
            s_mcflavor_0069abd0, s_mcflavor_0069ad3c,   s_mcflavor_0069ad40, s_mcflavor_0069ab48,
            s_mcflavor_0069abe0, s_mcflavor_0069ada8,   s_mcflavor_0069b2b0, s_mcflavor_0069abb4,
            s_mcflavor_0069aba4, s_mcflavor_0069ab38,   s_mcflavor_0069ab98, s_mcflavor_0069ab5c,
            s_mcflavor_0069ab90, s_mcflavor_0069b128,   s_mcflavor_0069adb0, s_mcflavor_0069ab50,
            s_mcflavor_0069abb8, s_mcflavor_0069b2d4,   s_mcflavor_0069b2cc, s_mcflavor_0069b2d0,
            s_mcflavor_0069b034, s_mcflavor_0069ab9c,   s_mcflavor_0069b130, s_mcflavor_0069acd8,
            s_mcflavor_0069acc8, s_mcflavor_0069adc4,   s_mcflavor_0069b370, s_mcflavor_0069b2d8,
            s_mcflavor_0069acbc, s_mcflavor_0069b2e0,   s_mcflavor_0069af60, s_mcflavor_0069adac,
            s_mcflavor_0069abf0, s_mcflavor_0069b29c,   s_mcflavor_0069b2b8, s_mcflavor_0069adb4,
            s_mcflavor_0069aba0, s_mcflavor_0069af3c,   s_mcflavor_0069accc, s_mcflavor_0069adf4,
            s_mcflavor_0069adcc, s_mcflavor_0069b12c,   s_mcflavor_0069abc0, s_mcflavor_0069b390,
            s_mcflavor_0069ab54, g_szLiteralRb_00698720};
        const int weights[50] = {
            0x56, 0x43, 0x22, 0x1e, 0x1b, 0x16, 0x12, 0xf, 0xd, 0xd, 0xd, 0xd, 0xc, 0xb, 0xb, 9, 9,
            8,    8,    8,    7,    7,    6,    6,    6,   5,   5,   5,   5,   4,   4,   4,   4, 4,
            4,    3,    3,    3,    3,    3,    3,    2,   2,   2,   2,   2,   2,   2,   2,   2};
        *out += PickWeighted(strings, weights, 0x21a, false);
      }
      count = count - 1;
    } while (count != 0);
  }

  if (flag != 0) {
    const char* strings[6] = {s_mcflavor_0069ab18, s_mcflavor_0069ab2c, s_mcflavor_0069ab24,
                              s_mcflavor_0069ab20, s_mcflavor_0069ac9c, s_mcflavor_0069aca8};
    const int weights[6] = {0x48, 0x41, 0x1e, 0x14, 0x13, 8};
    *out += PickWeighted(strings, weights, 0xd0, false);
  }

  // OUTLIER tail (no analogue in the VariantC exemplar): a 1-in-10 raw PRNG gate that,
  // when the built string is short (< 10 chars) and ends in a specific vowel, prepends
  // a prefix. 'o' -> s_mcflavor_0069b534, 'a' -> s_mcflavor_0069b52c.
  g_zoneStatusCodePrngSeed_006a5aec = g_zoneStatusCodePrngSeed_006a5aec * 0x15a4e35 + 1;
  if (static_cast<int>((g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 0x7fff) % 10 == 0) {
    int len = out->GetLength();
    if (len < 10) {
      char last = out->GetAt(len - 1);
      if (last == 'o') {
        *out = CString(s_mcflavor_0069b534) + *out;
      } else if (last == 'a') {
        *out = CString(s_mcflavor_0069b52c) + *out;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005d41a0
CString* GenerateMappedFlavorTextVariantDToSharedString(CString* out) {
  CString temp;
  GenerateMappedFlavorTextVariantD_005d33a0(&temp);
  *out = temp;
  return out;
}
