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
      const char* strings[20] = {s_mcflavor_0069ac58, s_mcflavor_0069ac54,
                                 s_mcflavor_0069ac50, s_mcflavor_0069ac4c,
                                 s_mcflavor_0069ac48, s_mcflavor_0069ac44,
                                 s_mcflavor_0069ac40, s_mcflavor_0069ac3c,
                                 s_mcflavor_0069ac38, g_szMovementParseCompareA_00694250,
                                 s_mcflavor_0069ac30, s_mcflavor_0069ac2c,
                                 s_mcflavor_0069ac28, s_mcflavor_0069ac24,
                                 s_mcflavor_0069ac20, s_mcflavor_0069ac1c,
                                 s_mcflavor_0069ac18, s_mcflavor_0069ac14,
                                 s_mcflavor_0069ac10, s_mcflavor_0069ac0c};
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
          s_mcflavor_0069ab90, s_mcflavor_0069ab8c, s_mcflavor_0069ab88, s_mcflavor_00698720,
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
      const char* strings[14] = {
          s_mcflavor_0069ac10, s_mcflavor_0069ad00, s_mcflavor_0069acfc,
          s_mcflavor_0069acf8, s_mcflavor_0069ac44, s_mcflavor_0069ac14,
          s_mcflavor_0069ac40, s_mcflavor_0069ac38, s_mcflavor_0069acf4,
          s_mcflavor_0069acf0, s_mcflavor_0069ac28, g_szMovementParseCompareA_00694250,
          s_mcflavor_0069ac24, s_mcflavor_0069acec};
      const int weights[14] = {3, 3, 2, 2, 2, 7, 3, 1, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x1d, false);
      break;
    }
    case 'V': {
      const char* strings[3] = {s_mcflavor_0069872c, s_mcflavor_0069ace8, s_mcflavor_0069ac00};
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
      text = s_mcflavor_00695794;
      break;
    case 'G': {
      const char* strings[14] = {
          s_mcflavor_0069ac1c, s_mcflavor_0069ac58, g_szMovementParseCompareA_00694250,
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
      text = s_mcflavor_0069872c;
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
      const char* strings[9] = {s_mcflavor_0069abfc, s_mcflavor_0069ac00, s_mcflavor_0069ae10,
                                s_mcflavor_0069872c, s_mcflavor_0069abf8, s_mcflavor_0069ae0c,
                                s_mcflavor_0069ae08, s_mcflavor_0069ae04, s_mcflavor_0069ae00};
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
      const char* strings[3] = {s_mcflavor_0069872c, s_mcflavor_0069ae64, s_mcflavor_0069ac00};
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
      const char* strings[7] = {g_szMovementParseCompareA_00694250,
                                s_mcflavor_0069ac2c,
                                s_mcflavor_0069ac24,
                                s_mcflavor_0069ac40,
                                s_mcflavor_0069ac44,
                                s_mcflavor_0069ac14,
                                s_mcflavor_0069ac58};
      const int weights[7] = {2, 3, 3, 0xa, 5, 0xe, 0xa};
      text = PickWeighted(strings, weights, 0x2f, false);
      break;
    }
    case 'V': {
      const char* strings[3] = {s_mcflavor_0069aedc, s_mcflavor_0069872c, s_mcflavor_0069aed8};
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
      text = s_mcflavor_00695794;
      break;
    case 'G': {
      const char* strings[14] = {
          s_mcflavor_0069ac38, s_mcflavor_0069ac58, s_mcflavor_0069ac44,
          s_mcflavor_0069acf0, s_mcflavor_0069ac10, s_mcflavor_0069af9c,
          s_mcflavor_0069ac14, s_mcflavor_0069acec, s_mcflavor_0069ae74,
          s_mcflavor_0069af98, s_mcflavor_0069ac0c, g_szMovementParseCompareA_00694250,
          s_mcflavor_0069ac54, s_mcflavor_0069ad48};
      const int weights[14] = {1, 4, 7, 1, 4, 1, 1, 1, 1, 1, 2, 1, 1, 2};
      text = PickWeighted(strings, weights, 0x1c, false);
      break;
    }
    case 'K': {
      const char* strings[12] = {
          s_mcflavor_0069ac44, s_mcflavor_0069af98, s_mcflavor_0069ac10,
          s_mcflavor_0069ac0c, s_mcflavor_0069ac38, g_szMovementParseCompareA_00694250,
          s_mcflavor_0069af94, s_mcflavor_0069ad48, s_mcflavor_0069af9c,
          s_mcflavor_0069ac48, s_mcflavor_0069ac58, s_mcflavor_0069acec};
      const int weights[12] = {4, 3, 2, 1, 2, 2, 1, 1, 1, 1, 1, 1};
      text = PickWeighted(strings, weights, 0x14, false);
      break;
    }
    case 'R': {
      const char* strings[2] = {s_mcflavor_0069872c, s_mcflavor_0069af90};
      const int weights[2] = {1, 1};
      text = PickWeighted(strings, weights, 1, true);
      break;
    }
    case 'V': {
      const char* strings[3] = {s_mcflavor_0069872c, s_mcflavor_0069ac00, s_mcflavor_0069af8c};
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
          s_mcflavor_0069af84, s_mcflavor_0069af80, s_mcflavor_0069af7c, s_mcflavor_0069af78,
          s_mcflavor_0069af74, s_mcflavor_00698720, s_mcflavor_00696d10, s_mcflavor_0069af70,
          s_mcflavor_0069add4, s_mcflavor_0069aba4, s_mcflavor_0069ab9c, s_mcflavor_0069af6c,
          s_mcflavor_0069adc4, s_mcflavor_0069acbc, s_mcflavor_0069af68, s_mcflavor_0069ab40,
          s_mcflavor_006976e0, s_mcflavor_0069ace4, s_mcflavor_0069af64, s_mcflavor_0069ab70,
          s_mcflavor_0069adb4, s_mcflavor_0069ad34, s_mcflavor_0069af60, s_mcflavor_0069af5c,
          s_mcflavor_0069ae34, s_mcflavor_0069af88, s_mcflavor_0069af58, s_mcflavor_0069af54,
          s_mcflavor_0069af50, s_mcflavor_0069adbc, s_mcflavor_0069af4c, s_mcflavor_0069af48,
          s_mcflavor_0069af44, s_mcflavor_0069af40, s_mcflavor_0069aba8, s_mcflavor_0069af3c,
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
      const char* strings[18] = {
          s_mcflavor_0069af98, s_mcflavor_00696674, g_szMovementParseCompareA_00694250,
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
      const char* strings[8] = {s_mcflavor_0069b0c4, s_mcflavor_0069872c, s_mcflavor_0069ac00,
                                s_mcflavor_0069ae0c, s_mcflavor_0069b0c0, s_mcflavor_0069b0bc,
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
      const char* strings[4] = {s_mcflavor_0069ae10, s_mcflavor_0069ae08, s_mcflavor_0069872c,
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
      text = s_mcflavor_00695794;
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
      const char* strings[6] = {s_mcflavor_0069ac00, s_mcflavor_0069b0c0, s_mcflavor_0069872c,
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
      const char* strings[10] = {s_mcflavor_0069ac44,
                                 s_mcflavor_0069ac14,
                                 s_mcflavor_0069ac10,
                                 s_mcflavor_0069ac40,
                                 s_mcflavor_0069b0a0,
                                 s_mcflavor_0069acf0,
                                 g_szMovementParseCompareA_00694250,
                                 s_mcflavor_0069ac54,
                                 s_mcflavor_0069ac0c,
                                 s_mcflavor_0069ac2c};
      const int weights[10] = {8, 9, 2, 1, 1, 1, 2, 6, 4, 2};
      text = PickWeighted(strings, weights, 0x24, false);
      break;
    }
    case 'V': {
      const char* strings[4] = {s_mcflavor_0069b0bc, s_mcflavor_0069872c, s_mcflavor_0069ac00,
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
