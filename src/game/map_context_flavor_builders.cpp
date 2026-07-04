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
  unsigned int raw = (g_zoneStatusCodePrngSeed_006a5aec >> 0xc) & 0x7fff;
  int remaining = static_cast<int>(useMask ? (raw & range) : (raw % range)) - weights[0];
  int index = 0;
  while (remaining >= 0) {
    index = index + 1;
    remaining = remaining - weights[index];
  }
  return strings[index];
}

} // namespace

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
