#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

namespace {

// RandomSetupFlow captures map-generation state while the retail random-setup screen is
// current, before this scenario accepts the setup and reaches the strategic map. Reaching
// this script therefore proves that the captures came from the real setup path rather than
// from a constructed fixture or a test-only map generator entry point.
class RandomMapGenerationCaptureTestCase : public EasyMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    RT_PASS();
    RT_END();
  }
};

class ExplicitPlanetRandomMapGenerationCaptureTestCase : public RandomMapGenerationCaptureTestCase {
public:
  explicit ExplicitPlanetRandomMapGenerationCaptureTestCase(const char* planetSeed)
      : planetSeed(planetSeed) {}

  const char* RandomSetupPlanetSeed() const override {
    return planetSeed;
  }

private:
  const char* planetSeed;
};

#define EXPLICIT_PLANET_CASE(className, seedText)                                                  \
  class className##Case : public ExplicitPlanetRandomMapGenerationCaptureTestCase {                \
  public:                                                                                          \
    className##Case() : ExplicitPlanetRandomMapGenerationCaptureTestCase(seedText) {}              \
  };

EXPLICIT_PLANET_CASE(OrdinaryTerrainRandomMapGenerationTest, "ordinary")
EXPLICIT_PLANET_CASE(TunedTerrainRandomMapGenerationTest, "@^>DmHfSpRc")
EXPLICIT_PLANET_CASE(DuneTerrainRandomMapGenerationTest, "Dune")
EXPLICIT_PLANET_CASE(MirkwoodTerrainRandomMapGenerationTest, "Mirkwood")
EXPLICIT_PLANET_CASE(EclectiaTerrainRandomMapGenerationTest, "Eclectia")

} // namespace

RUNTIME_TEST_FACTORY(RandomMapGenerationCaptureTestCase, RandomMapGenerationCaptureTest)
RUNTIME_TEST_FACTORY(OrdinaryTerrainRandomMapGenerationTestCase,
                     OrdinaryTerrainRandomMapGenerationTest)
RUNTIME_TEST_FACTORY(TunedTerrainRandomMapGenerationTestCase, TunedTerrainRandomMapGenerationTest)
RUNTIME_TEST_FACTORY(DuneTerrainRandomMapGenerationTestCase, DuneTerrainRandomMapGenerationTest)
RUNTIME_TEST_FACTORY(MirkwoodTerrainRandomMapGenerationTestCase,
                     MirkwoodTerrainRandomMapGenerationTest)
RUNTIME_TEST_FACTORY(EclectiaTerrainRandomMapGenerationTestCase,
                     EclectiaTerrainRandomMapGenerationTest)
