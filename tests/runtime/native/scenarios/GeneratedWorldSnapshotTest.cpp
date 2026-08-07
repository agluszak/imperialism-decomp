#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

namespace {

// RandomSetupFlow captures the generated world while the retail random-setup screen is
// current, before this scenario accepts the setup and reaches the strategic map. Reaching
// this script therefore proves that the snapshot came from the real setup path rather than
// from a constructed fixture or a test-only map generator entry point.
class GeneratedWorldSnapshotTestCase : public EasyMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    RT_PASS();
    RT_END();
  }
};

class ExplicitPlanetGeneratedWorldSnapshotTestCase : public GeneratedWorldSnapshotTestCase {
public:
  explicit ExplicitPlanetGeneratedWorldSnapshotTestCase(const char* planetSeed)
      : planetSeed(planetSeed) {}

  const char* RandomSetupPlanetSeed() const override {
    return planetSeed;
  }

private:
  const char* planetSeed;
};

#define EXPLICIT_PLANET_CASE(className, seedText)                                                  \
  class className##Case : public ExplicitPlanetGeneratedWorldSnapshotTestCase {                    \
  public:                                                                                          \
    className##Case() : ExplicitPlanetGeneratedWorldSnapshotTestCase(seedText) {}                  \
  };

EXPLICIT_PLANET_CASE(OrdinaryTerrainGeneratedWorldTest, "ordinary")
EXPLICIT_PLANET_CASE(TunedTerrainGeneratedWorldTest, "@^>DmHfSpRc")
EXPLICIT_PLANET_CASE(DuneTerrainGeneratedWorldTest, "Dune")
EXPLICIT_PLANET_CASE(MirkwoodTerrainGeneratedWorldTest, "Mirkwood")
EXPLICIT_PLANET_CASE(EclectiaTerrainGeneratedWorldTest, "Eclectia")

} // namespace

RUNTIME_TEST_FACTORY(GeneratedWorldSnapshotTestCase, GeneratedWorldSnapshotTest)
RUNTIME_TEST_FACTORY(OrdinaryTerrainGeneratedWorldTestCase, OrdinaryTerrainGeneratedWorldTest)
RUNTIME_TEST_FACTORY(TunedTerrainGeneratedWorldTestCase, TunedTerrainGeneratedWorldTest)
RUNTIME_TEST_FACTORY(DuneTerrainGeneratedWorldTestCase, DuneTerrainGeneratedWorldTest)
RUNTIME_TEST_FACTORY(MirkwoodTerrainGeneratedWorldTestCase, MirkwoodTerrainGeneratedWorldTest)
RUNTIME_TEST_FACTORY(EclectiaTerrainGeneratedWorldTestCase, EclectiaTerrainGeneratedWorldTest)
