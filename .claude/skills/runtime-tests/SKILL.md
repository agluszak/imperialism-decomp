---
name: runtime-tests
description: Write and debug native semantic runtime tests for the Imperialism decomp — the linear-script API (RT_ macros, script scenarios, screens, flows), the fast authoring loop, control discovery, and the MSVC500 rules the protothread imposes. Use when adding a runtime scenario, migrating one off the old phase-machine shape, diagnosing a stall or a runtime-test failure, or extending a screen driver.
---

# Native runtime tests

Runtime tests drive the real game in-process on its UI thread: no coordinate automation, no
timers, no polling (`just runtime-source-policy-gate` rejects all three). A scenario acts by
activating real controls and asserts on real game state.

## Write a linear script

```sh
just runtime-new player_buy_order_does_not_sell easy-map   # skeleton + catalog entry
just runtime-dev  player_buy_order_does_not_sell           # compile what changed, run
just runtime-test player_buy_order_does_not_sell           # canonical gated path
```

A scenario picks a **start point** and overrides `Script()` only:

| base | starts at |
| --- | --- |
| `EasyMapScriptScenario` | random game, Easy, on the map (no capital selection) |
| `IntroductoryMapScriptScenario` | Introductory, which also shows the opening newspaper |
| `CombinedMapScriptScenario` | Normal or above, after the capital is picked |
| `LoadedMapScriptScenario` | a saved game from a fixture |
| `ManagersReadyScriptScenario` | managers only: no window, no navigation, no screen |

Each base fixes its difficulty *and* the checkpoint hook that difficulty implies. Do not
override `DifficultyLevel`, `OnMapReadyWithoutCapitalSelection` or `OnCombinedMapReady` in a
test — the pair has to agree, and a mismatch means the hook silently never fires.

```cpp
class PlayerBuyOnlyTradeTestCase : public EasyMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_OPEN_SCREEN("open the Board of Trade", StrategicMap().OpenTrade(),
                   TTradeScreenPicture, kTurnEventTradeOverview);
    RT_ACTIVATE_AND_AWAIT("select the iron bid", Trade().SelectBid(kResourceIron),
                          Trade().BidSelected(kResourceIron), kObserveGameStateChanged);
    RT_CLOSE_TO_MAP("leave the Board of Trade", Trade().Close());

    RT_REQUIRE_EQ(-1, Player()->GetTradeOffersFor(kResourceIron));
    RT_RUN(endTurn.RejectOffers().ToNextStrategicMap(*this));
    RT_REQUIRE(PlayerExecutedNoSales());
    RT_PASS();

    RT_END();
  }

private:
  EndTurnFlow endTurn;   // state that survives a yield is a member field
};

RUNTIME_TEST_FACTORY(PlayerBuyOnlyTradeTestCase, PlayerBuyOnlyTradeTest)
```

The vocabulary is in `tests/runtime/native/scenarios/RuntimeScriptMacros.h`; read it before
writing a script. Assertions build their own text — expression, both values, source location,
phase, current turn event, current view class, modal depth — so never hand-format a failure.

## The MSVC500 rules the protothread imposes

`Script()` is a protothread: a saved program counter plus `case __LINE__` labels. All of this
is verified against the real compiler by `just protothread-probe --run`; re-run it after
changing a macro.

1. **State that survives a yield is a member field.** The compiler enforces it —
   `C2360: initialization of 'x' is skipped by 'case' label` — so an initialized local at
   statement level, or a `for (int i = ...)` counter, is a compile error. That is the rule
   working for you. Locals are fine inside a brace block containing no `RT_` macro.
2. **An *uninitialized* POD local is accepted and does not survive the yield.** Nothing catches
   this. Don't.
3. **Never put an `RT_` macro inside `try`/`catch`.** MSVC500 accepts it and the resumed code
   skips the try's EH setup, so the catch never fires and the CRT aborts.
4. **One `RT_` macro per source line** (two collide as `C2196`).
5. **A loop that handles a step must yield on every path.** "An expected screen is showing" is
   not "progress was made": the screen does not change until the game gets a turn to act, so
   awaiting the former busy-loops inside `Script()`. Use `RT_YIELD` after handling, and await
   only when nothing was handled.
6. New headers need a traditional `#ifndef` guard — `#pragma once` keys on the include
   spelling, so a header reached both as `"X.h"` and `"scenarios/X.h"` is parsed twice.
7. Forward-declare `struct RuntimeControlSelector` as `struct`: MSVC500 mangles struct and
   class differently, so `class` compiles and fails to link.
8. Friendship is not inherited — a concrete `RuntimeScriptFragment` reaches the scenario
   through the base's forwarders, not through `Host()`.

## Screens and flows, not control trees

A script must not touch `g_ModalViewStack`, `g_pViewMgr->currentTurnEventCode`,
`CurrentMainView`, `ResolveControlByTag`, `RUNTIME_CLASS`, `RuntimeUiDriver`, `Await`,
`ContinueAfterAction` or `EnterScenarioStep`. `just runtime-script-debt-gate` is a hard ban on all
of them in `scenarios/*Test.cpp` -- every scenario is a linear script, so there is no baseline and
no count to bless. A hit means extending the boundary is the work, not reaching through it.

Those mechanics live in `tests/runtime/native/screens/`, `flows/` and `probes/`. Screens are
`MainMenuScreen`, `RandomSetupScreen`, `CapitalSelectionScreen`, `StrategicMapScreen`,
`TradeScreen`, `DealBookScreen`, `OfferScreen`, `TransportScreen`, `DiplomacyScreen`, `CityScreen`,
`CityBuildingScreen`, `LoadSaveScreen`, `NewspaperScreen`, `ArmyBookScreen`, `EngineerDialogScreen`,
`ModalScreen` and `UiAnimationRegistry`; probes are `StrategicMapProbe`, `CivilianProbe` and
`StartingCiviliansProbe`. A probe is for what a screen cannot express: pixel captures,
render-surface comparisons and model-collection identity.

A screen derives from `MainViewScreen`, which gives it identity (class + turn event + **no modal
above it**), a failure that names what *is* current, and activation that propagates
`RuntimeUiDriver::RequireControl`'s diagnosis. Actions return `RuntimeActionResult`, never
`bool` — the bool drivers discarded the only useful part of a failure.

Adding a screen is the normal way to give a script new vocabulary; put the domain's magic
constants (a card's bitmap ids, a page cache's layout) in the screen so the script asks a question
instead of comparing numbers.

A screen's identity is its view class *and* its turn event: the same class on a different event is
a different screen (`CapitalSelectionScreen` and `StrategicMapScreen` are both `TMapUberPicture`).
One screen has no class of its own -- the transport ledger's root is a plain `TPicture` -- and says
so.

`EndTurnFlow` and `OpenCityBuildingFlow`/`CloseCityBuildingFlow` are `RuntimeScriptFragment`s:
reusable sub-scripts with their own program counter, driven by `RT_RUN`, written with the
`RT_FRAGMENT_*` macros. Write fragments with those macros — hand-rolled, the counter store and its
`case` label land on different lines and never match. Add a flow only where duplication already
exists; a fragment that runs twice in one scenario must rewind itself (`BeginFragment`).

A script normally starts at its base's checkpoint and runs to `RT_PASS`. One scenario instead hands
navigation *back* mid-run: `CapitalSelectionScriptScenario` begins the script at capital selection,
and `RestartRandomGameAtStrategicMapEntry()` returns control to the flow, which resumes the same
script (`ResumeScript`, which keeps the program counter) once the map is ready. Use it only for that
shape — every other scenario wants a plain start point.

## Debugging a failure or a stall

A stall reports what it was waiting for:

```
awaiting=!ModalScreen::AnyPresent() @ EndTurnFlow.cpp:148 [ui_state_changed]
```

with the same object in `heartbeat.json` and the result file. Read it first; it usually names
the wrong predicate directly.

- `just runtime-tree NAME --paths` — the real tag hierarchy the run last saw, with each node's
  event number, actionable state and selector path. Recorded on any non-passing run. Read
  selectors here instead of guessing from a UI builder.
- The run bundle's `gdb-rerun/symbolized-stack-*.txt` names the frame. Frame #0 inside
  `Script()` itself means the script is busy-looping (see rule 5 above).
- `RT_CHECK` accumulates non-fatal failures so one run reports several problems.

## Before committing

`just runtime-test-build`, `just runtime-harness-lint` (clang-cl — the only place `override` is
real, so it is what catches a mistyped `Script()`), `just runtime-test-suite pr`, and
`just runtime-check full --require-fixtures` at a stage boundary.

**`tests/runtime/expectations/` must not change.** Those files pin game state, not phase
names, so a faithful migration leaves them byte-identical. An expectation that needs editing is
the signal that behaviour changed — investigate, do not update it.

A runtime failure is a symptom of unfaithfully ported code, not a test to relax. Never close a
bug by adding a guard, a guessed value, an alternate behaviour or a test-only bypass; repair the
recovered source, data, resources or control flow so the retail path is what the test traverses.
