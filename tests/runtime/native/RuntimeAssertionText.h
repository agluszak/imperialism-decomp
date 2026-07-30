#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeAssertionText is test-only and must not be included in the production build
#endif

#include "game/mfc.h"

// Failure text for a runtime assertion, with the run context appended automatically.
//
// Scenarios used to hand-write both halves of every failure: the prose, and a wsprintfA
// call formatting the actual values into a fixed char buffer (27 such formats across the
// suite, with buffers hand-sized from 96 to 256 bytes). Worse, the prose had to be
// pre-escaped as a JSON fragment because that is what FailScenario consumes, so every
// call site carried "\"...\"" quoting.
//
// These builders replace both. The caller supplies the stringised expression and the two
// values; the context block -- source location, phase, current turn event, current view
// class, modal depth -- is filled in from the run, because that is exactly what a reader
// needs and exactly what nobody remembers to include:
//
//   requirement: player->GetTradeOffersFor(kResourceIron) == -1
//   expected: -1
//   actual: 0
//   source: PlayerBuyOnlyTradeTest.cpp:42
//   phase: close_trade
//   current event: 0x07dd
//   current view: TMapUberPicture
//   modal depth: 0
//
// The result is plain text for RuntimeScenario::FailScenarioText, which escapes it once.
// MSVC500 has no variadic templates and no variadic macros, so value formatting is a
// fixed overload set; add an overload rather than reaching for a template.

class RuntimeRun;

namespace RuntimeAssertionText {

// A bare requirement with no value pair, e.g. RT_REQUIRE(expr).
CString Requirement(const RuntimeRun& run, const char* expression, const char* file, int line);

// A requirement over two values. `relation` names the comparison as written ("==", "!=")
// so the text reads the same way the source does.
CString RequirementValues(const RuntimeRun& run, const char* expression, const char* relation,
                          const CString& expected, const CString& actual, const char* file,
                          int line);

// Free-form failure text with the same context block appended.
CString Failure(const RuntimeRun& run, const char* text, const char* file, int line);

// Renderers for the value pair. Overloads, not a template: MSVC500's template support is
// not worth spending here, and the set of things a scenario compares is small and known.
CString Value(int value);
CString Value(unsigned int value);
CString Value(short value);
CString Value(unsigned short value);
CString Value(long value);
CString Value(unsigned long value);
CString Value(bool value);
CString Value(const void* value);
CString Value(const char* value);
CString Value(const CString& value);

} // namespace RuntimeAssertionText
