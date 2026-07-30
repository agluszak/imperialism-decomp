#!/usr/bin/env python3
"""Ask MSVC500 whether a `switch`/`case __LINE__` protothread is a usable test-authoring base.

Background: native runtime scenarios are hand-written asynchronous state machines because
``RuntimeScenario::AdvanceScenario()`` is re-entered per observation and yields by
returning.  The linear-script authoring API replaces the per-test phase enum with a saved
program counter and Duff's-device ``case __LINE__`` labels hidden behind macros.  The whole
design rests on the 1997 compiler accepting that pattern, and on MSVC's
"initialization is skipped by case label" rule being a *usable* constraint rather than a
blocker -- so this probe compiles each hazard as its own translation unit with the exact
harness flags and reports what CL actually said, instead of what a modern compiler would.

``--run`` additionally links and executes a protothread under Wine and compares its
resume trace against the expected order, which is the only way to prove that resuming at
a ``case`` label really continues mid-function with member state intact.

Run this before changing the macro layer in
``tests/runtime/native/scenarios/RuntimeScriptMacros.h``.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from tools.common.repo import repo_root_from_file


DOCKER_IMAGE = "imperialism-msvc500:latest"

# Exactly the ImperialismRuntimeHarness compile line: the global RelWithDebInfo flags plus
# the target_compile_options block at CMakeLists.txt:247.  /Z7 is omitted (debug records
# only); /Od /Oy- matter because they are what the harness objects really use.
HARNESS_FLAGS = "/DWIN32 /D_WINDOWS /Zm1000 /MT /DNDEBUG /W3 /GX /GR- /Od /Oy-"

# The macro layer under test.  Kept verbatim here so the probe pins the exact text that
# RuntimeScriptMacros.h ships; a change there should be made here first and re-probed.
MACROS = r"""
#define RT_BEGIN() switch (ScriptProgramCounter()) { case 0:

#define RT_AWAIT(condition, observations)                                                 \
  do {                                                                                   \
    SetScriptProgramCounter(__LINE__);                                                    \
    case __LINE__:                                                                        \
    if (!(condition)) {                                                                   \
      AwaitScript((observations), #condition, __FILE__, __LINE__);                         \
      return;                                                                             \
    }                                                                                     \
  } while (0)

#define RT_ACTION(label, action)                                                          \
  do {                                                                                   \
    if (!RunScriptAction((label), (action), __FILE__, __LINE__)) return;                  \
    SetScriptProgramCounter(__LINE__);                                                    \
    ContinueAfterAction();                                                                \
    return;                                                                               \
    case __LINE__:;                                                                        \
  } while (0)

#define RT_RUN(fragmentCall)                                                              \
  do {                                                                                   \
    SetScriptProgramCounter(__LINE__);                                                    \
    case __LINE__:                                                                        \
    {                                                                                     \
      int rtStatus = (fragmentCall);                                                      \
      if (rtStatus != kScriptComplete) return;                                            \
    }                                                                                     \
  } while (0)

#define RT_PASS()                                                                         \
  do {                                                                                   \
    PassScript();                                                                          \
    return;                                                                               \
  } while (0)

#define RT_FAIL(text)                                                                     \
  do {                                                                                   \
    FailScript((text), __FILE__, __LINE__);                                                \
    return;                                                                               \
  } while (0)

#define RT_REQUIRE(expr)                                                                  \
  do {                                                                                   \
    if (!(expr)) {                                                                        \
      FailRequirement(#expr, __FILE__, __LINE__);                                          \
      return;                                                                             \
    }                                                                                     \
  } while (0)

#define RT_REQUIRE_EQ(expected, actual)                                                   \
  do {                                                                                   \
    if (!((expected) == (actual))) {                                                      \
      FailRequirementEq(#actual " == " #expected, (expected), (actual), __FILE__,          \
                        __LINE__);                                                         \
      return;                                                                             \
    }                                                                                     \
  } while (0)

#define RT_END()                                                                          \
    default: break; }                                                                      \
    FailScript("script returned without RT_PASS()", __FILE__, __LINE__)

// Fragment vocabulary.  A fragment yields a status instead of void, so it needs its own
// macros -- and it MUST use them: hand-rolling the pattern puts the program-counter store
// and the `case` label on two different source lines, which silently never match.  Inside
// a macro every __LINE__ collapses to the invocation line, which is the whole trick.
#define RT_FRAGMENT_BEGIN() switch (FragmentProgramCounter()) { case 0:

#define RT_FRAGMENT_AWAIT(condition, observations)                                         \
  do {                                                                                   \
    SetFragmentProgramCounter(__LINE__);                                                   \
    case __LINE__:                                                                        \
    if (!(condition)) {                                                                   \
      AwaitFragment((observations), #condition, __FILE__, __LINE__);                        \
      return kScriptRunning;                                                              \
    }                                                                                     \
  } while (0)

#define RT_FRAGMENT_YIELD()                                                               \
  do {                                                                                   \
    SetFragmentProgramCounter(__LINE__);                                                   \
    return kScriptRunning;                                                                \
    case __LINE__:;                                                                        \
  } while (0)

#define RT_FRAGMENT_DONE()                                                                \
  do {                                                                                   \
    return kScriptComplete;                                                               \
  } while (0)

#define RT_FRAGMENT_END()                                                                 \
    default: break; }                                                                      \
    return kScriptFailed
"""

# A stand-in for RuntimeScriptScenario: the same member-function surface the macros call,
# so the probe exercises real name lookup rather than free functions.
SCENARIO_BASE = r"""
enum { kScriptRunning = 0, kScriptComplete = 1, kScriptFailed = 2 };

// Stands in for MFC CString: a non-POD with a non-trivial ctor/dtor, which is what makes
// the "initialization skipped by case label" and /GX interactions worth probing.
class ProbeString {
public:
  ProbeString() : length(0) { buffer[0] = 0; }
  ProbeString(const char* text);
  ~ProbeString() { buffer[0] = 0; }
  const char* Text() const { return buffer; }
private:
  char buffer[64];
  int length;
};

class ProbeScenario {
public:
  ProbeScenario() : scriptProgramCounter(0), armed(0), finished(0), traceLength(0) {
    trace[0] = 0;
  }
  virtual ~ProbeScenario() {}
  virtual void Script() {}

  void Drive(int steps);
  const char* Trace() const { return trace; }

protected:
  int ScriptProgramCounter() const { return scriptProgramCounter; }
  void SetScriptProgramCounter(int line) { scriptProgramCounter = line; }
  void AwaitScript(unsigned int observations, const char* expression, const char* file,
                   int line);
  bool RunScriptAction(const char* label, bool actionSucceeded, const char* file, int line);
  void ContinueAfterAction() { armed = 1; }
  void PassScript();
  void FailScript(const char* text, const char* file, int line);
  void FailRequirement(const char* expr, const char* file, int line);
  void FailRequirementEq(const char* expr, int expected, int actual, const char* file,
                         int line);
  void FailRequirementEq(const char* expr, const char* expected, const char* actual,
                         const char* file, int line);
  void FailRequirementEq(const char* expr, void* expected, void* actual, const char* file,
                         int line);
  void Note(const char* mark);

  int scriptProgramCounter;
  int armed;
  int finished;

private:
  char trace[256];
  int traceLength;
};

extern void ProbeSink(void* p);
extern int ProbeSource(void);
extern void ProbeMayThrow(void);
"""


@dataclass(frozen=True)
class Case:
    name: str
    expectation: str  # "compiles" or "rejected"
    why: str
    body: str
    members: str = ""


def _cases() -> tuple[Case, ...]:
    return (
        Case(
            "baseline",
            "compiles",
            "the plain protothread: begin, await, action, pass",
            """
    RT_BEGIN();
    RT_ACTION("open", ProbeSource() != 0);
    RT_AWAIT(ProbeSource() != 0, 1);
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "pod_local_initialized_at_statement_level",
            "rejected",
            "an initialized POD local whose scope spans a case label (expected C2360/C2362)"
            " -- this is the rule that forces cross-yield state into member fields",
            """
    RT_BEGIN();
    int value = ProbeSource();
    RT_AWAIT(value != 0, 1);
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "pod_local_uninitialized_at_statement_level",
            "compiles",
            "an UNinitialized POD local spanning a case label -- accepted, and therefore a"
            " footgun the docs must call out (its value does not survive the yield)",
            """
    RT_BEGIN();
    int value;
    value = ProbeSource();
    RT_AWAIT(value != 0, 1);
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "pod_local_in_brace_block",
            "compiles",
            "the sanctioned workaround: an initialized local inside a brace block that"
            " contains no RT_ macro",
            """
    RT_BEGIN();
    {
      int value = ProbeSource();
      ProbeSink(&value);
    }
    RT_AWAIT(ProbeSource() != 0, 1);
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "nonpod_local_at_statement_level",
            "rejected",
            "a non-POD local (CString-shaped) spanning a case label",
            """
    RT_BEGIN();
    ProbeString label("phase");
    RT_AWAIT(label.Text()[0] != 0, 1);
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "nonpod_local_in_brace_block",
            "compiles",
            "a non-POD local inside a yield-free brace block, with /GX active",
            """
    RT_BEGIN();
    {
      ProbeString label("phase");
      ProbeSink((void*)label.Text());
    }
    RT_AWAIT(ProbeSource() != 0, 1);
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "while_loop_around_yield",
            "compiles",
            "a while loop containing both an action and an await, counter in a member"
            " field (the MapZoomToggleTest shape)",
            """
    RT_BEGIN();
    while (cycles < 2) {
      RT_ACTION("zoom out", ProbeSource() != 0);
      RT_AWAIT(ProbeSource() != 0, 1);
      ++cycles;
    }
    RT_PASS();
    RT_END();
""",
            members="  int cycles;\n",
        ),
        Case(
            "for_loop_with_member_counter",
            "compiles",
            "a for loop whose induction variable is a member field",
            """
    RT_BEGIN();
    for (cycles = 0; cycles < 3; ++cycles) {
      RT_ACTION("step", ProbeSource() != 0);
    }
    RT_PASS();
    RT_END();
""",
            members="  int cycles;\n",
        ),
        Case(
            "for_loop_with_local_counter",
            "rejected",
            "a for loop declaring its own induction variable -- the initialization spans a"
            " case label, so the compiler rejects exactly the counter that would reset on"
            " every resume",
            """
    RT_BEGIN();
    for (int i = 0; i < 3; ++i) {
      RT_ACTION("step", ProbeSource() != 0);
    }
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "await_inside_if_block",
            "compiles",
            "a case label nested inside an if block inside the switch",
            """
    RT_BEGIN();
    if (ProbeSource() != 0) {
      RT_AWAIT(ProbeSource() != 0, 1);
    }
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "await_inside_try_block",
            "compiles",
            "a case label inside a try block -- MSVC500 ACCEPTS this, so it cannot be"
            " caught by the compiler; the --run try probe decides whether EH survives the"
            " resume and therefore whether the source-policy gate must ban it",
            """
    RT_BEGIN();
    try {
      RT_AWAIT(ProbeSource() != 0, 1);
      ProbeMayThrow();
    } catch (...) {
    }
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "duplicate_case_on_one_line",
            "rejected",
            "two RT_ macros on the same source line collide on case __LINE__ (expected"
            " C2196) -- a compile error, never a silent misresume",
            """
    RT_BEGIN();
    RT_AWAIT(ProbeSource() != 0, 1); RT_AWAIT(ProbeSource() != 1, 1);
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "requirements_and_fail",
            "compiles",
            "the fixed-arity assertion macros against the overload set (no variadic macros"
            " in MSVC5)",
            """
    RT_BEGIN();
    RT_REQUIRE(ProbeSource() != 0);
    RT_REQUIRE_EQ(1, ProbeSource());
    RT_REQUIRE_EQ("expected", "actual");
    RT_AWAIT(ProbeSource() != 0, 1);
    if (ProbeSource() == 99) {
      RT_FAIL("probe forced failure");
    }
    RT_PASS();
    RT_END();
""",
        ),
        Case(
            "fragment_nested_protothread",
            "compiles",
            "RT_RUN driving a fragment that owns its own program counter (the EndTurnFlow"
            " shape)",
            """
    RT_BEGIN();
    RT_ACTION("begin turn", ProbeSource() != 0);
    RT_RUN(fragment.Advance(*this));
    RT_REQUIRE(fragment.Finished());
    RT_PASS();
    RT_END();
""",
            members="  ProbeFragment fragment;\n",
        ),
        Case(
            "deep_nesting_and_switch_inside_script",
            "compiles",
            "an author-written switch nested inside the protothread switch, with a yield"
            " after it",
            """
    RT_BEGIN();
    switch (ProbeSource()) {
    case 1:
      ProbeSink(0);
      break;
    default:
      break;
    }
    RT_AWAIT(ProbeSource() != 0, 1);
    RT_PASS();
    RT_END();
""",
        ),
    )


# The fragment used by the nested-protothread case: the same protothread shape, but it
# yields a status instead of returning void, which is what makes RT_RUN re-entrant.
FRAGMENT = r"""
class ProbeScenario;

class ProbeFragment {
public:
  ProbeFragment() : fragmentProgramCounter(0), done(0), steps(0) {}
  int Advance(ProbeScenario& scenario);
  bool Finished() const { return done != 0; }
  int Steps() const { return steps; }
protected:
  int FragmentProgramCounter() const { return fragmentProgramCounter; }
  void SetFragmentProgramCounter(int line) { fragmentProgramCounter = line; }
  void AwaitFragment(unsigned int, const char*, const char*, int) {}
private:
  int fragmentProgramCounter;
  int done;
  int steps;
};

inline int ProbeFragment::Advance(ProbeScenario&) {
  RT_FRAGMENT_BEGIN();
  ++steps;
  RT_FRAGMENT_YIELD();
  ++steps;
  RT_FRAGMENT_AWAIT(steps >= 2, 1);
  done = 1;
  RT_FRAGMENT_DONE();
  RT_FRAGMENT_END();
}
"""

SUPPORT = r"""
ProbeString::ProbeString(const char* text) : length(0) {
  int index = 0;
  while (text != 0 && text[index] != 0 && index < 63) {
    buffer[index] = text[index];
    ++index;
  }
  buffer[index] = 0;
  length = index;
}

void ProbeScenario::AwaitScript(unsigned int, const char* expression, const char*, int) {
  (void)expression;
  armed = 1;
}

bool ProbeScenario::RunScriptAction(const char* label, bool actionSucceeded, const char*,
                                   int) {
  Note(label);
  if (!actionSucceeded) {
    finished = kScriptFailed;
    return false;
  }
  return true;
}

void ProbeScenario::PassScript() {
  Note("pass");
  finished = kScriptComplete;
}

void ProbeScenario::FailScript(const char* text, const char*, int) {
  Note(text);
  finished = kScriptFailed;
}

void ProbeScenario::FailRequirement(const char* expr, const char*, int) {
  Note(expr);
  finished = kScriptFailed;
}

void ProbeScenario::FailRequirementEq(const char* expr, int, int, const char*, int) {
  Note(expr);
  finished = kScriptFailed;
}

void ProbeScenario::FailRequirementEq(const char* expr, const char*, const char*,
                                      const char*, int) {
  Note(expr);
  finished = kScriptFailed;
}

void ProbeScenario::FailRequirementEq(const char* expr, void*, void*, const char*, int) {
  Note(expr);
  finished = kScriptFailed;
}

void ProbeScenario::Note(const char* mark) {
  int index = 0;
  if (traceLength > 0 && traceLength < 250) {
    trace[traceLength] = '|';
    ++traceLength;
  }
  while (mark != 0 && mark[index] != 0 && traceLength < 250) {
    trace[traceLength] = mark[index];
    ++traceLength;
    ++index;
  }
  trace[traceLength] = 0;
}

void ProbeScenario::Drive(int steps) {
  int step = 0;
  for (step = 0; step < steps && finished == 0; ++step) {
    armed = 0;
    Script();
  }
}

void ProbeSink(void* p) { (void)p; }
int ProbeSource(void) { return 1; }
void ProbeMayThrow(void) {}
"""


def case_source(case: Case) -> str:
    members = case.members or ""
    return "".join(
        (
            SCENARIO_BASE,
            MACROS,
            FRAGMENT,
            "class ProbeCase : public ProbeScenario {\n",
            "public:\n",
            "  ProbeCase() { ProbeReset(); }\n",
            "  void Script();\n",
            "private:\n",
            "  void ProbeReset() { ProbeResetMembers(); }\n",
            "  void ProbeResetMembers();\n",
            members,
            "};\n\n",
            "void ProbeCase::ProbeResetMembers() {}\n\n",
            "void ProbeCase::Script() {",
            case.body,
            "}\n\n",
            SUPPORT,
        )
    )


# The behavioural program: proves a resume really continues mid-function with member
# state intact, rather than restarting the script.
RUN_SOURCE_BODY = """
    RT_BEGIN();
    Note("start");
    RT_ACTION("action1", true);
    Note("after1");
    RT_AWAIT(gate >= 1, 1);
    Note("gate1");
    while (cycles < 2) {
      RT_ACTION("loop", true);
      Note("inloop");
      ++cycles;
    }
    RT_AWAIT(gate >= 2, 1);
    Note("gate2");
    RT_RUN(fragment.Advance(*this));
    Note("fragment");
    RT_PASS();
    RT_END();
"""

RUN_EXPECTED_TRACE = (
    "start|action1|after1|gate1|loop|inloop|loop|inloop|gate2|fragment|pass"
)

RUN_MAIN = r"""
#include <stdio.h>

int main(void) {
  ProbeCase probe;
  int step = 0;
  for (step = 0; step < 40 && !probe.IsFinished(); ++step) {
    if (step == 3) probe.OpenGate(1);
    if (step == 8) probe.OpenGate(2);
    printf("STEP %02d pc=%d frag=%d trace=%s\n", step, probe.Pc(), probe.FragmentSteps(),
           probe.Trace());
    probe.DriveOnce();
  }
  printf("TRACE=%s\n", probe.Trace());
  printf("STATUS=%d\n", probe.FinishedStatus());
  printf("STEPS=%d\n", step);
  return 0;
}
"""


def run_source() -> str:
    return "".join(
        (
            SCENARIO_BASE,
            MACROS,
            FRAGMENT,
            "class ProbeCase : public ProbeScenario {\n",
            "public:\n",
            "  ProbeCase() : gate(0), cycles(0) {}\n",
            "  void Script();\n",
            "  void OpenGate(int value) { gate = value; }\n",
            "  void DriveOnce() { armed = 0; Script(); }\n",
            "  bool IsFinished() const { return finished != 0; }\n",
            "  int FinishedStatus() const { return finished; }\n",
            "  void Reveal(const char* mark) { Note(mark); }\n",
            "  int Pc() const { return ScriptProgramCounter(); }\n",
            "  int FragmentSteps() const { return fragment.Steps(); }\n",
            "private:\n",
            "  int gate;\n",
            "  int cycles;\n",
            "  ProbeFragment fragment;\n",
            "};\n\n",
            "void ProbeCase::Script() {",
            RUN_SOURCE_BODY,
            "}\n\n",
            SUPPORT,
            RUN_MAIN,
        )
    )


# MSVC500 accepts a `case` label inside a `try` block, so the compiler cannot warn about
# it.  This program yields inside a try, resumes there, and then throws: if the catch does
# not fire, jumping into the try skipped its EH state setup and the source-policy gate has
# to ban RT_ macros inside try/catch, because nothing else will catch the mistake.
TRY_SOURCE_BODY = """
    RT_BEGIN();
    Note("start");
    try {
      RT_AWAIT(gate >= 1, 1);
      Note("resumed-in-try");
      ProbeThrow();
      Note("NOT-REACHED");
    } catch (int) {
      Note("caught");
    }
    RT_PASS();
    RT_END();
"""

# Observed on MSVC500 /GX: the program aborts with "abnormal program termination" (exit 3)
# because jumping into the try via a case label skipped its EH state setup, so the throw is
# unhandled.  The probe asserts the hazard is still present -- if a future flag change ever
# made the catch fire, this expectation would flag it and the gate could be relaxed.
TRY_EXPECTED = "unhandled"
TRY_FORBIDDEN_MARK = "caught"

TRY_MAIN = r"""
#include <stdio.h>

void ProbeThrow(void) { throw 7; }

int main(void) {
  ProbeTryCase probe;
  int step = 0;
  for (step = 0; step < 12 && !probe.IsFinished(); ++step) {
    if (step == 2) probe.OpenGate(1);
    probe.DriveOnce();
  }
  printf("TRACE=%s\n", probe.Trace());
  printf("STATUS=%d\n", probe.FinishedStatus());
  return 0;
}
"""


def try_source() -> str:
    return "".join(
        (
            SCENARIO_BASE,
            "extern void ProbeThrow(void);\n",
            MACROS,
            "class ProbeTryCase : public ProbeScenario {\n",
            "public:\n",
            "  ProbeTryCase() : gate(0) {}\n",
            "  void Script();\n",
            "  void OpenGate(int value) { gate = value; }\n",
            "  void DriveOnce() { armed = 0; Script(); }\n",
            "  bool IsFinished() const { return finished != 0; }\n",
            "  int FinishedStatus() const { return finished; }\n",
            "private:\n",
            "  int gate;\n",
            "};\n\n",
            "void ProbeTryCase::Script() {",
            TRY_SOURCE_BODY,
            "}\n\n",
            SUPPORT,
            TRY_MAIN,
        )
    )


DIAGNOSTIC_RE = re.compile(r"^probe\.cpp\((\d+)\)\s*:\s*(error|warning)\s+(C\d+)\s*:\s*(.*)$")


def first_diagnostics(log: str, limit: int = 3) -> list[str]:
    found: list[str] = []
    for line in log.splitlines():
        match = DIAGNOSTIC_RE.match(line.strip())
        if match is None:
            continue
        kind = match.group(2)
        if kind != "error" and len(found) >= limit:
            continue
        found.append(f"{match.group(3)} line {match.group(1)}: {match.group(4).strip()}")
        if len(found) >= limit:
            break
    return found


def docker_sh(work_dir: Path, script: str) -> subprocess.CompletedProcess:
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "--entrypoint", "/bin/sh",
        "-e", r"INCLUDE=C:\dxsdk\include;C:\msvc\include;C:\msvc\mfc\include;C:\msvc\atl\include",
        "-e", r"LIB=C:\msvc\lib;C:\msvc\mfc\lib",
        "-e", r"WINEPATH=C:\msvc\bin;C:\msvc\redist",
        "-v", f"{work_dir}:/work", "-w", "/work",
        DOCKER_IMAGE, "-c", script,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def compile_case(work_dir: Path, case: Case, flags: str) -> tuple[bool, str]:
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "probe.cpp").write_text(case_source(case), encoding="ascii")
    script = (
        f"wine C:/msvc/bin/CL.EXE /nologo /c {flags} probe.cpp > cl.log 2>&1; "
        "status=$?; cat cl.log; exit $status"
    )
    proc = docker_sh(work_dir, script)
    log = proc.stdout + proc.stderr
    (work_dir / "cl.log").write_text(log, encoding="utf-8", errors="replace")
    return proc.returncode == 0, log


def run_behaviour(work_dir: Path, flags: str, source: str) -> tuple[bool, str]:
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "probe.cpp").write_text(source, encoding="ascii")
    script = (
        f"wine C:/msvc/bin/CL.EXE /nologo {flags} probe.cpp /Feprobe.exe > cl.log 2>&1; "
        "status=$?; "
        "if [ $status -ne 0 ]; then cat cl.log; echo PROTOTHREAD_PROBE_LINK_FAILED; "
        "exit 1; fi; "
        "wine probe.exe 2>/dev/null"
    )
    proc = docker_sh(work_dir, script)
    output = proc.stdout
    (work_dir / "run.log").write_text(
        proc.stdout + "\n--- stderr ---\n" + proc.stderr, encoding="utf-8", errors="replace"
    )
    return proc.returncode == 0, output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        help="Keep each case's probe.cpp and cl.log here (default: a build subdirectory).",
    )
    parser.add_argument(
        "--flags", default=HARNESS_FLAGS,
        help="Compile with exactly these flags instead of the harness line.",
    )
    parser.add_argument(
        "--run", action="store_true",
        help="Also link and execute a protothread under Wine and check its resume trace.",
    )
    parser.add_argument("--only", help="Probe only the case whose name contains this text.")
    args = parser.parse_args()

    repo = repo_root_from_file(__file__)
    # Docker rejects a relative -v source as a volume name, so anchor the work tree.
    base = (Path(args.work_dir) if args.work_dir else repo / "build-msvc500" / "protothread-probe")
    base = base.resolve()

    cases = _cases()
    if args.only:
        cases = tuple(case for case in cases if args.only in case.name)
        if not cases:
            print(f"no case matches {args.only!r}")
            return 2

    print(f"flags: {args.flags}\n")
    header = f"{'case':44} {'expected':10} {'actual':10} diagnostic"
    print(header)
    print("-" * len(header))

    surprises: list[str] = []
    for case in cases:
        compiled, log = compile_case(base / case.name, case, args.flags)
        actual = "compiles" if compiled else "rejected"
        diagnostics = first_diagnostics(log)
        note = diagnostics[0] if diagnostics else ""
        flag = " " if actual == case.expectation else "!"
        print(f"{flag}{case.name:43} {case.expectation:10} {actual:10} {note}")
        for extra in diagnostics[1:]:
            print(f"{'':66} {extra}")
        if actual != case.expectation:
            surprises.append(
                f"{case.name}: expected {case.expectation}, got {actual}"
                + (f" ({note})" if note else "")
            )

    print()
    for case in cases:
        print(f"  {case.name}: {case.why}")

    if args.run:
        behaviours = (
            ("resume", run_source(), RUN_EXPECTED_TRACE,
             "resume order and member state across yields, including a nested fragment"),
            ("try", try_source(), TRY_EXPECTED,
             "whether a catch still fires after resuming into its try block"),
        )
        for label, source, expected, why in behaviours:
            print(f"\nbehaviour[{label}]: {why}")
            ok, output = run_behaviour(base / f"_run_{label}", args.flags, source)
            print(output.strip() or "(no output)")
            trace = ""
            for line in output.splitlines():
                if line.startswith("TRACE="):
                    trace = line[len("TRACE="):].strip()
            if expected == "unhandled":
                # The hazard is that the throw escapes; the CRT aborts before any printf.
                if ok or TRY_FORBIDDEN_MARK in output:
                    surprises.append(
                        f"behaviour[{label}]: the catch fired after resuming into the try"
                        " -- MSVC500 no longer skips the EH state setup, so the"
                        " source-policy ban on RT_ macros inside try/catch can be revisited"
                    )
                else:
                    print("confirmed hazard: the catch did NOT fire; the throw was unhandled")
            elif not ok:
                surprises.append(f"behaviour[{label}]: did not build or run")
            elif trace != expected:
                surprises.append(
                    f"behaviour[{label}]: trace mismatch\n    expected {expected}\n"
                    f"    actual   {trace}"
                )
            else:
                print(f"trace matches: {trace}")

    print(f"\nartifacts: {base}")
    if surprises:
        print("\nUNEXPECTED RESULTS")
        for surprise in surprises:
            print(f"  - {surprise}")
        return 1
    print("\nall cases matched expectations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
