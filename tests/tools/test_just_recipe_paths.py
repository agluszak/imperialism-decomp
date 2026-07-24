"""Every explicit source path named in a just recipe must exist.

Guard for the class of drift where a recipe hardcodes src/... or include/...
paths that a later reorganization moves (imperialism-decomp-ifxx: the
scalar-clang-tidy sample named five root-level src/game TUs that had all moved
into subsystem folders, and CI never noticed because it does not run that
recipe).
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# A literal repo source path: optionally container-prefixed, no regex
# metacharacters, ending in a source/header extension.
PATH_RE = re.compile(
    r"(?:/imperialism/)?((?:src|include)/[A-Za-z0-9_/.\-]+\.(?:cpp|h|hpp|c|inc))"
)


def iter_just_files():
    yield REPO_ROOT / "justfile"
    yield from sorted((REPO_ROOT / "just").glob("*.just"))


class TestJustRecipePathsExist(unittest.TestCase):
    def test_explicit_source_paths_exist(self):
        missing = []
        for just_file in iter_just_files():
            for lineno, line in enumerate(
                just_file.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for match in PATH_RE.finditer(line):
                    rel = match.group(1)
                    if not (REPO_ROOT / rel).exists():
                        missing.append(
                            f"{just_file.relative_to(REPO_ROOT)}:{lineno}: {rel}"
                        )
        self.assertEqual(
            missing,
            [],
            "just recipes name source paths that do not exist:\n" + "\n".join(missing),
        )


if __name__ == "__main__":
    unittest.main()
