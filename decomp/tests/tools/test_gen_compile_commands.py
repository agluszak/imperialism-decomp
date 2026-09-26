"""Container compile commands retain the correct host source/build ownership."""

import unittest

from tools.workflow.gen_compile_commands import rewrite


class CompileCommandsTests(unittest.TestCase):
    def test_mounts_are_rewritten_once_and_at_path_boundaries(self) -> None:
        entries = [{
            "directory": "/build",
            "file": "/imperialism/build-msvc500/generated/ui/Factory.cpp",
            "command": 'clang-cl -I/imperialism/include -Fo/build/Factory.obj '
                       '"/imperialism/build-msvc500/generated/ui/Factory.cpp"',
        }]
        root = "/home/user/imperialism-decomp"
        build = root + "/build-msvc500/reccmp-source/cmake"
        result = rewrite(entries, root, build)[0]
        self.assertEqual(result["directory"], build)
        self.assertEqual(result["file"], root + "/build-msvc500/generated/ui/Factory.cpp")
        self.assertEqual(
            result["command"],
            f'clang-cl -I{root}/include -Fo{build}/Factory.obj '
            f'"{root}/build-msvc500/generated/ui/Factory.cpp"',
        )


if __name__ == "__main__":
    unittest.main()
