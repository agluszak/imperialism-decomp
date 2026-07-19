import unittest

from tools.runtime import smoke


class RuntimeSmokeTests(unittest.TestCase):
    def test_random_game_ladder_records_dispatch_arguments_and_waits_for_3b8(self) -> None:
        addrs = {
            name: address + 0x1000 for name, address, _ in smoke.RANDOM_GAME_MILESTONES
        }

        script = smoke.ladder_script(smoke.RANDOM_GAME_MILESTONES, addrs, trace_dispatch=True)

        self.assertIn("set $eventCode = *(unsigned int*)($esp + 4)", script)
        self.assertIn("set $payload = *(unsigned int*)($esp + 8)", script)
        self.assertIn("EVENT dispatch-4c eventCode=0x%x payload=0x%x", script)
        self.assertIn("if $eventCode == 0x3b8", script)
        self.assertIn("MILESTONE dispatch-map", script)

    def test_random_game_default_expectations_cover_the_vertical_slice(self) -> None:
        self.assertEqual(
            smoke.RANDOM_GAME_EXPECTED.split(","),
            [
                "start-game",
                "rebuild-nations",
                "dispatch-map",
                "include-lifecycle",
                "map-lifecycle",
                "map-dialog-ctor",
                "create-tool-window",
            ],
        )

    def test_dispatch_trace_parser_keeps_both_arguments(self) -> None:
        match = smoke.DISPATCH_EVENT_RE.search(
            "EVENT dispatch-4c eventCode=0x3b8 payload=0x6"
        )

        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(int(match.group(1), 16), 0x3B8)
        self.assertEqual(int(match.group(2), 16), 6)


if __name__ == "__main__":
    unittest.main()
