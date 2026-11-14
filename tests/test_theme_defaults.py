"""Performance-mode default check (SP4) — Theme.qml source assertions.

Theme.qml is a QML singleton (not importable from Python), so the default
is verified by inspecting the source: performance (lowFx) must start
enabled for fresh profiles, while the saved-setting/CLI precedence stays.
"""

import unittest
from pathlib import Path

THEME_PATH = Path(__file__).resolve().parent.parent / "qml" / "theme" / "Theme.qml"


class ThemeDefaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = THEME_PATH.read_text(encoding="utf-8")

    def test_low_fx_defaults_enabled(self):
        self.assertIn("property bool lowFxUser: true", self.source)

    def test_cli_flags_still_override(self):
        self.assertIn("--lowfx", self.source)
        self.assertIn("--fullfx", self.source)

    def test_fullfx_force_off_branch_precedes_lowfx(self):
        self.assertLess(
            self.source.index("_fullFxForced"),
            self.source.index("lowFx:"),
        )


if __name__ == "__main__":
    unittest.main()
