#!/usr/bin/env python3
"""Function-comparison entrypoint with vtable diagnostics routed elsewhere.

reccmp validates every paired vtable while constructing its database, even for a
single-function comparison.  The resulting global vtable-size warnings are useful
for ``just vtable`` but obscure the requested function diff.  Keep every other
reccmp diagnostic visible and suppress only that one vtable-specific message here.
"""

from __future__ import annotations

import logging

from reccmp.tools.asmcmp import main as reccmp_main

VTABLE_SIZE_WARNING = "Recomp vtable is larger than orig vtable for "


class FunctionCompareLogFilter(logging.Filter):
    """Route global vtable-size diagnostics away from function comparisons."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not (
            record.name == "reccmp.compare.verify"
            and record.getMessage().startswith(VTABLE_SIZE_WARNING)
        )


def main() -> int:
    logging.getLogger("reccmp.compare.verify").addFilter(FunctionCompareLogFilter())
    return reccmp_main()


if __name__ == "__main__":
    raise SystemExit(main())
