#pragma once

// CRT mem helpers at 0x005e8420 / 0x005e9cf0 are linked from the MSVC runtime,
// not reimplemented here. Do not add reccmp LIBRARY markers for them in this
// header — that duplicates the autogen stub markers and breaks reccmp-roadmap.
