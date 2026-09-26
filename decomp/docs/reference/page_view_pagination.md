# Page row ownership and pagination

`TPageView` owns `TLineData` objects in two `TList` collections: `orderedEntries`
contains the displayed lines, and `optionEntries` contains section headers. An
ordered line's `row` field selects its one-based header index; zero means no
header. Production callers include the Deal Book, trade category pages, army and
navy rosters, and technology pages.

The former local `TSelectableTextOptionEntry` class was a second, incompatible
description of these objects. The real `TLineData` is 16 bytes: `column` and `row`
are shorts at +4 and +6, followed by integer width and height at +8 and +12.
`SetLineDataRowAndBounds` (`0x0056f420`) writes the two bounds as dwords. The
page algorithms deliberately consume only the signed low word of the height.
`column` is the following space required for a line to fit, without adding that
space to the next line's position. The Deal Book gives commodity headers 30
pixels of required following space and its aid heading 60.

`ShowPage` dispatches slot +0x28 on each line (`0x0056fec3`), which is the real
`TLineData::InstallViews(TView*, int*)` virtual. The passed two-integer array is
horizontal then vertical position (`0x0056feb0` through `0x0056febf`).

## A section header must preserve its first row

At `0x0056fe7f`, `ShowPage` resolves a new section's header. It then decrements the
ordered index at `0x0056fe88` before the common increment at `0x0056fee0`. The
next iteration therefore returns to the first detail row. Substituting the
header without preserving that index omitted the first detail row of every
section.

For a header and two detail rows, each 30 pixels tall, on a page with bottom 90,
retail installs all three at Y=0, 30, and 60. The former reconstruction installed
only the header and second detail row.

## A page break counts its first ungrouped row once

`BuildPageLayout` resets Y to the page top and adds the overflowing line's height
at `0x0056fd19` and `0x0056fd25`. When that line has no header, the branch at
`0x0056fd32` skips the common addition at `0x0056fd44`. With a header, the added
height is the header's height instead (`0x0056fd3d` and `0x0056fd40`).

Six ungrouped 30-pixel lines on a page with bottom 90 produce two pages starting
at ordered indices 1 and 4. The former reconstruction counted the first line on
the second page twice and produced a third page starting at index 6.

The existing `trade_screen_operates` runtime scenario checks both cases through real
`TPageView` and `TTextLine` instances, inspecting the resulting `TStaticText`
children and page-start list. Both detached pages are released through their
production `Free` methods before the normal trade-screen flow continues.
