#pragma once

// The one four-character-identifier encoding policy for manually owned source.
//
// Imperialism inherits the Mac resource convention: a tag is four bytes stored in
// resource order, and the 32-bit value the code compares is that byte sequence read
// big-endian, so `'D','L','O','G'` is 0x444c4f47. The Mac control-tag index in
// docs/reference/mac_control_usage.json stores the same convention (its `tag_value`
// for DLOG is 1145851719 == 0x444c4f47), which makes it a direct oracle for every
// tag this source declares.
//
// Spell tags through this macro rather than as hexadecimal with a comment. A comment
// is free to disagree with its value -- and eighteen of them did, including
// transliterations that quietly reversed the byte order ('Wpam' for what is really
// `mapW`), invented case ('Card' for `card`), or were simply wrong ('shot' for
// `tsho`). With the macro the characters ARE the value, so the two cannot drift.
//
// Tags whose four characters really are a reversed or otherwise surprising reading of
// a familiar word are still spelled exactly as the bytes appear -- write
// IMPERIALISM_FOURCC('t','s','h','o'), not the word it looks like -- and carry a
// comment explaining the surprise.
//
// VC5-safe: this is a constant expression built from unsigned char promotions, not an
// implementation-defined multi-character literal like 'text'.
// The result type is `int`, not `unsigned int`. Tag bytes are printable ASCII, so a
// tag always fits in a positive int, and the retail code compares tags against int
// fields (TEventHandler::controlTag) and switches on int commands. Making the
// constants unsigned would silently turn every `tag < kControlTagX` range test into an
// unsigned compare and change the emitted branch.
#define IMPERIALISM_FOURCC(a, b, c, d)                                                             \
  (static_cast<int>((static_cast<unsigned int>(static_cast<unsigned char>(a)) << 24) |             \
                    (static_cast<unsigned int>(static_cast<unsigned char>(b)) << 16) |             \
                    (static_cast<unsigned int>(static_cast<unsigned char>(c)) << 8) |              \
                    static_cast<unsigned int>(static_cast<unsigned char>(d))))
