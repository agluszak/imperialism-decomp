#pragma once

#define IMPERIALISM_FOURCC(a, b, c, d)                                                             \
  (static_cast<int>((static_cast<unsigned int>(static_cast<unsigned char>(a)) << 24) |             \
                    (static_cast<unsigned int>(static_cast<unsigned char>(b)) << 16) |             \
                    (static_cast<unsigned int>(static_cast<unsigned char>(c)) << 8) |              \
                    static_cast<unsigned int>(static_cast<unsigned char>(d))))
