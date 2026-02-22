// Manual reconstruction of sprite pixel-scan helpers.

#include "decomp_types.h"

typedef unsigned int uint;

int AllocateWithFallbackHandler(undefined4 size_bytes);

// FUNCTION: IMPERIALISM 0x0047c3d0
int *Sprite__CollectNonTransparentPixels(void *this_obj, uint this_ptr)
{
  byte bVar1;
  int scan_offset;
  int col_idx;
  int byte_idx;
  int *out_pairs;
  uint uVar6;
  int byte_scan;
  int row_stride;
  char cVar9;
  char cVar10;
  byte *scan_ptr;
  int header_ptr;
  byte *pixel_ptr;
  int bit_row;
  int width;
  int *out_iter;
  int row_idx;
  int pair_count;
  byte *row_ptr;

  header_ptr = *(int *)((int)this_obj + 0x10);
  if (*(short *)(header_ptr + 0xe) != 1) {
    width = *(int *)(header_ptr + 4);
    pixel_ptr = *(byte **)((int)this_obj + 0xc);
    uVar6 = width + 3U & 0xfffffffc;
    if (this_ptr == 0xffffffff) {
      this_ptr = (uint)*pixel_ptr;
    }
    header_ptr = *(int *)(header_ptr + 8);
    row_idx = 0;
    scan_offset = 0;
    row_stride = uVar6 * 2;
    scan_ptr = pixel_ptr;
LAB_0047c603:
    do {
      col_idx = header_ptr;
      if (header_ptr < 1) {
        col_idx = -header_ptr;
      }
      if (col_idx <= scan_offset) {
        out_pairs = (int *)AllocateWithFallbackHandler((row_idx + 1) * 0x10);
        *out_pairs = row_idx * 2 + 1;
        pair_count = 1;
        header_ptr = 0;
        out_iter = out_pairs + 2;
        row_ptr = pixel_ptr;
        do {
          width = *(int *)(*(int *)((int)this_obj + 0x10) + 8);
          row_idx = width;
          if (width < 1) {
            row_idx = -width;
          }
          if (row_idx <= header_ptr) {
            header_ptr = header_ptr + -2;
            if (-1 < header_ptr) {
              out_iter = out_pairs + pair_count * 2;
              pixel_ptr = pixel_ptr + header_ptr * uVar6;
              do {
                width = *(int *)(*(int *)((int)this_obj + 0x10) + 4);
                do {
                  width = width + -1;
                  if (width < 0) {
                    goto LAB_0047c72a;
                  }
                } while (pixel_ptr[width] == this_ptr);
                row_stride = *(int *)(*(int *)((int)this_obj + 0x10) + 8);
                if (row_stride < 1) {
                  row_stride = -row_stride;
                }
                *out_iter = width;
                pair_count = pair_count + 1;
                out_iter[1] = (row_stride - header_ptr) + -1;
                out_iter = out_iter + 2;
LAB_0047c72a:
                header_ptr = header_ptr + -2;
                pixel_ptr = pixel_ptr + uVar6 * -2;
              } while (-1 < header_ptr);
            }
            out_pairs[pair_count * 2] = out_pairs[2];
            out_pairs[pair_count * 2 + 1] = out_pairs[3];
            return out_pairs;
          }
          row_idx = *(int *)(*(int *)((int)this_obj + 0x10) + 4);
          scan_offset = 0;
          if (0 < row_idx) {
            do {
              if (row_ptr[scan_offset] != this_ptr) {
                if (width < 1) {
                  width = -width;
                }
                *out_iter = scan_offset;
                out_iter[1] = (width - header_ptr) + -1;
                pair_count = pair_count + 1;
                out_iter = out_iter + 2;
                break;
              }
              scan_offset = scan_offset + 1;
            } while (scan_offset < row_idx);
          }
          header_ptr = header_ptr + 2;
          row_ptr = row_ptr + row_stride;
        } while (true);
      }
      col_idx = 0;
      if (0 < width) {
        do {
          if (scan_ptr[col_idx] != this_ptr) {
            row_idx = row_idx + 1;
            goto LAB_0047c631;
          }
          col_idx = col_idx + 1;
        } while (col_idx < width);
        scan_offset = scan_offset + 2;
        scan_ptr = scan_ptr + row_stride;
        goto LAB_0047c603;
      }
LAB_0047c631:
      scan_offset = scan_offset + 2;
      scan_ptr = scan_ptr + row_stride;
    } while (true);
  }
  width = *(int *)(header_ptr + 4);
  header_ptr = *(int *)(header_ptr + 8);
  bit_row = 0;
  this_ptr = 0;
  scan_offset = (int)(width + 0x1f + (width + 0x1f >> 0x1f & 0x1fU)) >> 5;
  row_stride = *(int *)((int)this_obj + 0xc);
  col_idx = scan_offset * 0x20;
  row_idx = row_stride;
  while (true) {
    byte_idx = header_ptr;
    if (header_ptr < 1) {
      byte_idx = -header_ptr;
    }
    if (byte_idx <= bit_row) {
      break;
    }
    byte_scan = 0;
    byte_idx = (int)(width + (width >> 0x1f & 7U)) >> 3;
    if (byte_idx < 1) {
LAB_0047c453:
      bit_row = bit_row + 8;
      row_idx = row_idx + col_idx;
    } else {
      do {
        if (*(char *)(byte_scan + row_idx) != '\0') {
          this_ptr = this_ptr + 1;
          goto LAB_0047c453;
        }
        byte_scan = byte_scan + 1;
      } while (byte_scan < byte_idx);
      bit_row = bit_row + 8;
      row_idx = row_idx + col_idx;
    }
  }
  out_pairs = (int *)AllocateWithFallbackHandler((this_ptr + 1) * 0x10);
  width = 0;
  *out_pairs = this_ptr * 2 + 1;
  this_ptr = 1;
  header_ptr = 0;
  out_iter = out_pairs + 2;
LAB_0047c48c:
  do {
    row_idx = *(int *)(*(int *)((int)this_obj + 0x10) + 8);
    bit_row = row_idx;
    if (row_idx < 1) {
      bit_row = -row_idx;
    }
    if (bit_row <= width) {
      width = width + -8;
      if (-1 < width) {
        header_ptr = width * scan_offset * 4;
        out_iter = out_pairs + this_ptr * 2;
        do {
          row_idx = *(int *)(*(int *)((int)this_obj + 0x10) + 4);
          row_idx = ((int)(row_idx + (row_idx >> 0x1f & 7U)) >> 3) + -1;
          if (-1 < row_idx) {
LAB_0047c55c:
            if (*(char *)(row_idx + row_stride + header_ptr) == '\0') {
              goto code_r0x0047c562;
            }
            cVar10 = '\0';
            for (cVar9 = *(char *)(row_idx + row_stride + header_ptr); cVar9 != '\0';
                 cVar9 = cVar9 << 1) {
              cVar10 = cVar10 + '\x01';
            }
            col_idx = *(int *)(*(int *)((int)this_obj + 0x10) + 8);
            if (col_idx < 1) {
              col_idx = -col_idx;
            }
            *out_iter = (int)cVar10 + row_idx * 8;
            out_iter[1] = (col_idx - width) + -1;
            this_ptr = this_ptr + 1;
            out_iter = out_iter + 2;
          }
LAB_0047c5a0:
          width = width + -8;
          header_ptr = header_ptr + scan_offset * -0x20;
        } while (-1 < width);
      }
      out_pairs[this_ptr * 2] = out_pairs[2];
      out_pairs[this_ptr * 2 + 1] = out_pairs[3];
      return out_pairs;
    }
    bit_row = *(int *)(*(int *)((int)this_obj + 0x10) + 4);
    byte_idx = 0;
    bit_row = (int)(bit_row + (bit_row >> 0x1f & 7U)) >> 3;
    if (0 < bit_row) {
LAB_0047c4be:
      if (*(char *)(byte_idx + row_stride + header_ptr) == '\0') {
        goto code_r0x0047c4c4;
      }
      cVar9 = '\0';
      for (bVar1 = *(byte *)(byte_idx + row_stride + header_ptr); bVar1 != 0;
           bVar1 = bVar1 >> 1) {
        cVar9 = cVar9 + '\x01';
      }
      if (row_idx < 1) {
        row_idx = -row_idx;
      }
      *out_iter = (byte_idx * 8 + 8) - (int)cVar9;
      this_ptr = this_ptr + 1;
      out_iter[1] = (row_idx - width) + -1;
      out_iter = out_iter + 2;
    }
    width = width + 8;
    header_ptr = header_ptr + col_idx;
  } while (true);
code_r0x0047c562:
  row_idx = row_idx + -1;
  if (row_idx < 0) {
    goto LAB_0047c5a0;
  }
  goto LAB_0047c55c;
code_r0x0047c4c4:
  byte_idx = byte_idx + 1;
  if (bit_row <= byte_idx) {
    goto code_r0x0047c4c9;
  }
  goto LAB_0047c4be;
code_r0x0047c4c9:
  width = width + 8;
  header_ptr = header_ptr + col_idx;
  goto LAB_0047c48c;
}
