/* Bitmaps of 24 bits per pixel: a Win32 program (subsystem WINDOWS), compiled
   with MinGW and linked to ReactOS's kernel32 and gdi32, which the scenario
   `bitmap-24` puts on the boot disk in the place of winlogon.exe. The LCL of
   Lazarus (PeaZip) makes its images in 24 bits: CreateBitmap and
   CreateDIBSection of 24 bits gave NULL, and PeaZip stopped on "Failed to
   get raw image description from bitmap". As ReactOS (bitmaps.c, dibobj.c):
   1. CreateBitmap of 24 bits: GetObject says 24 bits, its lines of 16 bits
      (16 pixels: 48 bytes); the bits it is given (lines aligned on 16 bits)
      come back by GetDIBits in 32 bits;
   2. CreateDIBSection of 24 bits (3 x 2, from the bottom up): GetObject gives
      its DIBSECTION (lines of 32 bits: 12 bytes), the address of its pixels;
   3. the process writes a pixel there, the kernel reads it (GetPixel);
   4. the kernel paints a pixel (PatBlt), the process reads it, BGR, the
      padding of the line untouched;
   5. GetDIBits: the description says 24 bits, the lines come back as they
      are;
   6. BitBlt of the DIB section of 24 bits into one of 32 bits: the colours;
   7. a DIB section of 1 bit (the masks of the LCL's images), its table
      black and white: the pixel the process sets read by the kernel, the
      one the kernel paints white read by the process.
   Each step goes to the debug port (DbgPrint); the program ends with 0.

   Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
   -nostdlib, entry point GuiStartup. */
#include "app_probe.h"

#define TAG "[bmp24] "

static BITMAPINFO *info(BITMAPINFO *bmi, int width, int height, int bit_count)
{
    BITMAPINFOHEADER *header = &bmi->bmiHeader;
    *header = (BITMAPINFOHEADER){0};
    header->biSize = sizeof(*header);
    header->biWidth = width;
    header->biHeight = height;
    header->biPlanes = 1;
    header->biBitCount = (WORD)bit_count;
    header->biCompression = BI_RGB;
    return bmi;
}

DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    DbgPrint(TAG "on WinSta0\\Default\n");
    HDC screen = CreateCompatibleDC(0), memory = CreateCompatibleDC(0);
    BITMAP bm;
    BITMAPINFO bmi;
    DWORD out[16];

    /* 1. CreateBitmap of 24 bits: lines of 16 bits; red and green, then
       blue and black. */
    HBITMAP plain = CreateBitmap(16, 16, 1, 24, 0);
    int got = plain ? GetObjectW(plain, sizeof(bm), &bm) : 0;
    DbgPrint(TAG "step 1: CreateBitmap of 24 bits %d: GetObject %d, %ldx%ld, %u bits, %ld bytes a line\n",
             plain != 0, got, bm.bmWidth, bm.bmHeight, bm.bmBitsPixel, bm.bmWidthBytes);
    /* Two pixels of 3 bytes: 6 bytes a line, already on 16 bits. */
    static const BYTE given[2 * 6] = {0, 0, 0xFF, 0, 0xFF, 0, /* the next line */ 0xFF, 0, 0, 0, 0, 0};
    HBITMAP small = CreateBitmap(2, 2, 1, 24, given);
    for (int i = 0; i < 4; ++i) out[i] = 0xDEAD;
    int lines = small ? GetDIBits(screen, small, 0, 2, out, info(&bmi, 2, -2, 32), DIB_RGB_COLORS) : 0;
    DbgPrint(TAG "step 1: its bits: %d lines, %06lx %06lx %06lx %06lx\n", lines, out[0] & 0xFFFFFF,
             out[1] & 0xFFFFFF, out[2] & 0xFFFFFF, out[3] & 0xFFFFFF);

    /* 2. CreateDIBSection of 24 bits, 3 x 2, from the bottom up. */
    BYTE *bits = 0;
    HBITMAP dib = CreateDIBSection(screen, info(&bmi, 3, 2, 24), DIB_RGB_COLORS, (void **)&bits, 0, 0);
    DIBSECTION section = {0};
    got = dib ? GetObjectW(dib, sizeof(section), &section) : 0;
    DbgPrint(TAG "step 2: CreateDIBSection of 24 bits %d, bits %d: GetObject %d, %u bits, %ld bytes a line, "
                 "biBitCount %u, size %lu\n",
             dib != 0, bits != 0, got, section.dsBm.bmBitsPixel, section.dsBm.bmWidthBytes,
             section.dsBmih.biBitCount, section.dsBmih.biSizeImage);
    if (!dib || !bits) {
        DbgPrint(TAG "done\n");
        ExitProcess(0);
    }

    /* 3. The process writes the top left pixel (the second line in memory),
       blue; the kernel reads it. Padding marked. */
    for (int i = 0; i < 24; ++i) bits[i] = 0xEE;
    for (int i = 0; i < 9; ++i) bits[i] = 0, bits[12 + i] = 0;
    bits[12] = 0xFF; /* (0, 0): B G R = FF 00 00 */
    HGDIOBJ old = SelectObject(memory, dib);
    COLORREF read = GetPixel(memory, 0, 0);
    DbgPrint(TAG "step 3: written by the process, read by the kernel: %06lx\n", read);

    /* 4. The kernel paints (1, 0) red; the process reads B G R. */
    HBRUSH red = CreateSolidBrush(RGB(255, 0, 0));
    HGDIOBJ old_brush = SelectObject(memory, red);
    BOOL painted = PatBlt(memory, 1, 0, 1, 1, PATCOPY);
    GdiFlush();
    DbgPrint(TAG "step 4: PatBlt %d: (1,0) %02x %02x %02x, (0,0) %02x %02x %02x, padding %02x %02x %02x\n", painted,
             bits[15], bits[16], bits[17], bits[12], bits[13], bits[14], bits[21], bits[22], bits[23]);
    SelectObject(memory, old_brush);
    SelectObject(memory, old);

    /* 5. GetDIBits: the description, then its lines of 24 bits. */
    BITMAPINFO query = {0};
    query.bmiHeader.biSize = sizeof(query.bmiHeader);
    int described = GetDIBits(screen, dib, 0, 0, 0, &query, DIB_RGB_COLORS);
    BYTE lines24[24];
    for (int i = 0; i < 24; ++i) lines24[i] = 0xAB;
    int copied = GetDIBits(screen, dib, 0, 2, lines24, info(&bmi, 3, 2, 24), DIB_RGB_COLORS);
    DbgPrint(TAG "step 5: described %d: %u bits; %d lines, top line %02x %02x %02x %02x %02x %02x\n", described,
             query.bmiHeader.biBitCount, copied, lines24[12], lines24[13], lines24[14], lines24[15], lines24[16],
             lines24[17]);

    /* 6. BitBlt into a DIB section of 32 bits. */
    DWORD *wide = 0;
    HBITMAP thirty_two = CreateDIBSection(screen, info(&bmi, 3, -2, 32), DIB_RGB_COLORS, (void **)&wide, 0, 0);
    HDC target = CreateCompatibleDC(0);
    HGDIOBJ old_target = SelectObject(target, thirty_two);
    old = SelectObject(memory, dib);
    BOOL blitted = BitBlt(target, 0, 0, 3, 2, memory, 0, 0, SRCCOPY);
    GdiFlush();
    DbgPrint(TAG "step 6: BitBlt %d: %06lx %06lx %06lx\n", blitted, wide[0] & 0xFFFFFF, wide[1] & 0xFFFFFF,
             wide[2] & 0xFFFFFF);
    SelectObject(memory, old);
    SelectObject(target, old_target);

    /* 7. A DIB section of 1 bit, 9 x 1, black and white. */
    struct { BITMAPINFOHEADER header; RGBQUAD colors[2]; } mono = {{0}, {{0, 0, 0, 0}, {0xFF, 0xFF, 0xFF, 0}}};
    info((BITMAPINFO *)&mono, 9, -1, 1);
    BYTE *one = 0;
    HBITMAP masks = CreateDIBSection(screen, (BITMAPINFO *)&mono, DIB_RGB_COLORS, (void **)&one, 0, 0);
    if (masks && one) {
        one[0] = 0x80; /* (0, 0) white */
        old = SelectObject(memory, masks);
        COLORREF first = GetPixel(memory, 0, 0), second = GetPixel(memory, 1, 0);
        HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
        old_brush = SelectObject(memory, white);
        painted = PatBlt(memory, 8, 0, 1, 1, PATCOPY);
        GdiFlush();
        got = GetObjectW(masks, sizeof(section), &section);
        DbgPrint(TAG "step 7: a DIB section of 1 bit: GetObject %d, %u bit, %ld bytes a line; (0,0) %06lx, (1,0) "
                     "%06lx; PatBlt %d: %02x %02x\n",
                 got, section.dsBm.bmBitsPixel, section.dsBm.bmWidthBytes, first, second, painted, one[0], one[1]);
        SelectObject(memory, old_brush);
        SelectObject(memory, old);
        DeleteObject(white);
        DeleteObject(masks);
    } else {
        DbgPrint(TAG "step 7: a DIB section of 1 bit: %d, bits %d\n", masks != 0, one != 0);
    }
    DeleteDC(target);
    DeleteObject(thirty_two);
    DeleteObject(dib);
    DeleteObject(red);
    DeleteObject(small);
    DeleteObject(plain);
    DeleteDC(memory);
    DeleteDC(screen);
    DbgPrint(TAG "done\n");
    ExitProcess(0);
    return 0;
}
