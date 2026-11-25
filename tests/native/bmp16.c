/* DIB sections of 16 bits per pixel: a Win32 program (subsystem WINDOWS),
   compiled with MinGW and linked to ReactOS's kernel32 and gdi32, which the
   scenario `bitmap-16` puts on the boot disk in the place of winlogon.exe.
   CreateDIBSection of 16 bits gave NULL. As ReactOS (dibobj.c, bitmaps.c,
   xlateobj.c):
   1. CreateDIBSection of 16 bits, BI_RGB (3 x 2, from the bottom up):
      GetObject gives its DIBSECTION, lines of 32 bits (8 bytes), BI_RGB and
      the masks of 5-5-5;
   2. the process writes a pixel there (red, 0x7C00), the kernel reads it
      (GetPixel);
   3. the kernel paints a pixel green (PatBlt), another gray (128 is 16 of
      31, read back as 132), the process reads them, the padding of the line
      untouched;
   4. GetDIBits: the description says 16 bits and BI_BITFIELDS, the lines of
      16 bits come back as they are, and in 32 bits as colours;
   5. CreateDIBSection of 16 bits, BI_BITFIELDS 5-6-5 (2 x 1, from the top
      down): GetObject says BI_BITFIELDS and its masks; a pixel the process
      writes, read by the kernel; one the kernel paints blue; GetDIBits in
      BI_BITFIELDS gives its masks and its lines;
   6. BitBlt of the 5-5-5 section into the 5-6-5 one: red and green, each in
      its masks.
   Each step goes to the debug port (DbgPrint); the program ends with 0.

   Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
   -nostdlib, entry point GuiStartup. */
#include "app_probe.h"

#define TAG "[bmp16] "

static BITMAPINFO *info(BITMAPINFO *bmi, int width, int height, int bit_count, DWORD compression)
{
    BITMAPINFOHEADER *header = &bmi->bmiHeader;
    *header = (BITMAPINFOHEADER){0};
    header->biSize = sizeof(*header);
    header->biWidth = width;
    header->biHeight = height;
    header->biPlanes = 1;
    header->biBitCount = (WORD)bit_count;
    header->biCompression = compression;
    return bmi;
}

/* A BITMAPINFOHEADER and the three masks of BI_BITFIELDS. */
struct fields {
    BITMAPINFOHEADER header;
    DWORD masks[3];
};

DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    DbgPrint(TAG "on WinSta0\\Default\n");
    HDC screen = CreateCompatibleDC(0), memory = CreateCompatibleDC(0);
    BITMAPINFO bmi;
    DIBSECTION section = {0};

    /* 1. CreateDIBSection of 16 bits, BI_RGB, 3 x 2 from the bottom up. */
    WORD *bits = 0;
    HBITMAP dib = CreateDIBSection(screen, info(&bmi, 3, 2, 16, BI_RGB), DIB_RGB_COLORS, (void **)&bits, 0, 0);
    int got = dib ? GetObjectW(dib, sizeof(section), &section) : 0;
    DbgPrint(TAG "step 1: CreateDIBSection of 16 bits %d, bits %d: GetObject %d, %u bits, %ld bytes a line, "
                 "compression %lu, masks %04lx %04lx %04lx, size %lu\n",
             dib != 0, bits != 0, got, section.dsBm.bmBitsPixel, section.dsBm.bmWidthBytes,
             section.dsBmih.biCompression, section.dsBitfields[0], section.dsBitfields[1], section.dsBitfields[2],
             section.dsBmih.biSizeImage);
    if (!dib || !bits) {
        DbgPrint(TAG "done\n");
        ExitProcess(0);
    }

    /* 2. The process writes the top left pixel (the second line in memory:
       words 4 to 7) red; the kernel reads it. Padding marked. */
    for (int i = 0; i < 8; ++i) bits[i] = 0xEEEE;
    for (int i = 0; i < 3; ++i) bits[i] = 0, bits[4 + i] = 0;
    bits[4] = 0x7C00;
    HGDIOBJ old = SelectObject(memory, dib);
    COLORREF read = GetPixel(memory, 0, 0);
    DbgPrint(TAG "step 2: written by the process, read by the kernel: %06lx\n", read);

    /* 3. The kernel paints (1, 0) green and (2, 0) gray; the process reads
       their words. */
    HBRUSH green = CreateSolidBrush(RGB(0, 255, 0)), gray = CreateSolidBrush(RGB(128, 128, 128));
    HGDIOBJ old_brush = SelectObject(memory, green);
    BOOL painted = PatBlt(memory, 1, 0, 1, 1, PATCOPY);
    SelectObject(memory, gray);
    painted = PatBlt(memory, 2, 0, 1, 1, PATCOPY) && painted;
    GdiFlush();
    COLORREF grey = GetPixel(memory, 2, 0);
    DbgPrint(TAG "step 3: PatBlt %d: (1,0) %04x, (2,0) %04x read back %06lx, (0,0) %04x, padding %04x\n", painted,
             bits[5], bits[6], grey, bits[4], bits[7]);
    SelectObject(memory, old_brush);
    SelectObject(memory, old);

    /* 4. GetDIBits: the description, its lines of 16 bits, then in 32 bits
       from the top down. */
    BITMAPINFO query = {0};
    query.bmiHeader.biSize = sizeof(query.bmiHeader);
    int described = GetDIBits(screen, dib, 0, 0, 0, &query, DIB_RGB_COLORS);
    WORD lines16[8];
    for (int i = 0; i < 8; ++i) lines16[i] = 0xABAB;
    int copied = GetDIBits(screen, dib, 0, 2, lines16, info(&bmi, 3, 2, 16, BI_RGB), DIB_RGB_COLORS);
    DWORD out[6];
    for (int i = 0; i < 6; ++i) out[i] = 0xDEAD;
    int copied32 = GetDIBits(screen, dib, 0, 2, out, info(&bmi, 3, -2, 32, BI_RGB), DIB_RGB_COLORS);
    DbgPrint(TAG "step 4: described %d: %u bits, compression %lu; %d lines, top line %04x %04x %04x; %d lines in "
                 "32 bits: %06lx %06lx %06lx\n",
             described, query.bmiHeader.biBitCount, query.bmiHeader.biCompression, copied, lines16[4], lines16[5],
             lines16[6], copied32, out[0] & 0xFFFFFF, out[1] & 0xFFFFFF, out[2] & 0xFFFFFF);

    /* 5. CreateDIBSection of 16 bits, BI_BITFIELDS 5-6-5, 2 x 1 from the top
       down. */
    struct fields rgb565 = {{0}, {0xF800, 0x07E0, 0x001F}};
    info((BITMAPINFO *)&rgb565, 2, -1, 16, BI_BITFIELDS);
    WORD *wide = 0;
    HBITMAP masked = CreateDIBSection(screen, (BITMAPINFO *)&rgb565, DIB_RGB_COLORS, (void **)&wide, 0, 0);
    if (!masked || !wide) {
        DbgPrint(TAG "step 5: CreateDIBSection of 5-6-5: %d, bits %d\n", masked != 0, wide != 0);
        DbgPrint(TAG "done\n");
        ExitProcess(0);
    }
    got = GetObjectW(masked, sizeof(section), &section);
    wide[0] = 0;
    wide[1] = 0x07E0; /* (1, 0) green */
    old = SelectObject(memory, masked);
    COLORREF second = GetPixel(memory, 1, 0);
    HBRUSH blue = CreateSolidBrush(RGB(0, 0, 255));
    old_brush = SelectObject(memory, blue);
    painted = PatBlt(memory, 0, 0, 1, 1, PATCOPY);
    GdiFlush();
    SelectObject(memory, old_brush);
    SelectObject(memory, old);
    struct fields asked = {{0}, {0, 0, 0}};
    info((BITMAPINFO *)&asked, 2, -1, 16, BI_BITFIELDS);
    WORD back[2] = {0xABAB, 0xABAB};
    copied = GetDIBits(screen, masked, 0, 1, back, (BITMAPINFO *)&asked, DIB_RGB_COLORS);
    DbgPrint(TAG "step 5: 5-6-5: GetObject %d, compression %lu, masks %04lx %04lx %04lx; (1,0) %06lx; PatBlt %d: "
                 "%04x; GetDIBits %d: masks %04lx %04lx %04lx, %04x %04x\n",
             got, section.dsBmih.biCompression, section.dsBitfields[0], section.dsBitfields[1],
             section.dsBitfields[2], second, painted, wide[0], copied, asked.masks[0], asked.masks[1],
             asked.masks[2], back[0], back[1]);

    /* 6. BitBlt of the top line of the 5-5-5 section (red, green) into the
       5-6-5 one. */
    HDC target = CreateCompatibleDC(0);
    HGDIOBJ old_target = SelectObject(target, masked);
    old = SelectObject(memory, dib);
    BOOL blitted = BitBlt(target, 0, 0, 2, 1, memory, 0, 0, SRCCOPY);
    GdiFlush();
    DbgPrint(TAG "step 6: BitBlt %d: %04x %04x\n", blitted, wide[0], wide[1]);
    SelectObject(memory, old);
    SelectObject(target, old_target);

    DeleteDC(target);
    DeleteObject(masked);
    DeleteObject(blue);
    DeleteObject(gray);
    DeleteObject(green);
    DeleteObject(dib);
    DeleteDC(memory);
    DeleteDC(screen);
    DbgPrint(TAG "done\n");
    ExitProcess(0);
    return 0;
}
