/* Polygons, polylines and Bézier curves (NtGdiPolyPolyDraw), the stock pens
   and the pen of a DC's attributes: a Win32 program (subsystem WINDOWS),
   compiled with MinGW and linked to ReactOS's user32 and gdi32, which the
   scenario `polygons` puts on the boot disk in the place of winlogon.exe.
   Apache OpenOffice (VCL) paints its backgrounds and gradients by Polygon
   with NULL_PEN: NtGdiPolyPolyDraw had no handler and GetStockObject gave
   no pens, so nothing was painted, and what a closed menu or a moved window
   had left on the screen stayed there (trails). As ReactOS (fillshap.c,
   line.c) and XP, on a DIB section of 32 bits whose pixels the program
   reads itself:
   1. the stock pens exist; a new DC has BLACK_PEN;
   2. Polygon with NULL_PEN: a triangle covers the pixels whose centre is in
      it (its slanted right edge is out), and has no outline;
   3. the DC's pen (CreatePen, chosen by SelectObject in the DC's
      attributes, without a call to the kernel) outlines a square, blue,
      right and bottom edges included, the brush inside;
   4. PolyPolygon: a hole stays empty in ALTERNATE, fills in WINDING when
      both outlines turn the same way;
   5. R2_NOT: a polygon inverts what is there, twice gives it back;
   6. Polyline and LineTo stop before their last pixel; PolylineTo moves the
      current position; PolyBezier goes through its ends, and refuses a
      count that is not 1 + 3n;
   7. CreatePolygonRgn: a complex region, the triangle's box;
   8. SetPixel;
   9. a window painted by Polygon in WM_PAINT (bands of a gradient, NULL_PEN,
      as VCL), a popup shown over it, then destroyed: the window paints
      again where the popup was (the scenario checks pixels of the screen).
   Each result goes to the debug port (DbgPrint), where the scenario looks
   for it.

   Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
   -nostdlib, entry point GuiStartup. */
#include "app_probe.h"

#define TAG "[poly] "
#define SIZE 64
#define GREEN RGB(0, 0xC0, 0)

static DWORD *bits;

/* The pixel (x, y) of the DIB section, as 0xRRGGBB. */
static DWORD at(int x, int y)
{
    return bits[y * SIZE + x] & 0xFFFFFF;
}

static void clear(void)
{
    for (int i = 0; i < SIZE * SIZE; ++i) bits[i] = 0xFFFFFF;
}

static LRESULT CALLBACK banded_proc(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_ERASEBKGND)
        return 1;
    if (message == WM_PAINT) {
        PAINTSTRUCT paint;
        RECT client;
        HDC dc = BeginPaint(window, &paint);
        HBRUSH green = CreateSolidBrush(GREEN);
        HGDIOBJ old_pen = SelectObject(dc, GetStockObject(NULL_PEN));
        HGDIOBJ old_brush = SelectObject(dc, green);
        GetClientRect(window, &client);
        /* Four slanted bands, as the steps of a gradient: they tile. */
        int step = client.right / 4;
        for (int band = 0; band < 4; ++band) {
            int left = band * step - 20, right = band == 3 ? client.right + 40 : (band + 1) * step - 20;
            POINT points[4] = {{left, 0}, {right, 0}, {right + 40, client.bottom}, {left + 40, client.bottom}};
            if (band == 0) points[0].x = points[3].x = -100;
            Polygon(dc, points, 4);
        }
        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
        DeleteObject(green);
        EndPaint(window, &paint);
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

static void pump(void)
{
    MSG message;
    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) DispatchMessageW(&message);
}

DWORD WINAPI GuiStartup(void)
{
    app_desktop();
    DbgPrint(TAG "on WinSta0\\Default\n");

    /* 1. The stock pens; the pen of a new DC. */
    HGDIOBJ white_pen = GetStockObject(WHITE_PEN), black_pen = GetStockObject(BLACK_PEN);
    HGDIOBJ null_pen = GetStockObject(NULL_PEN);
    HDC dc = CreateCompatibleDC(0);
    DbgPrint(TAG "step 1: stock pens %d %d %d, a new DC has BLACK_PEN %d\n", white_pen != 0, black_pen != 0,
             null_pen != 0, GetCurrentObject(dc, OBJ_PEN) == black_pen);

    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth = SIZE;
    bmi.bmiHeader.biHeight = -SIZE;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    HBITMAP section = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, (void **)&bits, 0, 0);
    app_check(section && bits, "CreateDIBSection");
    SelectObject(dc, section);
    clear();

    /* 2. A triangle with NULL_PEN: the pixels whose centre is inside. */
    HBRUSH red = CreateSolidBrush(RGB(0xFF, 0, 0)), green = CreateSolidBrush(GREEN);
    SelectObject(dc, null_pen);
    SelectObject(dc, red);
    POINT triangle[3] = {{0, 0}, {8, 0}, {0, 8}};
    BOOL drawn = Polygon(dc, triangle, 3);
    int count = 0;
    for (int y = 0; y < 10; ++y)
        for (int x = 0; x < 10; ++x) count += at(x, y) == 0xFF0000;
    DbgPrint(TAG "step 2: Polygon %d: %d red pixels; (0,0) %06lx, (6,0) %06lx, (7,0) %06lx, (3,3) %06lx, (4,3) %06lx\n",
             drawn, count, at(0, 0), at(6, 0), at(7, 0), at(3, 3), at(4, 3));

    /* 3. The DC's pen, chosen in its attributes: the outline. */
    HPEN blue = CreatePen(PS_SOLID, 1, RGB(0, 0, 0xFF));
    SelectObject(dc, blue);
    SelectObject(dc, green);
    POINT square[4] = {{20, 0}, {30, 0}, {30, 10}, {20, 10}};
    drawn = Polygon(dc, square, 4);
    DbgPrint(TAG "step 3: outlined %d: inside %06lx, corner %06lx, right %06lx, bottom %06lx, beyond %06lx %06lx\n",
             drawn, at(25, 5), at(20, 0), at(30, 5), at(25, 10), at(31, 5), at(25, 11));

    /* 4. A hole: ALTERNATE, then WINDING (both outlines clockwise). */
    SelectObject(dc, null_pen);
    SelectObject(dc, red);
    POINT rings[8] = {{0, 20}, {20, 20}, {20, 40}, {0, 40}, {5, 25}, {15, 25}, {15, 35}, {5, 35}};
    INT counts[2] = {4, 4};
    drawn = PolyPolygon(dc, rings, counts, 2);
    DWORD hole = at(10, 30), ring = at(2, 22);
    clear();
    int old_mode = SetPolyFillMode(dc, WINDING);
    BOOL again = PolyPolygon(dc, rings, counts, 2);
    DbgPrint(TAG "step 4: ALTERNATE %d: hole %06lx, ring %06lx; WINDING %d (was %d): hole %06lx\n", drawn, hole, ring,
             again, old_mode, at(10, 30));
    SetPolyFillMode(dc, ALTERNATE);

    /* 5. R2_NOT, once and twice. */
    clear();
    PatBlt(dc, 40, 20, 20, 20, PATCOPY);
    SetROP2(dc, R2_NOT);
    POINT box[4] = {{40, 20}, {60, 20}, {60, 40}, {40, 40}};
    Polygon(dc, box, 4);
    DWORD once = at(50, 30);
    Polygon(dc, box, 4);
    DbgPrint(TAG "step 5: R2_NOT once %06lx, twice %06lx\n", once, at(50, 30));
    SetROP2(dc, R2_COPYPEN);

    /* 6. Lines: without their last pixel; the current position. */
    clear();
    SelectObject(dc, black_pen);
    POINT line[2] = {{0, 50}, {10, 50}};
    Polyline(dc, line, 2);
    MoveToEx(dc, 0, 52, 0);
    LineTo(dc, 10, 52);
    MoveToEx(dc, 0, 54, 0);
    POINT to[2] = {{10, 54}, {10, 60}};
    PolylineTo(dc, to, 2);
    POINT position = {0};
    GetCurrentPositionEx(dc, &position);
    POINT curve[4] = {{20, 50}, {20, 60}, {30, 60}, {30, 50}};
    BOOL bezier = PolyBezier(dc, curve, 4), wrong = PolyBezier(dc, curve, 3);
    DbgPrint(TAG "step 6: Polyline (9,50) %06lx (10,50) %06lx; LineTo (9,52) %06lx (10,52) %06lx; PolylineTo "
                 "(10,55) %06lx, position %ld,%ld; PolyBezier %d (20,50) %06lx (25,57) %06lx, 3 points %d\n",
             at(9, 50), at(10, 50), at(9, 52), at(10, 52), at(10, 55), position.x, position.y, bezier, at(20, 50),
             at(25, 57), wrong);

    /* 7. The triangle's region. */
    HRGN region = CreatePolygonRgn(triangle, 3, ALTERNATE);
    RECT bounds = {0};
    int complexity = region ? GetRgnBox(region, &bounds) : 0;
    DbgPrint(TAG "step 7: CreatePolygonRgn %d: complexity %d, box %ld,%ld,%ld,%ld\n", region != 0, complexity,
             bounds.left, bounds.top, bounds.right, bounds.bottom);

    /* 8. SetPixel. */
    COLORREF set = SetPixel(dc, 63, 63, RGB(1, 2, 3));
    DbgPrint(TAG "step 8: SetPixel %06lx: %06lx\n", set, at(63, 63));

    /* 9. A window painted by Polygon, a popup over it, then gone. */
    WNDCLASSW banded = {0}, plain = {0};
    banded.lpfnWndProc = banded_proc;
    banded.hInstance = GetModuleHandleW(0);
    banded.lpszClassName = L"PolyBanded";
    plain.lpfnWndProc = DefWindowProcW;
    plain.hInstance = banded.hInstance;
    plain.hbrBackground = GetStockObject(WHITE_BRUSH);
    plain.lpszClassName = L"PolyPopup";
    app_check(RegisterClassW(&banded) && RegisterClassW(&plain), "RegisterClassW");
    HWND window = CreateWindowExW(0, L"PolyBanded", L"Bands", WS_POPUP | WS_VISIBLE, 100, 100, 300, 200, 0, 0,
                                  banded.hInstance, 0);
    UpdateWindow(window);
    pump();
    HWND popup = CreateWindowExW(WS_EX_TOPMOST, L"PolyPopup", L"", WS_POPUP | WS_BORDER, 150, 150, 100, 60, window, 0,
                                 banded.hInstance, 0);
    ShowWindow(popup, SW_SHOWNOACTIVATE);
    UpdateWindow(popup);
    pump();
    Sleep(300);
    DestroyWindow(popup);
    for (int i = 0; i < 10; ++i) {
        pump();
        Sleep(50);
    }
    DbgPrint(TAG "step 9: the popup over the bands is gone\n");
    DbgPrint(TAG "done\n");
    for (;;) {
        pump();
        Sleep(100);
    }
    return 0;
}
