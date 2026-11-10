/*
 * M6, text: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32, user32 and gdi32, which the scenario `text`
 * puts on the boot disk in the place of winlogon.exe (like `gui`, see
 * gui1.c). It takes a desktop like winlogon, then works with the text of
 * GDI: stock fonts (GetStockObject), a font of its own (CreateFontW),
 * SelectObject, the text metrics and extents (GetTextMetricsW,
 * GetTextExtentPoint32W, GetTextExtentExPointW), text drawn in a window
 * (TextOutW transparent, ExtTextOutW opaque and clipped, in a bold font) and
 * user32's DrawTextW (words wrapped in a rectangle, a line centred in one,
 * the rectangle a text needs, a line cut to its rectangle) and the clip
 * region (IntersectClipRect, GetClipBox, SelectClipRgn). Each result goes to the
 * debug port (DbgPrint), where the scenario looks for it, and the drawing to
 * the screen, where it checks pixels; the program ends with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HFONT;
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef DWORD COLORREF;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HICON hCursor;
    HBRUSH hbrBackground;
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
    HICON hIconSm;
} WNDCLASSEXW;

typedef struct {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

typedef struct {
    LONG x;
    LONG y;
} POINT;

typedef struct {
    LONG cx;
    LONG cy;
} SIZE;

typedef struct {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG;

typedef struct {
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
} PAINTSTRUCT;

typedef struct {
    LONG tmHeight;
    LONG tmAscent;
    LONG tmDescent;
    LONG tmInternalLeading;
    LONG tmExternalLeading;
    LONG tmAveCharWidth;
    LONG tmMaxCharWidth;
    LONG tmWeight;
    LONG tmOverhang;
    LONG tmDigitizedAspectX;
    LONG tmDigitizedAspectY;
    WCHAR tmFirstChar;
    WCHAR tmLastChar;
    WCHAR tmDefaultChar;
    WCHAR tmBreakChar;
    BYTE tmItalic;
    BYTE tmUnderlined;
    BYTE tmStruckOut;
    BYTE tmPitchAndFamily;
    BYTE tmCharSet;
} TEXTMETRICW;

#define WS_OVERLAPPED 0x00000000
#define WS_CAPTION 0x00C00000
#define WS_SYSMENU 0x00080000
#define WS_VISIBLE 0x10000000
#define WM_PAINT 0x000F
#define PM_REMOVE 1
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define SYSTEM_FONT 13
#define DEFAULT_GUI_FONT 17
#define OBJ_FONT 6
#define FW_NORMAL 400
#define FW_BOLD 700
#define DEFAULT_CHARSET 1
#define TRANSPARENT 1
#define OPAQUE 2
#define ETO_OPAQUE 0x0002
#define ETO_CLIPPED 0x0004
#define DT_CENTER 0x0001
#define DT_VCENTER 0x0004
#define DT_WORDBREAK 0x0010
#define DT_SINGLELINE 0x0020
#define DT_CALCRECT 0x0400
#define DT_NOPREFIX 0x0800
#define RGB(r, g, b) ((COLORREF)((r) | ((g) << 8) | ((b) << 16)))
#define EXIT_STATUS 0x600D

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) int __stdcall DrawTextW(HDC dc, const WCHAR *text, int count, RECT *rect, UINT format);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC dc);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

__declspec(dllimport) HFONT __stdcall CreateFontW(int height, int width, int escapement, int orientation, int weight,
                                                  DWORD italic, DWORD underline, DWORD strike_out, DWORD char_set,
                                                  DWORD out_precision, DWORD clip_precision, DWORD quality,
                                                  DWORD pitch_and_family, const WCHAR *face);
__declspec(dllimport) BOOL __stdcall DeleteObject(HGDIOBJ object);
__declspec(dllimport) BOOL __stdcall ExtTextOutW(HDC dc, int x, int y, UINT options, const RECT *rect,
                                                 const WCHAR *string, UINT count, const int *dx);
__declspec(dllimport) BOOL __stdcall GdiFlush(void);
__declspec(dllimport) int __stdcall GetClipBox(HDC dc, RECT *rect);
__declspec(dllimport) DWORD __stdcall GetObjectType(HGDIOBJ object);
__declspec(dllimport) HGDIOBJ __stdcall GetStockObject(int index);
__declspec(dllimport) BOOL __stdcall GetTextExtentExPointW(HDC dc, const WCHAR *string, int count, int max_extent,
                                                           int *fit, int *dx, SIZE *size);
__declspec(dllimport) BOOL __stdcall GetTextExtentPoint32W(HDC dc, const WCHAR *string, int count, SIZE *size);
__declspec(dllimport) BOOL __stdcall GetTextMetricsW(HDC dc, TEXTMETRICW *metrics);
__declspec(dllimport) int __stdcall IntersectClipRect(HDC dc, int left, int top, int right, int bottom);
__declspec(dllimport) int __stdcall SelectClipRgn(HDC dc, void *region);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);
__declspec(dllimport) COLORREF __stdcall SetBkColor(HDC dc, COLORREF color);
__declspec(dllimport) int __stdcall SetBkMode(HDC dc, int mode);
__declspec(dllimport) COLORREF __stdcall SetTextColor(HDC dc, COLORREF color);
__declspec(dllimport) BOOL __stdcall TextOutW(HDC dc, int x, int y, const WCHAR *string, int count);

static const WCHAR CLASS_NAME[] = L"MinoText";
static int painted;

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned int count)
{
    unsigned char *to = destination;
    const unsigned char *from = source;
    while (count--)
        *to++ = *from++;
    return destination;
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), 1))
        return 0;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return 0;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    if (!desktop || !SetThreadDesktop(desktop) || !SwitchDesktop(desktop))
        return 0;
    DbgPrint("[text] on WinSta0\\Default\n");
    return 1;
}

/* Tahoma Bold of the caption's size. */
static HFONT bold_font(void)
{
    return CreateFontW(-11, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Tahoma");
}

/* DrawTextW: words wrapped in a rectangle of 100 x 40 pixels from 10, 100
   (navy, transparent), a line centred in a rectangle from 150, 100 to
   250, 140, the rectangle a text needs (DT_CALCRECT), a line cut to a
   rectangle from 260, 100 to 300, 113; then "After" at 10, 150, which shows
   only if DrawTextW gave the DC its clip region back. */
static void draw_text(HDC dc)
{
    RECT wrapped = {10, 100, 110, 140};
    RECT centred = {150, 100, 250, 140};
    RECT needed = {0, 0, 0, 0};
    RECT cut = {260, 100, 300, 113};
    int height;

    height = DrawTextW(dc, L"Words wrapped on more lines", -1, &wrapped, DT_WORDBREAK | DT_NOPREFIX);
    DbgPrint("[text] DrawTextW, wrapped: %d\n", height);
    height = DrawTextW(dc, L"Centred", -1, &centred, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    DbgPrint("[text] DrawTextW, centred: %d\n", height);
    height = DrawTextW(dc, L"Words wrapped on more lines", -1, &needed, DT_CALCRECT | DT_NOPREFIX);
    DbgPrint("[text] DrawTextW(DT_CALCRECT): %d, %ld x %ld\n", height, needed.right, needed.bottom);
    height = DrawTextW(dc, L"Clipped text", -1, &cut, DT_SINGLELINE | DT_NOPREFIX);
    DbgPrint("[text] DrawTextW, cut: %d; TextOutW after it: %d\n", height, TextOutW(dc, 10, 150, L"After", 5));
}

/* IntersectClipRect alone, twice: the second rectangle crosses the clip
   region the first one made, which (seen by GetClipBox) is then from 100, 150
   to 140, 163 and cuts at 140 a text that TextOutW does not clip;
   SelectClipRgn(NULL) takes it back. */
static void clip_rect(HDC dc)
{
    RECT box;
    int first = IntersectClipRect(dc, 100, 140, 300, 163);
    int kind = IntersectClipRect(dc, 50, 150, 140, 170);

    GetClipBox(dc, &box);
    DbgPrint("[text] IntersectClipRect: %d, %d, box %ld %ld %ld %ld; TextOutW: %d\n", first, kind, box.left, box.top,
             box.right, box.bottom, TextOutW(dc, 100, 150, L"Clipped text", 12));
    kind = SelectClipRgn(dc, 0);
    GetClipBox(dc, &box);
    DbgPrint("[text] SelectClipRgn(NULL): %d, box %ld %ld %ld %ld\n", kind, box.left, box.top, box.right, box.bottom);
}

/* What the window paints: "Mino" in navy on its white background
   (transparent), "Opaque" on yellow cut to its rectangle, "Bold" in Tahoma
   Bold. */
static void draw_texts(HDC dc)
{
    RECT rect = {10, 40, 60, 60};
    HFONT bold;
    HGDIOBJ old;

    old = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    SetTextColor(dc, RGB(0, 0, 128));
    SetBkMode(dc, TRANSPARENT);
    DbgPrint("[text] TextOutW: %d\n", TextOutW(dc, 10, 10, L"Mino", 4));
    SetBkMode(dc, OPAQUE);
    SetBkColor(dc, RGB(255, 255, 0));
    DbgPrint("[text] ExtTextOutW, opaque and clipped: %d\n",
             ExtTextOutW(dc, 12, 42, ETO_OPAQUE | ETO_CLIPPED, &rect, L"Opaque text", 11, 0));
    bold = bold_font();
    SelectObject(dc, bold);
    SetBkMode(dc, TRANSPARENT);
    DbgPrint("[text] TextOutW, bold: %d\n", TextOutW(dc, 10, 70, L"Bold", 4));
    SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    draw_text(dc);
    clip_rect(dc);
    SelectObject(dc, old);
    DeleteObject(bold);
    GdiFlush();
}

static LRESULT __stdcall text_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    if (message == WM_PAINT) {
        HDC dc = BeginPaint(window, &paint);
        draw_texts(dc);
        EndPaint(window, &paint);
        painted = 1;
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

/* The stock fonts: fonts, public, the DC's default the system font. */
static void check_stock_fonts(void)
{
    HGDIOBJ gui = GetStockObject(DEFAULT_GUI_FONT);
    HGDIOBJ system = GetStockObject(SYSTEM_FONT);

    DbgPrint("[text] GetStockObject: DEFAULT_GUI_FONT %s (type %lu), SYSTEM_FONT %s (type %lu)\n",
             gui ? "a font" : "none", GetObjectType(gui), system ? "a font" : "none", GetObjectType(system));
}

/* The metrics and extents of the default GUI font (MS Shell Dlg, -11: Tahoma)
   and of a bold font. */
static void check_metrics(HWND window)
{
    TEXTMETRICW metrics;
    SIZE size, bold_size;
    HDC dc = GetDC(window);
    HGDIOBJ old;
    HFONT bold;

    old = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    DbgPrint("[text] SelectObject: the old font is %s\n",
             old == GetStockObject(SYSTEM_FONT) ? "the system font" : "WRONG");
    memset(&metrics, 0, sizeof metrics);
    if (GetTextMetricsW(dc, &metrics))
        DbgPrint("[text] GetTextMetricsW: height %ld, ascent %ld, descent %ld, internal %ld, external %ld, "
                 "average %ld, maximum %ld, weight %ld, chars %04x-%04x, pitch %02x, charset %u\n",
                 metrics.tmHeight, metrics.tmAscent, metrics.tmDescent, metrics.tmInternalLeading,
                 metrics.tmExternalLeading, metrics.tmAveCharWidth, metrics.tmMaxCharWidth, metrics.tmWeight,
                 metrics.tmFirstChar, metrics.tmLastChar, metrics.tmPitchAndFamily, metrics.tmCharSet);
    else
        DbgPrint("[text] GetTextMetricsW failed (%lu)\n", GetLastError());
    memset(&size, 0, sizeof size);
    GetTextExtentPoint32W(dc, L"Mino", 4, &size);
    bold = bold_font();
    DbgPrint("[text] CreateFontW: %s (type %lu)\n", bold ? "a font" : "none", GetObjectType(bold));
    SelectObject(dc, bold);
    memset(&bold_size, 0, sizeof bold_size);
    GetTextExtentPoint32W(dc, L"Mino", 4, &bold_size);
    DbgPrint("[text] GetTextExtentPoint32W(Mino): %ld x %ld, bold %ld x %ld\n", size.cx, size.cy, bold_size.cx,
             bold_size.cy);
    SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    {
        int fit = -1, dx[4] = {0, 0, 0, 0};
        BOOL got = GetTextExtentExPointW(dc, L"Mino", 4, 12, &fit, dx, &size);
        DbgPrint("[text] GetTextExtentExPointW(Mino, 12): %d, fit %d, dx %d %d %d %d, %ld x %ld\n", got, fit, dx[0],
                 dx[1], dx[2], dx[3], size.cx, size.cy);
    }
    SelectObject(dc, old);
    DeleteObject(bold);
    ReleaseDC(window, dc);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;
    int round;

    if (!take_a_desktop())
        ExitProcess(1);
    check_stock_fonts();
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = text_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    window = CreateWindowExW(0, CLASS_NAME, L"Text", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 300, 200,
                             360, 200, 0, 0, instance, 0);
    if (!window)
        ExitProcess(3);
    for (round = 0; round < 100 && !painted; round++)
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
            DispatchMessageW(&message);
    DbgPrint("[text] painted: %s\n", painted ? "yes" : "no");
    check_metrics(window);

    DbgPrint("[text] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
