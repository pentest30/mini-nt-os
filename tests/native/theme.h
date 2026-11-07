/*
 * Mino's blue theme for the native GUI probes (SETUP1.EXE, DESKTOP1.EXE).
 *
 * An original theme in the style of the XP era: blue window frames with
 * rounded tops, glossy buttons, a blue taskbar. It uses no resource from any
 * other system: every shape is drawn here, the text is the Tahoma of the
 * pinned ReactOS.
 *
 * A probe draws a whole frame into a canvas (a 32-bit DIB section selected
 * in a memory DC: the program writes the pixels, win32k writes the text),
 * then copies it to its window with one BitBlt. This file also holds the
 * Win32 types and imports the probes share.
 */

#ifndef MINO_THEME_H
#define MINO_THEME_H

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned short USHORT;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HFONT;
typedef void *HBITMAP;
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HKL;
typedef void *HANDLE;
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
    BYTE rgbReserved[32];
} PAINTSTRUCT;

#define TRUE 1
#define FALSE 0
#define MAXIMUM_ALLOWED 0x02000000
#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define WM_PAINT 0x000F
#define WM_ERASEBKGND 0x0014
#define WM_KEYDOWN 0x0100
#define WM_CHAR 0x0102
#define VK_TAB 0x09
#define VK_RETURN 0x0D
#define VK_ESCAPE 0x1B
#define VK_SPACE 0x20
#define VK_UP 0x26
#define VK_DOWN 0x28
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define DT_LEFT 0x0000
#define DT_CENTER 0x0001
#define DT_RIGHT 0x0002
#define DT_VCENTER 0x0004
#define DT_BOTTOM 0x0008
#define DT_WORDBREAK 0x0010
#define DT_SINGLELINE 0x0020
#define DT_NOPREFIX 0x0800

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) int __stdcall DrawTextW(HDC dc, const WCHAR *text, int count, RECT *rect, UINT format);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) BOOL __stdcall InvalidateRect(HWND window, const RECT *rect, BOOL erase);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

void *memset(void *destination, int value, unsigned int count);
void *memcpy(void *destination, const void *source, unsigned int count);

/* A pixel of a 32-bit DIB: 0x00RRGGBB. */
typedef DWORD PIXEL;
#define PX(r, g, b) ((PIXEL)(((r) << 16) | ((g) << 8) | (b)))

/* The palette. */
#define C_WHITE PX(255, 255, 255)
#define C_INK PX(24, 32, 48)          /* body text */
#define C_INK_SOFT PX(74, 86, 110)    /* secondary text */
#define C_INK_BLUE PX(12, 48, 130)    /* headings and links */
#define C_FACE PX(238, 243, 252)      /* dialog and toolbar body */
#define C_FACE_LINE PX(198, 212, 238) /* etched lines on the face */
#define C_SELECT PX(49, 106, 197)     /* a selected item */
#define C_GREEN PX(46, 140, 58)
#define C_RED PX(196, 48, 36)
#define C_AMBER PX(150, 100, 10)

typedef struct {
    int width;
    int height;
    PIXEL *bits;
    HDC dc;
    HBITMAP bitmap;
    BOOL text_pending;
} CANVAS;

/* A vertical gradient: `count` stops, each at a fraction (0..256) of the
 * height. */
typedef struct {
    int at;
    PIXEL color;
} STOP;

enum Corners { CORNER_TL = 1, CORNER_TR = 2, CORNER_BL = 4, CORNER_BR = 8, CORNERS_TOP = 3, CORNERS_ALL = 15 };
enum ButtonState { BUTTON_NORMAL, BUTTON_FOCUSED, BUTTON_DISABLED };
enum Glyph { GLYPH_MINIMIZE, GLYPH_MAXIMIZE, GLYPH_CLOSE };

RECT rect(LONG left, LONG top, LONG right, LONG bottom);
PIXEL mix(PIXEL from, PIXEL to, int amount256);

BOOL canvas_create(CANVAS *canvas, int width, int height);
void canvas_present(CANVAS *canvas, HDC target);

void fill(CANVAS *canvas, RECT area, PIXEL color);
void frame(CANVAS *canvas, RECT area, PIXEL color);
void gradient(CANVAS *canvas, RECT area, PIXEL top, PIXEL bottom);
void gradient_stops(CANVAS *canvas, RECT area, const STOP *stops, int count);
void hgradient(CANVAS *canvas, RECT area, PIXEL left, PIXEL right);
void shade(CANVAS *canvas, RECT area, PIXEL color, int alpha256);
/* A rounded rectangle filled with a vertical gradient, anti-aliased. */
void round_fill(CANVAS *canvas, RECT area, int radius, int corners, PIXEL top, PIXEL bottom);
void round_fill_stops(CANVAS *canvas, RECT area, int radius, int corners, const STOP *stops, int count);
void glow(CANVAS *canvas, int cx, int cy, int radius, PIXEL color, int alpha);
void round_frame(CANVAS *canvas, RECT area, int radius, int corners, PIXEL color);
void disc(CANVAS *canvas, int cx, int cy, int radius, PIXEL top, PIXEL bottom);
void ring(CANVAS *canvas, int cx, int cy, int radius, int width, PIXEL color);
void line(CANVAS *canvas, int x0, int y0, int x1, int y1, int width, PIXEL color);

HFONT font(int pixels, BOOL bold);
void text(CANVAS *canvas, const WCHAR *value, RECT area, PIXEL color, HFONT face, UINT flags);
void text_shadow(CANVAS *canvas, const WCHAR *value, RECT area, PIXEL color, HFONT face, UINT flags);

/* The widgets. */
void caption_button(CANVAS *canvas, int x, int y, enum Glyph glyph);
/* A window frame: rounded blue title bar, borders, Close (and Minimize and
 * Maximize); returns the client area. The title leaves 28 pixels for an
 * icon, which the caller draws. */
RECT window_frame(CANVAS *canvas, RECT area, const WCHAR *title, BOOL with_size_buttons);
void button(CANVAS *canvas, RECT area, const WCHAR *label, enum ButtonState state);
void progress_bar(CANVAS *canvas, RECT area, int percent);
void check_mark(CANVAS *canvas, int x, int y, int size, PIXEL color);
void folder_icon(CANVAS *canvas, int x, int y, int size);
void emblem(CANVAS *canvas, int cx, int cy, int radius);
/* A card: a rounded panel with an accent on its left edge. */
void card(CANVAS *canvas, RECT area, PIXEL background, PIXEL border, PIXEL accent);

/* The probes' common start: logon process, WinSta0\Default, switched to. */
BOOL take_desktop(void);

#endif
