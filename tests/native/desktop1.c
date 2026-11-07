/*
 * Mino desktop design probe. It owns WinSta0\Default like winlogon, paints
 * the desktop shell from the installer design specification, and keeps the
 * Start menu keyboard-accessible. Built freestanding by xtask.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
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
typedef void *HGDIOBJ;
typedef void *HWINSTA;
typedef void *HDESK;
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
#define COLOR_WINDOW 5
#define WM_PAINT 0x000F
#define WM_KEYDOWN 0x0100
#define WM_CHAR 0x0102
#define VK_RETURN 0x0D
#define VK_ESCAPE 0x1B
#define VK_SPACE 0x20
#define VK_UP 0x26
#define VK_DOWN 0x28
#define TRANSPARENT 1
#define PATCOPY 0x00F00021
#define DT_LEFT 0x0000
#define DT_CENTER 0x0001
#define DT_RIGHT 0x0002
#define DT_VCENTER 0x0004
#define DT_WORDBREAK 0x0010
#define DT_SINGLELINE 0x0020
#define DT_NOPREFIX 0x0800
#define DEFAULT_GUI_FONT 17
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define RGB(r, g, b) ((COLORREF)((r) | ((g) << 8) | ((b) << 16)))

static const WCHAR CLASS_NAME[] = L"MinoDesktop";
static BOOL menu_open = TRUE;
static int selected_item;

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
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
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(COLORREF color);
__declspec(dllimport) BOOL __stdcall DeleteObject(HGDIOBJ object);
__declspec(dllimport) BOOL __stdcall GdiFlush(void);
__declspec(dllimport) HGDIOBJ __stdcall GetStockObject(int index);
__declspec(dllimport) BOOL __stdcall PatBlt(HDC dc, int x, int y, int width, int height, DWORD operation);
__declspec(dllimport) HGDIOBJ __stdcall SelectObject(HDC dc, HGDIOBJ object);
__declspec(dllimport) int __stdcall SetBkMode(HDC dc, int mode);
__declspec(dllimport) COLORREF __stdcall SetTextColor(HDC dc, COLORREF color);

void *memset(void *destination, int value, unsigned int count)
{
    BYTE *bytes = destination;
    while (count--)
        *bytes++ = (BYTE)value;
    return destination;
}

static RECT rect(LONG left, LONG top, LONG right, LONG bottom)
{
    RECT value = {left, top, right, bottom};
    return value;
}

static void fill(HDC dc, RECT area, COLORREF color)
{
    HBRUSH brush = CreateSolidBrush(color);
    HGDIOBJ previous;

    if (!brush)
        return;
    previous = SelectObject(dc, brush);
    PatBlt(dc, area.left, area.top, area.right - area.left, area.bottom - area.top, PATCOPY);
    if (previous)
        SelectObject(dc, previous);
    DeleteObject(brush);
}

static void border(HDC dc, RECT area, COLORREF color)
{
    fill(dc, rect(area.left, area.top, area.right, area.top + 1), color);
    fill(dc, rect(area.left, area.bottom - 1, area.right, area.bottom), color);
    fill(dc, rect(area.left, area.top, area.left + 1, area.bottom), color);
    fill(dc, rect(area.right - 1, area.top, area.right, area.bottom), color);
}

static void text(HDC dc, const WCHAR *value, RECT area, COLORREF color, UINT flags)
{
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextW(dc, value, -1, &area, flags | DT_NOPREFIX);
}

static void folder(HDC dc, int x, int y, const WCHAR *label)
{
    fill(dc, rect(x + 3, y, x + 18, y + 4), RGB(197, 137, 38));
    fill(dc, rect(x, y + 4, x + 31, y + 25), RGB(197, 137, 38));
    fill(dc, rect(x + 2, y + 6, x + 29, y + 23), RGB(255, 255, 255));
    text(dc, label, rect(x - 20, y + 34, x + 58, y + 56), RGB(38, 36, 31),
         DT_CENTER | DT_SINGLELINE);
}

static void draw_files(HDC dc, int width, int height)
{
    int left = width / 2 - 260;
    int top = height / 2 - 290;
    int right = left + 620;
    int bottom = top + 520;

    if (top < 32)
        top = 32;
    bottom = top + 520;
    fill(dc, rect(left, top, right, bottom), RGB(236, 231, 216));
    border(dc, rect(left, top, right, bottom), RGB(110, 104, 88));
    fill(dc, rect(left + 1, top + 1, right - 1, top + 32), RGB(227, 221, 203));
    fill(dc, rect(left + 10, top + 8, left + 28, top + 26), RGB(47, 107, 57));
    text(dc, L"F", rect(left + 10, top + 8, left + 28, top + 26), RGB(255, 255, 255),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Files — Home", rect(left + 38, top + 3, right - 100, top + 32), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"_   []   X", rect(right - 90, top + 3, right - 8, top + 32), RGB(87, 83, 74),
         DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(left + 1, top + 33, right - 1, top + 74), RGB(236, 231, 216));
    border(dc, rect(left + 10, top + 41, left + 36, top + 67), RGB(126, 120, 102));
    border(dc, rect(left + 44, top + 41, left + 70, top + 67), RGB(126, 120, 102));
    text(dc, L"<", rect(left + 10, top + 41, left + 36, top + 67), RGB(38, 36, 31),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L">", rect(left + 44, top + 41, left + 70, top + 67), RGB(38, 36, 31),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(left + 80, top + 41, right - 10, top + 67), RGB(255, 255, 255));
    border(dc, rect(left + 80, top + 41, right - 10, top + 67), RGB(126, 120, 102));
    text(dc, L"Home", rect(left + 96, top + 41, right - 20, top + 67), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(left + 1, top + 75, left + 158, bottom - 25), RGB(236, 231, 216));
    fill(dc, rect(left + 1, top + 75, left + 158, top + 115), RGB(199, 212, 224));
    text(dc, L"Home", rect(left + 38, top + 75, left + 150, top + 115), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Documents", rect(left + 38, top + 120, left + 150, top + 148), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Pictures", rect(left + 38, top + 150, left + 150, top + 178), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Downloads", rect(left + 38, top + 180, left + 150, top + 208), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(left + 158, top + 75, right - 1, bottom - 25), RGB(255, 255, 255));
    folder(dc, left + 205, top + 110, L"Documents");
    folder(dc, left + 300, top + 110, L"Downloads");
    folder(dc, left + 395, top + 110, L"Music");
    folder(dc, left + 490, top + 110, L"Pictures");
    folder(dc, left + 205, top + 205, L"Videos");
    text(dc, L"5 folders · Home · Mino system", rect(left + 12, bottom - 25, right - 12, bottom),
         RGB(87, 83, 74), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

static void draw_start_menu(HDC dc, int height)
{
    static const WCHAR *items[] = {L"Files", L"Text Editor", L"Terminal", L"Settings", L"Software", L"Help",
                                   L"Restart", L"Shut down"};
    int left = 10;
    int bottom = height - 56;
    int top = bottom - 352;
    int index;

    fill(dc, rect(left, top, left + 302, bottom), RGB(247, 243, 232));
    border(dc, rect(left, top, left + 302, bottom), RGB(110, 104, 88));
    fill(dc, rect(left + 16, top + 16, left + 46, top + 46), RGB(58, 110, 165));
    text(dc, L"M", rect(left + 16, top + 16, left + 46, top + 46), RGB(255, 255, 255),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Mino User", rect(left + 58, top + 10, left + 280, top + 34), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Local session", rect(left + 58, top + 32, left + 280, top + 52), RGB(87, 83, 74),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(left + 1, top + 62, left + 301, top + 63), RGB(219, 212, 194));
    for (index = 0; index < 8; ++index) {
        int row_top = top + 64 + index * 34 + (index >= 6 ? 8 : 0);
        if (index == selected_item) {
            fill(dc, rect(left + 2, row_top, left + 300, row_top + 32), RGB(58, 110, 165));
            border(dc, rect(left + 3, row_top + 1, left + 299, row_top + 31), RGB(30, 78, 121));
        }
        text(dc, items[index], rect(left + 44, row_top, left + 284, row_top + 32),
             index == selected_item ? RGB(255, 255, 255) : RGB(38, 36, 31),
             DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        text(dc, index < 6 ? L"[]" : L"o", rect(left + 15, row_top, left + 38, row_top + 32),
             index == selected_item ? RGB(255, 255, 255) : RGB(87, 83, 74),
             DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

static void draw_taskbar(HDC dc, int width, int height)
{
    int top = height - 46;

    fill(dc, rect(0, top, width, height), RGB(236, 231, 216));
    fill(dc, rect(0, top, width, top + 1), RGB(255, 255, 255));
    border(dc, rect(8, top + 7, 104, height - 5), RGB(30, 78, 121));
    fill(dc, rect(11, top + 10, 101, height - 8), menu_open ? RGB(227, 221, 203) : RGB(247, 243, 232));
    text(dc, L"M  Start", rect(11, top + 10, 101, height - 8), RGB(38, 36, 31),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    fill(dc, rect(114, top + 8, 202, height - 6), RGB(223, 230, 239));
    border(dc, rect(114, top + 8, 202, height - 6), RGB(58, 110, 165));
    text(dc, L"[]  Files", rect(122, top + 8, 196, height - 6), RGB(38, 36, 31),
         DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"network   volume       14:32", rect(width - 300, top + 3, width - 16, top + 23),
         RGB(87, 83, 74), DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    text(dc, L"Fri 7 Nov", rect(width - 150, top + 22, width - 16, height - 2), RGB(38, 36, 31),
         DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

static void draw(HWND window, HDC dc)
{
    RECT client;

    SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    GetClientRect(window, &client);
    fill(dc, client, RGB(219, 213, 197));
    text(dc, L"m", rect(client.right - 220, 70, client.right - 40, 220), RGB(196, 190, 174),
         DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    draw_files(dc, client.right, client.bottom);
    if (menu_open)
        draw_start_menu(dc, client.bottom);
    draw_taskbar(dc, client.right, client.bottom);
    GdiFlush();
}

static void repaint(HWND window)
{
    InvalidateRect(window, 0, TRUE);
    UpdateWindow(window);
}

static LRESULT __stdcall desktop_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    (void)l;
    if (message == WM_PAINT) {
        BeginPaint(window, &paint);
        draw(window, paint.hdc);
        EndPaint(window, &paint);
        return 0;
    }
    if (message == WM_KEYDOWN && menu_open) {
        if (w == VK_UP) {
            selected_item = selected_item ? selected_item - 1 : 7;
            repaint(window);
            return 0;
        }
        if (w == VK_DOWN) {
            selected_item = selected_item == 7 ? 0 : selected_item + 1;
            repaint(window);
            return 0;
        }
    }
    if (message == WM_CHAR) {
        if (w == VK_ESCAPE) {
            menu_open = FALSE;
            DbgPrint("[desktop] start menu closed\n");
            repaint(window);
            return 0;
        }
        if (w == VK_RETURN || w == VK_SPACE) {
            menu_open = !menu_open;
            DbgPrint("[desktop] start menu %s\n", menu_open ? "open" : "closed");
            repaint(window);
            return 0;
        }
    }
    return DefWindowProcW(window, message, w, l);
}

static BOOL take_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), TRUE))
        return FALSE;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return FALSE;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    return desktop && SetThreadDesktop(desktop) && SwitchDesktop(desktop);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;
    int width;
    int height;

    if (!take_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = desktop_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);
    window = CreateWindowExW(0, CLASS_NAME, L"Mino Desktop", WS_POPUP | WS_VISIBLE,
                             0, 0, width, height, 0, 0, instance, 0);
    if (!window)
        ExitProcess(3);
    UpdateWindow(window);
    DbgPrint("[desktop] start menu open\n");
    DbgPrint("[desktop] ready\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    ExitProcess(0);
    return 0;
}
