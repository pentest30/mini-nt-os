/*
 * The caret: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32, user32 and gdi32, which the scenario `caret`
 * puts on the boot disk in the place of winlogon.exe (like `scrollex`, see
 * scrollx1.c). On WinSta0\Default, W at 100, 100 (400 x 300, white, its
 * client area from 104, 124) takes a caret of 2 x 16 pixels, which it reads
 * back from the screen at each step (GetPixel on its DC: black where the
 * caret inverts the white, white where it does not):
 * - without a caret, SetCaretPos fails; a caret whose window is destroyed
 *   goes with it;
 * - CreateCaret: hidden, at 0, 0; SetCaretPos; HideCaret of a window
 *   without it fails (ERROR_ACCESS_DENIED); ShowCaret draws it at once;
 * - it blinks: WM_SYSTIMER (IDCARETTIMER) comes to the message loop every
 *   100 ms, which DispatchMessage gives back to the kernel;
 * - INFINITE as the blink time: it stays drawn; hidden twice, shown once,
 *   it stays hidden; moved, it leaves its place clean;
 * - WM_PAINT (BeginPaint hides it, EndPaint shows it) and ScrollWindowEx
 *   (it moves with the content) leave it drawn.
 * Each step goes to the debug port (DbgPrint, a line each, its values taken
 * before); the program ends with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HBITMAP;
typedef void *HDC;
typedef void *HRGN;
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
    HCURSOR hCursor;
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
    unsigned char rgbReserved[32];
} PAINTSTRUCT;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_VISIBLE 0x10000000
#define WM_PAINT 0x000F
#define WM_TIMER 0x0113
#define WM_SYSTIMER 0x0118
#define WM_APP 0x8000
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define SW_INVALIDATE 0x0002
#define SW_ERASE 0x0004
#define IDCARETTIMER 0xFFFF
#define INFINITE 0xFFFFFFFF
#define EXIT_STATUS 0x6013

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) COLORREF __stdcall GetPixel(HDC hdc, int x, int y);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) BOOL __stdcall CreateCaret(HWND window, HBITMAP bitmap, int width, int height);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall DestroyCaret(void);
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) UINT __stdcall GetCaretBlinkTime(void);
__declspec(dllimport) BOOL __stdcall GetCaretPos(POINT *point);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall HideCaret(HWND window);
__declspec(dllimport) BOOL __stdcall InvalidateRect(HWND window, const RECT *rect, BOOL erase);
__declspec(dllimport) BOOL __stdcall KillTimer(HWND window, UINT id);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC hdc);
__declspec(dllimport) int __stdcall ScrollWindowEx(HWND window, int dx, int dy, const RECT *scroll, const RECT *clip,
                                                   HRGN update, RECT *update_rect, UINT flags);
__declspec(dllimport) BOOL __stdcall SetCaretBlinkTime(UINT milliseconds);
__declspec(dllimport) BOOL __stdcall SetCaretPos(int x, int y);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) UINT __stdcall SetTimer(HWND window, UINT id, UINT elapse, void *procedure);
__declspec(dllimport) BOOL __stdcall ShowCaret(HWND window);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

static const WCHAR CLASS_NAME[] = L"MinoCaret";
static HWND w;
static int painted;

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
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
    DbgPrint("[caret] on WinSta0\\Default\n");
    return 1;
}

/* The colour at (x, y) of W's client area, on the screen. */
static COLORREF pixel(int x, int y)
{
    HDC hdc = GetDC(w);
    COLORREF color = GetPixel(hdc, x, y);
    ReleaseDC(w, hdc);
    return color;
}

/* Pumps W's messages for about `milliseconds`, counting the caret's
 * WM_SYSTIMER messages, each given back to the kernel. */
static int pump(UINT milliseconds)
{
    MSG message;
    int blinks = 0;

    SetTimer(w, 1, milliseconds, 0);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        if (message.message == WM_TIMER && message.hwnd == w && message.wParam == 1)
            break;
        if (message.message == WM_SYSTIMER && message.wParam == IDCARETTIMER)
            blinks++;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    KillTimer(w, 1);
    return blinks;
}

static void steps(void)
{
    POINT at = {-1, -1};
    HWND other;
    BOOL ok, ok2;
    DWORD error;
    COLORREF before, after;
    UINT time;
    int blinks;

    DbgPrint("[caret] blink time %u\n", GetCaretBlinkTime());
    ok = DestroyCaret();
    DbgPrint("[caret] without a caret: DestroyCaret %d, SetCaretPos %d\n", ok, SetCaretPos(1, 1));

    other = CreateWindowExW(0, CLASS_NAME, L"O", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 600, 100, 200, 100, 0, 0,
                            GetModuleHandleW(0), 0);
    CreateCaret(other, 0, 2, 16);
    ShowCaret(other);
    DestroyWindow(other);
    DbgPrint("[caret] its window destroyed: SetCaretPos %d\n", SetCaretPos(1, 1));

    SetCaretBlinkTime(100);
    other = CreateWindowExW(0, CLASS_NAME, L"O", WS_OVERLAPPEDWINDOW, 600, 100, 200, 100, 0, 0, GetModuleHandleW(0), 0);
    ok = CreateCaret(w, 0, 2, 16);
    GetCaretPos(&at);
    before = pixel(10, 40);
    ok2 = SetCaretPos(10, 40);
    DbgPrint("[caret] CreateCaret %d, at %ld %ld, hidden %06lx; SetCaretPos %d\n", ok, at.x, at.y, before, ok2);
    GetCaretPos(&at);
    SetLastError(0);
    ok = HideCaret(other);
    error = GetLastError();
    DbgPrint("[caret] at %ld %ld; HideCaret of a window without it: %d (%lu)\n", at.x, at.y, ok, error);
    ok = ShowCaret(w);
    DbgPrint("[caret] ShowCaret %d: %06lx %06lx, beside it %06lx\n", ok, pixel(10, 40), pixel(11, 55), pixel(12, 40));

    blinks = pump(450);
    DbgPrint("[caret] blinking: at least 3 WM_SYSTIMER %d\n", blinks >= 3);

    HideCaret(w);
    before = pixel(10, 40);
    SetCaretBlinkTime(INFINITE);
    time = GetCaretBlinkTime();
    ShowCaret(w);
    after = pixel(10, 40);
    DbgPrint("[caret] steady: hidden %06lx, blink time %ld, shown %06lx\n", before, (LONG)time, after);
    pump(250);
    DbgPrint("[caret] steady 250 ms later: %06lx\n", pixel(10, 40));

    HideCaret(w);
    HideCaret(w);
    ShowCaret(w);
    before = pixel(10, 40);
    ShowCaret(w);
    DbgPrint("[caret] hidden twice, shown once: %06lx; shown again: %06lx\n", before, pixel(10, 40));

    SetCaretPos(30, 40);
    DbgPrint("[caret] moved: where it was %06lx, where it is %06lx\n", pixel(10, 40), pixel(30, 40));

    InvalidateRect(w, 0, 1);
    UpdateWindow(w);
    DbgPrint("[caret] after WM_PAINT: %06lx\n", pixel(30, 40));

    ScrollWindowEx(w, 0, -10, 0, 0, 0, 0, SW_INVALIDATE | SW_ERASE);
    UpdateWindow(w);
    GetCaretPos(&at);
    DbgPrint("[caret] scrolled up 10: at %ld %ld, %06lx, below it %06lx\n", at.x, at.y, pixel(30, 35), pixel(30, 50));
    DbgPrint("[caret] done\n");
    PostQuitMessage(0);
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    PAINTSTRUCT paint;

    switch (message) {
    case WM_PAINT:
        BeginPaint(window, &paint);
        EndPaint(window, &paint);
        if (window == w && !painted) {
            painted = 1;
            PostMessageW(window, WM_APP, 0, 0);
        }
        return 0;
    case WM_APP:
        steps();
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    w = CreateWindowExW(0, CLASS_NAME, L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0, instance, 0);
    if (!w)
        ExitProcess(3);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
