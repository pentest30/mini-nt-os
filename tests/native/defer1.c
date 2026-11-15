/*
 * What explorer's taskbar asks of USER before it lays its controls out: a
 * Win32 program (subsystem WINDOWS), compiled with MinGW and linked to
 * ReactOS's kernel32 and user32, which the scenario `defer-window-pos` puts
 * on the boot disk in the place of winlogon.exe (like zorder1.c). The
 * taskbar places its Start button, its band site and its tray by
 * BeginDeferWindowPos, DeferWindowPos and EndDeferWindowPos (traywnd.cpp,
 * AlignControls): without them the button kept its size of 0. It also calls
 * SetWindowRgn(NULL) and RemoveProp. The program takes a desktop like
 * winlogon, shows two popups A and B, then:
 * 1. BeginDeferWindowPos(-1): NULL, ERROR_INVALID_PARAMETER;
 * 2. a batch that moves A, sizes B, then sizes A again without moving it
 *    (SWP_NOMOVE): the two moves of A merge; EndDeferWindowPos places both;
 * 3. the ended batch: EndDeferWindowPos and DeferWindowPos fail with
 *    ERROR_INVALID_DWP_HANDLE;
 * 4. flags DeferWindowPos refuses (an unknown one: ERROR_INVALID_FLAGS;
 *    SWP_ASYNCWINDOWPOS: ERROR_INVALID_PARAMETER), the desktop window
 *    refused; an empty batch ends;
 * 5. SetWindowRgn(A, NULL, TRUE): A, under B, goes to the top of its
 *    siblings (SetWindowPos HWND_TOP, as ReactOS);
 * 6. RemoveProp: the property's data, then nothing left.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
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
typedef void *HANDLE;
typedef void *HWND;
typedef void *HDWP;
typedef void *HRGN;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
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

#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002
#define SWP_NOZORDER 0x0004
#define SWP_NOACTIVATE 0x0010
#define SWP_ASYNCWINDOWPOS 0x4000
#define GW_HWNDPREV 3
#define MAXIMUM_ALLOWED 0x02000000
#define COLOR_WINDOW 5
#define EXIT_STATUS 0x7006

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) HDWP __stdcall BeginDeferWindowPos(int count);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) HDWP __stdcall DeferWindowPos(HDWP batch, HWND window, HWND after, int x, int y, int cx, int cy,
                                                    UINT flags);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall EndDeferWindowPos(HDWP batch);
__declspec(dllimport) HWND __stdcall GetDesktopWindow(void);
__declspec(dllimport) HANDLE __stdcall GetPropW(HWND window, const WCHAR *name);
__declspec(dllimport) HWND __stdcall GetWindow(HWND window, UINT command);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HANDLE __stdcall RemovePropW(HWND window, const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetPropW(HWND window, const WCHAR *name, HANDLE data);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) int __stdcall SetWindowRgn(HWND window, HRGN region, BOOL redraw);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

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
    return 1;
}

static LRESULT __stdcall procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    return DefWindowProcW(hwnd, message, w, l);
}

/* The window's rectangle, "left,top-right,bottom", to the debug port. */
static void print_rect(const char *what, HWND window)
{
    RECT rect = {0, 0, 0, 0};

    GetWindowRect(window, &rect);
    DbgPrint("[defer] %s at %ld,%ld-%ld,%ld\n", what, rect.left, rect.top, rect.right, rect.bottom);
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    WNDCLASSEXW class_info;
    HWND a, b;
    HDWP batch, again;
    BOOL ended, same, unknown, asynchronous, under;
    DWORD error, async_error, removed, left;
    int region;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoDefer";
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    a = CreateWindowExW(0, L"MinoDefer", L"A", WS_POPUP | WS_VISIBLE, 10, 10, 50, 50, 0, 0, instance, 0);
    b = CreateWindowExW(0, L"MinoDefer", L"B", WS_POPUP | WS_VISIBLE, 70, 10, 50, 50, 0, 0, instance, 0);
    if (!a || !b)
        ExitProcess(3);
    DbgPrint("[defer] ready\n");

    SetLastError(0);
    batch = BeginDeferWindowPos(-1);
    error = GetLastError();
    DbgPrint("[defer] step 1: BeginDeferWindowPos(-1): %d, error %lu\n", batch != 0, error);

    batch = BeginDeferWindowPos(1);
    again = DeferWindowPos(batch, a, 0, 100, 100, 200, 150, SWP_NOZORDER | SWP_NOACTIVATE);
    same = batch != 0 && again == batch;
    again = DeferWindowPos(batch, b, 0, 400, 120, 150, 100, SWP_NOZORDER | SWP_NOACTIVATE);
    same = same && again == batch;
    again = DeferWindowPos(batch, a, 0, 0, 0, 250, 180, SWP_NOZORDER | SWP_NOMOVE | SWP_NOACTIVATE);
    same = same && again == batch;
    ended = EndDeferWindowPos(batch);
    DbgPrint("[defer] step 2: a batch of three moves, the same handle %d; EndDeferWindowPos %d\n", same, ended);
    print_rect("A", a);
    print_rect("B", b);

    SetLastError(0);
    ended = EndDeferWindowPos(batch);
    error = GetLastError();
    SetLastError(0);
    again = DeferWindowPos(batch, a, 0, 1, 1, 1, 1, SWP_NOZORDER);
    DbgPrint("[defer] step 3: the ended batch: EndDeferWindowPos %d, error %lu; DeferWindowPos %d, error %lu\n", ended,
             error, again != 0, GetLastError());

    batch = BeginDeferWindowPos(0);
    SetLastError(0);
    again = DeferWindowPos(batch, a, 0, 1, 1, 1, 1, 0x10000);
    unknown = again != 0;
    error = GetLastError();
    SetLastError(0);
    again = DeferWindowPos(batch, a, 0, 1, 1, 1, 1, SWP_ASYNCWINDOWPOS);
    asynchronous = again != 0;
    async_error = GetLastError();
    again = DeferWindowPos(batch, GetDesktopWindow(), 0, 1, 1, 1, 1, SWP_NOZORDER);
    ended = EndDeferWindowPos(batch);
    DbgPrint("[defer] step 4: an unknown flag: %d, error %lu; SWP_ASYNCWINDOWPOS: %d, error %lu; the desktop window: %d; "
             "the empty batch ends %d\n",
             unknown, error, asynchronous, async_error, again != 0, ended);
    print_rect("A still", a);

    under = GetWindow(a, GW_HWNDPREV) == b;
    region = SetWindowRgn(a, 0, 1);
    DbgPrint("[defer] step 5: A under B: %d; SetWindowRgn(A, NULL) %d, A on top %d\n", under, region != 0,
             GetWindow(a, GW_HWNDPREV) == 0);

    SetPropW(a, L"MinoProp", (HANDLE)0x1234);
    removed = (DWORD)RemovePropW(a, L"MinoProp");
    left = (DWORD)GetPropW(a, L"MinoProp");
    DbgPrint("[defer] step 6: RemoveProp %lx, then GetProp %lx and RemoveProp %lx\n", removed, left,
             (DWORD)RemovePropW(a, L"MinoProp"));

    DbgPrint("[defer] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
