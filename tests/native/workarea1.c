/*
 * SystemParametersInfo(SPI_GETWORKAREA, SPI_SETWORKAREA): a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's user32,
 * which the scenario
 * `work-area` puts on the boot disk in the place of winlogon.exe. Apache
 * OpenOffice 4.1.17 started with no window: VCL centres its splash screen
 * and its first-start wizard in the work area that SPI_GETWORKAREA gives,
 * which Mino did not implement (FALSE). VCL used its RECT uninitialised and
 * put both windows at x = 0x4E4F43C0 and beyond; the wizard waited, unseen,
 * and every later launch waited on it. With SPI_GETWORKAREA alone,
 * explorer's taskbar disappeared: its desktop took the work area, the whole
 * screen, which explorer took for a full-screen application, and the taskbar
 * went to the bottom of the Z order; the taskbar sets the work area to keep
 * its room (SPI_SETWORKAREA). As ReactOS (sysparams.c,
 * UserSystemParametersInfo: the primary monitor's rcWork, SpiGet, SpiSet):
 * 1. SPI_GETWORKAREA gives TRUE and the whole RECT: the screen, with no
 *    taskbar to take room from it;
 * 2. the same rectangle as GetMonitorInfo's rcWork for the primary monitor;
 * 3. uiParam is ignored;
 * 4. a NULL pvParam gives FALSE;
 * 5. SPI_SETWORKAREA sets it: read back by SPI_GETWORKAREA and
 *    GetMonitorInfo;
 * 6. an empty rectangle, one beyond the screen, a NULL pvParam: FALSE, the
 *    work area kept;
 * 7. the whole screen again;
 * 8. with SPIF_SENDCHANGE, WM_SETTINGCHANGE (wParam SPI_SETWORKAREA, lParam
 *    NULL) reaches a top-level window of another thread, as explorer's
 *    desktop, which takes the new work area then: after a change of
 *    resolution, explorer took its desktop, still as large as the old
 *    screen, for a full-screen application and hid its taskbar again;
 * 9. without it, nothing is sent.
 * Like winlogon, the program takes WinSta0 and a desktop first: the windows
 * that WM_SETTINGCHANGE reaches are those of its caller's desktop.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef unsigned short WCHAR;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct {
    LONG left, top, right, bottom;
} RECT;

typedef struct {
    LONG x, y;
} POINT;

typedef struct {
    DWORD cbSize;
    RECT rcMonitor;
    RECT rcWork;
    DWORD dwFlags;
} MONITORINFO;

typedef struct {
    UINT style;
    WNDPROC proc;
    int class_extra, window_extra;
    HANDLE instance, icon, cursor, background;
    const WCHAR *menu, *name;
} WNDCLASSW;

typedef struct {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG;

#define SPI_SETWORKAREA 0x002F
#define SPI_GETWORKAREA 0x0030
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define MONITOR_DEFAULTTOPRIMARY 1
#define SENTINEL 0x5A5A5A5A
#define SPIF_SENDCHANGE 0x0002
#define WM_DESTROY 0x0002
#define WM_CLOSE 0x0010
#define WM_SETTINGCHANGE 0x001A
#define WS_POPUP 0x80000000
#define INFINITE 0xFFFFFFFF
#define MAXIMUM_ALLOWED 0x02000000

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                    DWORD access, void *attributes);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const void *name);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                         void *attributes);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, DWORD(__stdcall *start)(void *),
                                                    void *parameter, DWORD flags, DWORD *id);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HANDLE menu, HANDLE instance, void *parameter);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) unsigned short __stdcall RegisterClassW(const WNDCLASSW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall GetMonitorInfoW(HANDLE monitor, MONITORINFO *info);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) HANDLE __stdcall MonitorFromPoint(POINT point, DWORD flags);
__declspec(dllimport) BOOL __stdcall SystemParametersInfoW(UINT action, UINT param, void *pv, UINT win_ini);

/* A top-level window of another thread, as explorer's desktop: what
 * WM_SETTINGCHANGE brought it. */
static HANDLE listener_ready;
static HDESK desktop;
static HWND listener;
static volatile LONG settings_seen, settings_wparam, settings_lparam = -1;

static LRESULT __stdcall listener_proc(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_SETTINGCHANGE) {
        settings_seen++;
        settings_wparam = (LONG)w;
        settings_lparam = l;
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

static DWORD __stdcall listener_thread(void *parameter)
{
    WNDCLASSW window_class = {0};
    MSG message;
    (void)parameter;
    if (!SetThreadDesktop(desktop))
        DbgPrint("[workarea] SetThreadDesktop: error %lu\n", GetLastError());
    window_class.proc = listener_proc;
    window_class.instance = GetModuleHandleW(0);
    window_class.name = L"WorkAreaListener";
    if (!RegisterClassW(&window_class))
        DbgPrint("[workarea] RegisterClassW: error %lu\n", GetLastError());
    listener = CreateWindowExW(0, L"WorkAreaListener", L"listener", WS_POPUP, 0, 0, 10, 10, 0, 0,
                               window_class.instance, 0);
    if (!listener)
        DbgPrint("[workarea] CreateWindowExW: error %lu\n", GetLastError());
    SetEvent(listener_ready);
    if (!listener)
        return 1;
    while (GetMessageW(&message, 0, 0, 0) > 0)
        DispatchMessageW(&message);
    return 0;
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;

    if (!RegisterLogonProcess(GetCurrentProcessId(), 1))
        return 0;
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station))
        return 0;
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    return desktop && SetThreadDesktop(desktop) && SwitchDesktop(desktop);
}

static BOOL same(const RECT *a, const RECT *b)
{
    return a->left == b->left && a->top == b->top && a->right == b->right && a->bottom == b->bottom;
}

DWORD __stdcall GuiStartup(void)
{
    RECT work = {SENTINEL, SENTINEL, SENTINEL, SENTINEL}, again = {SENTINEL, SENTINEL, SENTINEL, SENTINEL};
    RECT screen = {0, 0, 0, 0};
    MONITORINFO info;
    POINT origin = {0, 0};
    BOOL got, got_monitor, got_again, got_null, set, empty, beyond, set_null, restored;
    HANDLE thread;
    LONG seen_before;
    RECT smaller, empty_rect, beyond_rect, now = {SENTINEL, SENTINEL, SENTINEL, SENTINEL};

    if (!take_a_desktop()) {
        DbgPrint("[workarea] no desktop\n");
        ExitProcess(1);
    }
    screen.right = GetSystemMetrics(SM_CXSCREEN);
    screen.bottom = GetSystemMetrics(SM_CYSCREEN);
    DbgPrint("[workarea] ready: a screen of %ldx%ld\n", screen.right, screen.bottom);

    /* 1. The work area: the whole screen. */
    got = SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    DbgPrint("[workarea] step 1: %d, (%ld,%ld)-(%ld,%ld), the screen %d\n", got, work.left, work.top, work.right,
             work.bottom, same(&work, &screen));

    /* 2. The primary monitor's rcWork. */
    info.cbSize = sizeof info;
    got_monitor = GetMonitorInfoW(MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY), &info);
    DbgPrint("[workarea] step 2: GetMonitorInfo %d, the same rcWork %d\n", got_monitor, same(&work, &info.rcWork));

    /* 3. uiParam does not count. */
    got_again = SystemParametersInfoW(SPI_GETWORKAREA, 123, &again, 0);
    DbgPrint("[workarea] step 3: uiParam 123: %d, the same %d\n", got_again, same(&again, &work));

    /* 4. Nowhere to write it. */
    got_null = SystemParametersInfoW(SPI_GETWORKAREA, 0, 0, 0);
    DbgPrint("[workarea] step 4: a NULL pvParam: %d\n", got_null);

    /* 5. A work area above a taskbar of 30 pixels. */
    smaller = screen;
    smaller.bottom -= 30;
    set = SystemParametersInfoW(SPI_SETWORKAREA, 0, &smaller, 0);
    got = SystemParametersInfoW(SPI_GETWORKAREA, 0, &now, 0);
    got_monitor = GetMonitorInfoW(MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY), &info);
    DbgPrint("[workarea] step 5: set %d, read back %d, the same %d, rcWork the same %d\n", set, got,
             same(&now, &smaller), got_monitor && same(&info.rcWork, &smaller));

    /* 6. Refused: nothing changes. */
    empty_rect = smaller;
    empty_rect.right = empty_rect.left;
    beyond_rect = screen;
    beyond_rect.bottom += 1;
    empty = SystemParametersInfoW(SPI_SETWORKAREA, 0, &empty_rect, 0);
    beyond = SystemParametersInfoW(SPI_SETWORKAREA, 0, &beyond_rect, 0);
    set_null = SystemParametersInfoW(SPI_SETWORKAREA, 0, 0, 0);
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &now, 0);
    DbgPrint("[workarea] step 6: empty %d, beyond the screen %d, NULL %d, kept %d\n", empty, beyond, set_null,
             same(&now, &smaller));

    /* 7. The whole screen again. */
    restored = SystemParametersInfoW(SPI_SETWORKAREA, 0, &screen, 0);
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &now, 0);
    DbgPrint("[workarea] step 7: %d, the screen %d\n", restored, same(&now, &screen));

    /* 8. Announced: another thread's top-level window hears of it. */
    listener_ready = CreateEventW(0, 1, 0, 0);
    thread = CreateThread(0, 0, listener_thread, 0, 0, 0);
    if (!listener_ready || !thread)
        ExitProcess(1);
    WaitForSingleObject(listener_ready, INFINITE);
    set = SystemParametersInfoW(SPI_SETWORKAREA, 0, &smaller, SPIF_SENDCHANGE);
    DbgPrint("[workarea] step 8: SPIF_SENDCHANGE %d, WM_SETTINGCHANGE %ld, wParam %lx, lParam %ld\n", set,
             settings_seen, settings_wparam, settings_lparam);

    /* 9. Not announced: nothing more, even later. */
    seen_before = settings_seen;
    restored = SystemParametersInfoW(SPI_SETWORKAREA, 0, &screen, 0);
    Sleep(300);
    DbgPrint("[workarea] step 9: without SPIF_SENDCHANGE %d, %ld more\n", restored, settings_seen - seen_before);
    PostMessageW(listener, WM_CLOSE, 0, 0);
    WaitForSingleObject(thread, INFINITE);

    DbgPrint("[workarea] done\n");
    ExitProcess(0);
    return 0;
}
