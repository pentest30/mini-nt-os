/*
 * The shell hooks and the minimized windows of a shell: a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's user32,
 * which the scenario `shell-hooks` puts on the boot disk in the place of
 * winlogon.exe. Explorer's taskbar showed no button: its task list
 * registers for the shell hooks (RegisterShellHookWindow, then the
 * registered message "SHELLHOOK" on each top-level window shown, activated,
 * renamed, hidden or destroyed), and win32k had none. A minimized window
 * went to the bottom left of the screen, under the taskbar: explorer asks
 * for ARW_HIDE (SPI_SETMINIMIZEDMETRICS), which win32k did not take. As
 * ReactOS (desktop.c: IntRegisterShellHookWindow, co_IntShellHookNotify;
 * winpos.c, window.c, focus.c: UpdateShellHook; simplecall.c; sysparams.c):
 * 1. RegisterShellHookWindow for a window of another thread; SetTaskmanWindow,
 *    read back by GetTaskmanWindow;
 * 2. an application window shown: HSHELL_WINDOWCREATED and
 *    HSHELL_WINDOWACTIVATED for it;
 * 3. its title changed: HSHELL_REDRAW;
 * 4. hidden: HSHELL_WINDOWDESTROYED;
 * 5. a tool window and an owned window shown: nothing for them;
 * 6. destroyed: HSHELL_WINDOWDESTROYED;
 * 7. once deregistered, nothing more;
 * 8. SPI_GETMINIMIZEDMETRICS and SPI_SETMINIMIZEDMETRICS (SM_ARRANGE follows);
 *    with ARW_HIDE, a minimized window goes to (-32000, -32000).
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

typedef struct {
    UINT cbSize;
    int iWidth, iHorzGap, iVertGap, iArrange;
} MINIMIZEDMETRICS;

#define HSHELL_WINDOWCREATED 1
#define HSHELL_WINDOWDESTROYED 2
#define HSHELL_WINDOWACTIVATED 4
#define HSHELL_REDRAW 6
#define SPI_GETMINIMIZEDMETRICS 0x002B
#define SPI_SETMINIMIZEDMETRICS 0x002C
#define SM_ARRANGE 56
#define ARW_HIDE 0x0008
#define SW_HIDE 0
#define SW_SHOW 5
#define SW_MINIMIZE 6
#define WM_DESTROY 0x0002
#define WM_CLOSE 0x0010
#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_POPUP 0x80000000
#define WS_EX_TOOLWINDOW 0x00000080
#define INFINITE 0xFFFFFFFF
#define MAXIMUM_ALLOWED 0x02000000
#define EVENTS 64

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const void *name);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, DWORD(__stdcall *start)(void *),
                                                    void *parameter, DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                    DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                         void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HANDLE menu, HANDLE instance, void *parameter);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall DeregisterShellHookWindow(HWND window);
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) HWND __stdcall GetTaskmanWindow(void);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) unsigned short __stdcall RegisterClassW(const WNDCLASSW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall RegisterShellHookWindow(HWND window);
__declspec(dllimport) UINT __stdcall RegisterWindowMessageW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetTaskmanWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SetWindowTextW(HWND window, const WCHAR *text);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SystemParametersInfoW(UINT action, UINT param, void *pv, UINT win_ini);

static HDESK desktop;
static HANDLE instance, listener_ready;
static HWND listener;
static UINT shell_message;
static BOOL registered, taskman_set;

/* What the shell hook window received: HSHELL_* code and window. */
static volatile LONG event_count;
static volatile LONG event_code[EVENTS];
static volatile LONG event_window[EVENTS];

static LRESULT __stdcall listener_proc(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (shell_message && message == shell_message) {
        LONG at = event_count;
        if (at < EVENTS) {
            event_code[at] = (LONG)w;
            event_window[at] = l;
            event_count = at + 1;
        }
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

static LRESULT __stdcall plain_proc(HWND window, UINT message, WPARAM w, LPARAM l)
{
    return DefWindowProcW(window, message, w, l);
}

static DWORD __stdcall listener_thread(void *parameter)
{
    MSG message;
    (void)parameter;
    SetThreadDesktop(desktop);
    listener = CreateWindowExW(0, L"ShellHookListener", L"listener", WS_POPUP, 0, 0, 10, 10, 0, 0, instance, 0);
    if (listener) {
        registered = RegisterShellHookWindow(listener);
        taskman_set = SetTaskmanWindow(listener) != 0;
    }
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

/* The listener had time to take what was posted to it. */
static void settle(void)
{
    Sleep(300);
}

/* How many events `code` it received for `window` since `from`. */
static int seen(LONG from, LONG code, HWND window)
{
    int found = 0;
    LONG i;
    for (i = from; i < event_count; i++)
        found += event_code[i] == code && event_window[i] == (LONG)window;
    return found;
}

static HWND create(DWORD ex_style, DWORD style, HWND owner, const WCHAR *title)
{
    return CreateWindowExW(ex_style, L"ShellHookPlain", title, style, 100, 100, 300, 200, owner, 0, instance, 0);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSW listener_class = {0}, plain_class = {0};
    MINIMIZEDMETRICS metrics = {0}, read_back = {0};
    HANDLE thread;
    HWND app, tool, owned, late;
    RECT rect = {0, 0, 0, 0};
    LONG from;
    BOOL got, set, again;
    int arrange_before;

    if (!take_a_desktop()) {
        DbgPrint("[shellhook] no desktop\n");
        ExitProcess(1);
    }
    instance = GetModuleHandleW(0);
    shell_message = RegisterWindowMessageW(L"SHELLHOOK");
    listener_class.proc = listener_proc;
    listener_class.instance = instance;
    listener_class.name = L"ShellHookListener";
    plain_class.proc = plain_proc;
    plain_class.instance = instance;
    plain_class.name = L"ShellHookPlain";
    if (!shell_message || !RegisterClassW(&listener_class) || !RegisterClassW(&plain_class)) {
        DbgPrint("[shellhook] setup failed (error %lu)\n", GetLastError());
        ExitProcess(1);
    }
    DbgPrint("[shellhook] ready\n");

    /* 1. The listener, in another thread. */
    listener_ready = CreateEventW(0, 1, 0, 0);
    thread = CreateThread(0, 0, listener_thread, 0, 0, 0);
    if (!listener_ready || !thread)
        ExitProcess(1);
    WaitForSingleObject(listener_ready, INFINITE);
    DbgPrint("[shellhook] step 1: RegisterShellHookWindow %d, SetTaskmanWindow %d, GetTaskmanWindow the listener %d\n",
             registered, taskman_set, listener && GetTaskmanWindow() == listener);

    /* 2. An application window shown. */
    from = event_count;
    app = create(0, WS_OVERLAPPEDWINDOW, 0, L"Application");
    ShowWindow(app, SW_SHOW);
    settle();
    DbgPrint("[shellhook] step 2: shown: created %d, activated %d\n", seen(from, HSHELL_WINDOWCREATED, app) > 0,
             seen(from, HSHELL_WINDOWACTIVATED, app) > 0);

    /* 3. Its title. */
    from = event_count;
    SetWindowTextW(app, L"Renamed");
    settle();
    DbgPrint("[shellhook] step 3: SetWindowText: redraw %d\n", seen(from, HSHELL_REDRAW, app) > 0);

    /* 4. Hidden. */
    from = event_count;
    ShowWindow(app, SW_HIDE);
    settle();
    DbgPrint("[shellhook] step 4: hidden: destroyed %d\n", seen(from, HSHELL_WINDOWDESTROYED, app) > 0);

    /* 5. Not in a taskbar: a tool window, a window with an owner. */
    from = event_count;
    ShowWindow(app, SW_SHOW);
    tool = create(WS_EX_TOOLWINDOW, WS_OVERLAPPEDWINDOW, 0, L"Tool");
    owned = create(0, WS_OVERLAPPEDWINDOW, app, L"Owned");
    ShowWindow(tool, SW_SHOW);
    ShowWindow(owned, SW_SHOW);
    settle();
    DbgPrint("[shellhook] step 5: a tool window %d, an owned window %d\n", seen(from, HSHELL_WINDOWCREATED, tool),
             seen(from, HSHELL_WINDOWCREATED, owned));
    DestroyWindow(owned);
    DestroyWindow(tool);

    /* 6. Destroyed. */
    from = event_count;
    DestroyWindow(app);
    settle();
    DbgPrint("[shellhook] step 6: DestroyWindow: destroyed %d\n", seen(from, HSHELL_WINDOWDESTROYED, app) > 0);

    /* 7. Deregistered: nothing more. */
    again = DeregisterShellHookWindow(listener);
    from = event_count;
    late = create(0, WS_OVERLAPPEDWINDOW, 0, L"Late");
    ShowWindow(late, SW_SHOW);
    settle();
    DbgPrint("[shellhook] step 7: DeregisterShellHookWindow %d, then %ld events\n", again, event_count - from);

    /* 8. The minimized windows of a shell. */
    metrics.cbSize = sizeof metrics;
    got = SystemParametersInfoW(SPI_GETMINIMIZEDMETRICS, sizeof metrics, &metrics, 0);
    arrange_before = GetSystemMetrics(SM_ARRANGE);
    metrics.iArrange |= ARW_HIDE;
    set = SystemParametersInfoW(SPI_SETMINIMIZEDMETRICS, sizeof metrics, &metrics, 0);
    read_back.cbSize = sizeof read_back;
    SystemParametersInfoW(SPI_GETMINIMIZEDMETRICS, sizeof read_back, &read_back, 0);
    ShowWindow(late, SW_MINIMIZE);
    GetWindowRect(late, &rect);
    DbgPrint("[shellhook] step 8: GET %d, arrange %d (SM_ARRANGE %d); SET %d, read back %d (SM_ARRANGE %d); minimized at "
             "(%ld, %ld)\n",
             got, metrics.iArrange & ~ARW_HIDE, arrange_before, set, read_back.iArrange, GetSystemMetrics(SM_ARRANGE),
             rect.left, rect.top);
    metrics.iArrange &= ~ARW_HIDE;
    SystemParametersInfoW(SPI_SETMINIMIZEDMETRICS, sizeof metrics, &metrics, 0);
    DestroyWindow(late);

    PostMessageW(listener, WM_CLOSE, 0, 0);
    WaitForSingleObject(thread, INFINITE);
    DbgPrint("[shellhook] done\n");
    ExitProcess(0);
    return 0;
}
