/*
 * WM_ACTIVATEAPP: a Win32 program (subsystem WINDOWS), compiled with MinGW
 * and linked to ReactOS's kernel32 and user32, which the scenario
 * `activate-app` puts on the boot disk in the place of winlogon.exe (like
 * send1.c). It takes a desktop like winlogon; its main thread A opens a
 * window A1, a top-level window A2 that it never shows and a child of A1,
 * then:
 * 1. shows A1: A takes the foreground;
 * 2. starts a thread B, which opens and shows B1: B takes it;
 * 3. brings A1 back with SetWindowPos (no SWP_NOACTIVATE): A takes it again.
 * Each time the foreground changes thread, every top-level window of the
 * two threads, shown or not, gets WM_ACTIVATEAPP: TRUE and the TID of the
 * thread that loses the foreground in the thread that gains it, FALSE and
 * the TID of the gaining thread in the other. The child gets none. Each
 * WM_ACTIVATEAPP goes to the debug port (DbgPrint), where the scenario looks
 * for it, with the step, the window, the thread named by lParam and the
 * thread that ran the procedure.
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
typedef DWORD(__stdcall *THREAD_START)(void *);

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

#define WM_QUIT 0x0012
#define WM_ACTIVATEAPP 0x001C
#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define SW_SHOWNORMAL 1
#define SWP_NOSIZE 0x0001
#define SWP_NOMOVE 0x0002
#define HWND_TOP ((HWND)0)
#define PM_REMOVE 0x0001
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define INFINITE 0xFFFFFFFF
#define EXIT_STATUS 0x7003

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) BOOL __stdcall PostThreadMessageW(DWORD thread, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SetWindowPos(HWND window, HWND insert_after, int x, int y, int cx, int cy,
                                                  UINT flags);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static HDESK desktop;
static HWND window_a1;
static HWND window_a2;
static HWND window_child;
static HWND window_b1;
static DWORD thread_a;
static volatile DWORD thread_b;
/* The step under way, and the WM_ACTIVATEAPP received by both threads. */
static volatile int step;
static volatile LONG received;

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

static const char *window_name(HWND hwnd)
{
    if (hwnd == window_a1)
        return "A1";
    if (hwnd == window_a2)
        return "A2";
    if (hwnd == window_b1)
        return "B1";
    if (hwnd == window_child)
        return "the child";
    return "an unknown window";
}

static const char *thread_name(DWORD tid)
{
    if (tid == 0)
        return "none";
    if (tid == thread_a)
        return "A";
    if (tid == thread_b)
        return "B";
    return "another";
}

static LRESULT __stdcall procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_ACTIVATEAPP) {
        DbgPrint("[activate] step %d: %s WM_ACTIVATEAPP %u, other thread %s, in thread %s\n", step,
                 window_name(hwnd), w, thread_name((DWORD)l), thread_name(GetCurrentThreadId()));
        __sync_fetch_and_add(&received, 1);
        return 0;
    }
    return DefWindowProcW(hwnd, message, w, l);
}

/* Handles A's messages until `count` WM_ACTIVATEAPP came, for 3 s at most. */
static BOOL pump_until(LONG count)
{
    MSG message;
    int i;

    for (i = 0; i < 300; i++) {
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
            DispatchMessageW(&message);
        if (received >= count)
            return 1;
        Sleep(10);
    }
    DbgPrint("[activate] step %d: %ld of %ld WM_ACTIVATEAPP came\n", step, received, count);
    return 0;
}

static DWORD __stdcall thread_b_main(void *parameter)
{
    MSG message;

    (void)parameter;
    thread_b = GetCurrentThreadId();
    if (!SetThreadDesktop(desktop))
        DbgPrint("[activate] B has no desktop\n");
    window_b1 = CreateWindowExW(0, L"MinoActivate", L"B1", WS_OVERLAPPEDWINDOW, 400, 120, 240, 160, 0, 0,
                                GetModuleHandleW(0), 0);
    if (!window_b1)
        DbgPrint("[activate] B1 missing\n");
    ShowWindow(window_b1, SW_SHOWNORMAL);
    while (GetMessageW(&message, 0, 0, 0) > 0)
        DispatchMessageW(&message);
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HANDLE thread;
    DWORD id;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoActivate";
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    thread_a = GetCurrentThreadId();
    window_a1 = CreateWindowExW(0, L"MinoActivate", L"A1", WS_OVERLAPPEDWINDOW, 100, 100, 240, 160, 0, 0, instance, 0);
    window_a2 = CreateWindowExW(0, L"MinoActivate", L"A2", WS_OVERLAPPEDWINDOW, 0, 0, 120, 80, 0, 0, instance, 0);
    window_child =
        CreateWindowExW(0, L"MinoActivate", L"child", WS_CHILD | WS_VISIBLE, 10, 10, 60, 40, window_a1, 0, instance, 0);
    if (!window_a1 || !window_a2 || !window_child)
        ExitProcess(3);
    DbgPrint("[activate] ready\n");

    step = 1;
    ShowWindow(window_a1, SW_SHOWNORMAL);
    if (!pump_until(2))
        ExitProcess(4);

    step = 2;
    thread = CreateThread(0, 0, thread_b_main, 0, 0, &id);
    if (!thread)
        ExitProcess(5);
    if (!pump_until(5))
        ExitProcess(6);

    step = 3;
    SetWindowPos(window_a1, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    if (!pump_until(8))
        ExitProcess(7);

    /* Time for a WM_ACTIVATEAPP too many to show up. */
    Sleep(200);
    pump_until(8);
    PostThreadMessageW(thread_b, WM_QUIT, 0, 0);
    WaitForSingleObject(thread, INFINITE);
    DbgPrint("[activate] done: %ld WM_ACTIVATEAPP\n", received);
    ExitProcess(EXIT_STATUS);
    return 0;
}
