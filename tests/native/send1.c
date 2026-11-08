/*
 * SendMessage between threads: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `send-messages` puts on the boot disk in the place of winlogon.exe (like
 * gui1.c). It takes a desktop like winlogon; its main thread opens window
 * W, then starts a worker thread, which opens its own window V and sends to
 * W, a window of the main thread:
 * - SendMessage: W's procedure runs in the main thread, its value comes back
 *   to the worker;
 * - a pointer in lParam: the same process, the procedure writes through it;
 * - a nested send: while W handles the message, the main thread sends to V,
 *   whose procedure runs in the worker, which waits for W meanwhile;
 * - SendMessageTimeout of 100 ms to a procedure that sleeps 400 ms: 0 and
 *   ERROR_TIMEOUT;
 * - SendNotifyMessage: TRUE at once, W handles it later;
 * then the worker posts WM_QUIT to the main thread, which never got a sent
 * message from GetMessage, and ends with EXIT_STATUS. Each result goes to the
 * debug port (DbgPrint), where the scenario looks for it.
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
typedef unsigned long DWORD_PTR;
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

#define WM_USER 0x0400
#define WM_QUIT 0x0012
#define SMTO_NORMAL 0x0000
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define INFINITE 0xFFFFFFFF
#define EXIT_STATUS 0x7002

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);
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
__declspec(dllimport) BOOL __stdcall PostThreadMessageW(DWORD thread, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall SendMessageTimeoutW(HWND window, UINT message, WPARAM w, LPARAM l, UINT flags,
                                                           UINT timeout, DWORD_PTR *result);
__declspec(dllimport) BOOL __stdcall SendNotifyMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static HDESK desktop;
static HWND window_w;
static HWND window_v;
static DWORD main_thread;
static DWORD worker_thread;
/* What GetMessage returned of the messages the worker sent. */
static int sent_out_of_get_message;
static int notified;

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

/* V, the worker's window. */
static LRESULT __stdcall procedure_v(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_USER + 4) {
        DbgPrint("[send] V got the nested message in the %s thread\n",
                 GetCurrentThreadId() == worker_thread ? "worker" : "wrong");
        return 4;
    }
    return DefWindowProcW(hwnd, message, w, l);
}

/* W, the main thread's window. */
static LRESULT __stdcall procedure_w(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    switch (message) {
    case WM_USER + 1:
        DbgPrint("[send] W got %x in the %s thread\n", message, GetCurrentThreadId() == main_thread ? "main" : "wrong");
        return (LRESULT)(w + 10 * l);
    case WM_USER + 2:
        *(LONG *)l = 1234;
        return 1;
    case WM_USER + 3:
        return 300 + SendMessageW(window_v, WM_USER + 4, 0, 0);
    case WM_USER + 5:
        Sleep(400);
        return 5;
    case WM_USER + 6:
        notified = 1;
        DbgPrint("[send] W got the notification in the %s thread\n",
                 GetCurrentThreadId() == main_thread ? "main" : "wrong");
        return 0;
    }
    return DefWindowProcW(hwnd, message, w, l);
}

static BOOL register_class(const WCHAR *name, WNDPROC procedure)
{
    WNDCLASSEXW class_info;

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = name;
    return RegisterClassExW(&class_info) != 0;
}

static DWORD __stdcall worker(void *parameter)
{
    LONG written = 0;
    DWORD_PTR result = 99;
    LRESULT value;
    DWORD error;
    BOOL ok;

    (void)parameter;
    worker_thread = GetCurrentThreadId();
    if (!SetThreadDesktop(desktop))
        DbgPrint("[send] the worker has no desktop\n");
    window_v = CreateWindowExW(0, L"MinoSendV", L"V", 0, 0, 0, 100, 100, 0, 0, GetModuleHandleW(0), 0);
    DbgPrint("[send] worker ready: V %s\n", window_v ? "created" : "missing");
    value = SendMessageW(window_w, WM_USER + 1, 5, 7);
    DbgPrint("[send] SendMessage to the main thread: %ld\n", value);
    value = SendMessageW(window_w, WM_USER + 2, 0, (LPARAM)&written);
    DbgPrint("[send] through a pointer: %ld, written %ld\n", value, written);
    value = SendMessageW(window_w, WM_USER + 3, 0, 0);
    DbgPrint("[send] nested: %ld\n", value);
    SetLastError(0);
    ok = SendMessageTimeoutW(window_w, WM_USER + 5, 0, 0, SMTO_NORMAL, 100, &result);
    error = GetLastError();
    DbgPrint("[send] SendMessageTimeout of 100 ms: %d, error %lu\n", ok, error);
    ok = SendMessageTimeoutW(window_w, WM_USER + 1, 1, 2, SMTO_NORMAL, 5000, &result);
    DbgPrint("[send] SendMessageTimeout of 5 s: %d, result %lu\n", ok, result);
    DbgPrint("[send] SendNotifyMessage: %d\n", SendNotifyMessageW(window_w, WM_USER + 6, 0, 0));
    Sleep(100);
    PostThreadMessageW(main_thread, WM_QUIT, 0, 0);
    return 0;
}

DWORD __stdcall GuiStartup(void)
{
    HANDLE thread;
    DWORD id;
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    if (!register_class(L"MinoSendW", procedure_w) || !register_class(L"MinoSendV", procedure_v))
        ExitProcess(2);
    main_thread = GetCurrentThreadId();
    window_w = CreateWindowExW(0, L"MinoSendW", L"W", 0, 0, 0, 100, 100, 0, 0, GetModuleHandleW(0), 0);
    if (!window_w)
        ExitProcess(3);
    DbgPrint("[send] ready\n");
    thread = CreateThread(0, 0, worker, 0, 0, &id);
    if (!thread)
        ExitProcess(4);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        if (message.message >= WM_USER + 1 && message.message <= WM_USER + 6)
            sent_out_of_get_message++;
        DispatchMessageW(&message);
    }
    WaitForSingleObject(thread, INFINITE);
    DbgPrint("[send] sent messages out of GetMessage: %d; notified %d\n", sent_out_of_get_message, notified);
    DbgPrint("[send] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
