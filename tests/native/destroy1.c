/*
 * DestroyWindow, DestroyMenu and what win32k gives back at the end of a GUI
 * thread and of a GUI process: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32, user32 and gdi32, which the
 * scenario `destroy` puts on the boot disk in the place of winlogon.exe. It
 * takes WinSta0\Default like winlogon, then checks, one after the other:
 * - DestroyWindow of a visible window A, with a child B (itself the parent of
 *   C) and a popup D that A owns: D goes first, then WM_DESTROY comes to A,
 *   B, C (parents first), WM_NCDESTROY to C, B, A (children first); IsWindow
 *   is TRUE during these messages, FALSE after;
 * - a child F that goes alone: its parent E gets WM_PARENTNOTIFY (WM_DESTROY,
 *   F's id, F) first, and has no child left;
 * - DestroyWindow of a destroyed window (ERROR_INVALID_WINDOW_HANDLE), of the
 *   desktop window and of another thread's window (ERROR_ACCESS_DENIED);
 * - WM_CLOSE, and WM_SYSCOMMAND SC_CLOSE, to DefWindowProc: DestroyWindow;
 * - a destroyed window takes its timer and its posted message with it;
 * - a window takes its menu bar with it; DestroyMenu destroys a menu once
 *   (then ERROR_INVALID_MENU_HANDLE, which also says a menu is gone: user32
 *   cannot read win32k's menus yet, IsMenu is always FALSE);
 * - a thread that ends with a window (and its child, a timer and a DC taken
 *   by GetDC): its windows are gone, their procedure got no message, and the
 *   process's count of USER objects (GetGuiResources) is back where it was;
 * - a child process (this program, with `child` and the parent's thread id
 *   on its command line) that ends without giving back anything: two
 *   windows, three menus, a timer, a cache DC, a brush, a memory DC. Once it
 *   has ended, GetGuiResources counts no USER or GDI object of it, and its
 *   window and its menu are gone.
 * The kernel journals what it gives back at the end of a thread or a
 * process, and what a process would leave (forbidden here).
 * Each result goes to the debug port (DbgPrint), where the scenario looks for
 * it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short WORD;
typedef unsigned char BYTE;
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
typedef void *HDC;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef unsigned int UINT_PTR;
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

typedef struct {
    DWORD cb;
    WCHAR *lpReserved;
    WCHAR *lpDesktop;
    WCHAR *lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    BYTE *lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW;

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WM_DESTROY 0x0002
#define WM_CLOSE 0x0010
#define WM_NCDESTROY 0x0082
#define WM_SYSCOMMAND 0x0112
#define WM_TIMER 0x0113
#define WM_PARENTNOTIFY 0x0210
#define WM_USER 0x0400
#define WM_APP 0x8000
#define WM_QUIT 0x0012
#define SC_CLOSE 0xF060
#define PM_REMOVE 0x0001
#define GW_CHILD 5
#define MF_STRING 0x0000
#define MF_POPUP 0x0010
#define GR_GDIOBJECTS 0
#define GR_USEROBJECTS 1
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define INFINITE 0xFFFFFFFF
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_WINDOW_HANDLE 1400
#define ERROR_INVALID_MENU_HANDLE 1401
#define EXIT_STATUS 0x7103
#define CHILD_EXIT_STATUS 0x7104

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual_reset, BOOL initial_state,
                                                    const WCHAR *name);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line,
                                                    void *process_attributes, void *thread_attributes,
                                                    BOOL inherit_handles, DWORD flags, void *environment,
                                                    const WCHAR *directory, STARTUPINFOW *startup_info,
                                                    PROCESS_INFORMATION *information);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) WCHAR *__stdcall GetCommandLineW(void);
__declspec(dllimport) HANDLE __stdcall GetCurrentProcess(void);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) BOOL __stdcall AppendMenuW(HMENU menu, UINT flags, UINT_PTR id, const WCHAR *item);
__declspec(dllimport) HMENU __stdcall CreateMenu(void);
__declspec(dllimport) HMENU __stdcall CreatePopupMenu(void);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall DestroyMenu(HMENU menu);
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) HWND __stdcall GetDesktopWindow(void);
__declspec(dllimport) DWORD __stdcall GetGuiResources(HANDLE process, DWORD flags);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HWND __stdcall GetWindow(HWND window, UINT command);

__declspec(dllimport) BOOL __stdcall IsWindow(HWND window);
__declspec(dllimport) BOOL __stdcall KillTimer(HWND window, UINT_PTR id);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall PostThreadMessageW(DWORD thread, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) UINT_PTR __stdcall SetTimer(HWND window, UINT_PTR id, UINT elapse, void *procedure);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

__declspec(dllimport) HDC __stdcall CreateCompatibleDC(HDC dc);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(DWORD color);

static const WCHAR CLASS_NAME[] = L"MinoDestroy";
static HDESK desktop;

/* The windows the procedure knows by a letter, and what it saw. */
static HWND windows[24];
static char letters[24];
static int known;
static char log_text[128];
static int log_length;
/* WM_PARENTNOTIFY of a destroyed child: its id and its handle. */
static WPARAM notified_w;
static LPARAM notified_l;

/* The worker thread's windows, and its events. */
static HWND window_x;
static HWND window_y;
static HANDLE worker_ready;
static HANDLE worker_go;

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

static void remember(HWND window, char letter)
{
    if (known < (int)(sizeof windows / sizeof windows[0])) {
        windows[known] = window;
        letters[known] = letter;
        known++;
    }
}

static char letter_of(HWND window)
{
    int i;

    for (i = 0; i < known; i++)
        if (windows[i] == window)
            return letters[i];
    return '?';
}

static void note(char a, char b)
{
    if (log_length + 2 < (int)sizeof log_text) {
        log_text[log_length++] = a;
        log_text[log_length++] = b;
        log_text[log_length] = 0;
    }
}

static void clear_log(void)
{
    log_length = 0;
    log_text[0] = 0;
}

/* WM_DESTROY: the letter and '-', WM_NCDESTROY: the letter and '.', while
 * IsWindow is TRUE (a window is one until its last message has been
 * handled), '!' otherwise; WM_PARENTNOTIFY of WM_DESTROY: the parent's letter
 * and '^'. */
static LRESULT __stdcall procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    switch (message) {
    case WM_DESTROY:
        note(letter_of(hwnd), IsWindow(hwnd) ? '-' : '!');
        return 0;
    case WM_NCDESTROY:
        note(letter_of(hwnd), IsWindow(hwnd) ? '.' : '!');
        break;
    case WM_PARENTNOTIFY:
        if ((w & 0xFFFF) == WM_DESTROY) {
            notified_w = w;
            notified_l = l;
            note(letter_of(hwnd), '^');
        }
        return 0;
    }
    return DefWindowProcW(hwnd, message, w, l);
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

static BOOL register_class(void)
{
    WNDCLASSEXW class_info;

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&class_info) != 0;
}

static HWND create(char letter, DWORD style, int x, int y, int width, int height, HWND parent, HMENU menu)
{
    HWND window = CreateWindowExW(0, CLASS_NAME, L"Destroy", style, x, y, width, height, parent, menu,
                                  GetModuleHandleW(0), 0);
    if (window)
        remember(window, letter);
    else
        DbgPrint("[destroy] window %c not created, error %lu\n", letter, GetLastError());
    return window;
}

/* The messages of the current thread: dispatched; those of `window`
 * counted. */
static int pump(HWND window)
{
    MSG message;
    int counted = 0;

    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) {
        if (window && message.hwnd == window)
            counted++;
        else
            DispatchMessageW(&message);
    }
    return counted;
}

static DWORD user_objects(HANDLE process)
{
    return GetGuiResources(process, GR_USEROBJECTS);
}

/* The worker: a window X with a child Y, a timer and a DC it never gives
 * back; it ends when told, with all of them. */
static DWORD __stdcall worker(void *parameter)
{
    (void)parameter;
    SetThreadDesktop(desktop);
    window_x = create('X', WS_OVERLAPPEDWINDOW | WS_VISIBLE, 420, 80, 220, 160, 0, 0);
    window_y = create('Y', WS_CHILD | WS_VISIBLE, 5, 5, 60, 40, window_x, (HMENU)2);
    SetTimer(window_x, 3, 10, 0);
    GetDC(window_x);
    SetEvent(worker_ready);
    WaitForSingleObject(worker_go, INFINITE);
    return 0;
}

/* The decimal number after `child ` in the command line, if it is there. */
static BOOL child_of(const WCHAR *line, DWORD *parent)
{
    static const WCHAR word[] = L"child ";
    const WCHAR *at;
    int i;

    for (at = line; *at; at++) {
        for (i = 0; word[i] && at[i] == word[i]; i++)
            ;
        if (!word[i]) {
            DWORD value = 0;
            at += i;
            while (*at >= '0' && *at <= '9')
                value = value * 10 + (DWORD)(*at++ - '0');
            *parent = value;
            return 1;
        }
    }
    return 0;
}

/* The child process: everything it makes stays when it ends. */
static void child_main(DWORD parent)
{
    HMENU bar, popup, loose;
    HWND window;
    MSG message;

    if (!register_class())
        ExitProcess(21);
    bar = CreateMenu();
    popup = CreatePopupMenu();
    loose = CreatePopupMenu();
    AppendMenuW(popup, MF_STRING, 100, L"Item");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)popup, L"File");
    window = create('P', WS_OVERLAPPEDWINDOW | WS_VISIBLE, 60, 300, 240, 160, 0, bar);
    create('Q', WS_CHILD | WS_VISIBLE, 10, 10, 60, 40, window, (HMENU)3);
    SetTimer(window, 4, 50, 0);
    GetDC(window);
    CreateSolidBrush(0x00336699);
    CreateCompatibleDC(0);
    DbgPrint("[destroy] child: window %d, menus %d %d %d\n", window != 0, bar != 0, popup != 0, loose != 0);
    PostThreadMessageW(parent, WM_APP, (WPARAM)window, (LPARAM)loose);
    while (GetMessageW(&message, 0, 0, 0) > 0)
        DispatchMessageW(&message);
    ExitProcess(CHILD_EXIT_STATUS);
}

static void check_tree(void)
{
    HWND a, b, c, d;
    BOOL ok;

    a = create('A', WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, 300, 200, 0, 0);
    b = create('B', WS_CHILD | WS_VISIBLE, 10, 10, 120, 80, a, (HMENU)1);
    c = create('C', WS_CHILD | WS_VISIBLE, 5, 5, 40, 30, b, (HMENU)2);
    d = create('D', WS_POPUP | WS_VISIBLE, 200, 160, 120, 90, a, 0);
    pump(0);
    clear_log();
    ok = DestroyWindow(a);
    DbgPrint("[destroy] DestroyWindow(A): %d, messages %s\n", ok, log_text);
    DbgPrint("[destroy] A, B, C, D gone: %d %d %d %d\n", !IsWindow(a), !IsWindow(b), !IsWindow(c), !IsWindow(d));
    SetLastError(0);
    ok = DestroyWindow(a);
    DbgPrint("[destroy] again: %d, error %lu\n", ok, GetLastError());
    SetLastError(0);
    ok = DestroyWindow(GetDesktopWindow());
    DbgPrint("[destroy] the desktop window: %d, error %lu\n", ok, GetLastError());
}

static void check_child(void)
{
    HWND e, f;
    BOOL ok;

    e = create('E', WS_OVERLAPPEDWINDOW, 40, 40, 300, 200, 0, 0);
    f = create('F', WS_CHILD | WS_VISIBLE, 10, 10, 50, 50, e, (HMENU)7);
    clear_log();
    ok = DestroyWindow(f);
    DbgPrint("[destroy] DestroyWindow(F): %d, messages %s, id %u, handle %d\n", ok, log_text,
             (unsigned)(notified_w >> 16), notified_l == (LPARAM)f);
    DbgPrint("[destroy] E lives, without a child: %d %d\n", IsWindow(e), GetWindow(e, GW_CHILD) == 0);
    DestroyWindow(e);
}

static void check_close(void)
{
    HWND g, h;

    g = create('G', WS_OVERLAPPEDWINDOW, 40, 40, 300, 200, 0, 0);
    clear_log();
    SendMessageW(g, WM_CLOSE, 0, 0);
    DbgPrint("[destroy] WM_CLOSE: messages %s, gone %d\n", log_text, !IsWindow(g));
    h = create('H', WS_OVERLAPPEDWINDOW, 40, 40, 300, 200, 0, 0);
    clear_log();
    SendMessageW(h, WM_SYSCOMMAND, SC_CLOSE, 0);
    DbgPrint("[destroy] SC_CLOSE: messages %s, gone %d\n", log_text, !IsWindow(h));
}

static void check_queue(void)
{
    HWND k;
    BOOL killed;
    int left;

    k = create('K', WS_OVERLAPPEDWINDOW, 40, 40, 300, 200, 0, 0);
    SetTimer(k, 1, 10, 0);
    PostMessageW(k, WM_USER + 1, 0, 0);
    DestroyWindow(k);
    Sleep(60);
    left = pump(k);
    killed = KillTimer(k, 1);
    DbgPrint("[destroy] messages for K after it: %d, its timer killed again %d\n", left, killed);
}

/* user32 cannot read win32k's menus yet (IsMenu is FALSE, AppendMenu does
 * not attach a popup): a second DestroyMenu, which win32k answers, says
 * whether a menu is gone. */
static void check_menus(void)
{
    HMENU bar, loose;
    HWND l;
    BOOL first, second;
    DWORD error;

    bar = CreateMenu();
    AppendMenuW(bar, MF_STRING, 100, L"File");
    l = create('L', WS_OVERLAPPEDWINDOW, 40, 40, 300, 200, 0, bar);
    DestroyWindow(l);
    SetLastError(0);
    first = DestroyMenu(bar);
    error = GetLastError();
    DbgPrint("[destroy] the bar gone with L: %d, error %lu\n", !first, error);
    loose = CreatePopupMenu();
    first = DestroyMenu(loose);
    SetLastError(0);
    second = DestroyMenu(loose);
    error = GetLastError();
    DbgPrint("[destroy] DestroyMenu: %d, again %d, error %lu\n", first, second, error);
}

static void check_thread(void)
{
    HANDLE thread;
    DWORD id, before;
    BOOL ok;
    DWORD error;

    before = user_objects(GetCurrentProcess());
    worker_ready = CreateEventW(0, 1, 0, 0);
    worker_go = CreateEventW(0, 1, 0, 0);
    thread = CreateThread(0, 0, worker, 0, 0, &id);
    if (!thread || !worker_ready || !worker_go) {
        DbgPrint("[destroy] no worker thread\n");
        return;
    }
    WaitForSingleObject(worker_ready, INFINITE);
    DbgPrint("[destroy] the worker's windows: %d %d, USER objects %lu more\n", IsWindow(window_x), IsWindow(window_y),
             user_objects(GetCurrentProcess()) - before);
    SetLastError(0);
    ok = DestroyWindow(window_x);
    error = GetLastError();
    DbgPrint("[destroy] another thread's window: %d, error %lu\n", ok, error);
    clear_log();
    SetEvent(worker_go);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    DbgPrint("[destroy] the worker ended: X, Y gone %d %d, messages '%s', USER objects back %d\n", !IsWindow(window_x),
             !IsWindow(window_y), log_text, user_objects(GetCurrentProcess()) == before);
}

static void check_process(void)
{
    static WCHAR command[64] = L"C:\\DESTROY1.EXE child ";
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    MSG message;
    HWND window = 0;
    HMENU menu = 0;
    DWORD tid = GetCurrentThreadId(), code = 0, user, gdi, error;
    BOOL menu_left;
    WCHAR digits[12];
    int count = 0, length = 0, i;

    do
        digits[count++] = (WCHAR)('0' + tid % 10);
    while ((tid /= 10) != 0);
    while (command[length])
        length++;
    for (i = count - 1; i >= 0; i--)
        command[length++] = digits[i];
    command[length] = 0;

    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\DESTROY1.EXE", command, 0, 0, 0, 0, 0, 0, &startup, &process)) {
        DbgPrint("[destroy] CreateProcessW: error %lu\n", GetLastError());
        return;
    }
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        if (message.message == WM_APP) {
            window = (HWND)message.wParam;
            menu = (HMENU)message.lParam;
            break;
        }
        DispatchMessageW(&message);
    }
    user = GetGuiResources(process.hProcess, GR_USEROBJECTS);
    gdi = GetGuiResources(process.hProcess, GR_GDIOBJECTS);
    DbgPrint("[destroy] the child holds at least 5 USER and 3 GDI objects: %d %d\n", user >= 5, gdi >= 3);
    PostThreadMessageW(process.dwThreadId, WM_QUIT, 0, 0);
    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &code);
    user = GetGuiResources(process.hProcess, GR_USEROBJECTS);
    gdi = GetGuiResources(process.hProcess, GR_GDIOBJECTS);
    SetLastError(0);
    menu_left = DestroyMenu(menu);
    error = GetLastError();
    DbgPrint("[destroy] the child ended (%lx): USER %lu, GDI %lu, its window gone %d, its menu gone %d (%lu)\n", code,
             user, gdi, !IsWindow(window), !menu_left, error);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

DWORD __stdcall GuiStartup(void)
{
    DWORD parent, start;

    if (child_of(GetCommandLineW(), &parent)) {
        child_main(parent);
        return 0;
    }
    if (!take_a_desktop())
        ExitProcess(1);
    if (!register_class())
        ExitProcess(2);
    start = user_objects(GetCurrentProcess());
    DbgPrint("[destroy] ready\n");
    check_tree();
    check_child();
    check_close();
    check_queue();
    check_menus();
    check_thread();
    pump(0);
    DbgPrint("[destroy] USER objects back to the start: %d\n", user_objects(GetCurrentProcess()) == start);
    check_process();
    DbgPrint("[destroy] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
