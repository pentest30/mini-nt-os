/*
 * The hooks and the queries of the shell's menus: a Win32 program (subsystem
 * WINDOWS), compiled with MinGW and linked to ReactOS's kernel32 and user32,
 * which the scenario `hooks` puts on the boot disk in the place of
 * winlogon.exe (like `caret`, see caret1.c). On WinSta0\Default:
 * - SetWindowsHookEx refuses an unknown type, a hook without a procedure, a
 *   global-only type on a thread, a global hook without a module;
 * - WH_GETMESSAGE: the hook sees the message GetMessage and PeekMessage are
 *   about to give (code HC_ACTION, wParam 1 if it leaves the queue) and may
 *   change it; two hooks: the last set is called first, and CallNextHookEx
 *   calls the other and gives what it returned; unhooked, a hook is no longer
 *   called, and a second UnhookWindowsHookEx fails (ERROR_INVALID_HOOK_HANDLE);
 *   outside a hook, CallNextHookEx gives 0;
 * - WH_MSGFILTER: CallMsgFilter calls it with its code and gives what it
 *   returned; unhooked, CallMsgFilter gives 0 (user32 tests fsHooks); in
 *   TrackPopupMenu, the hook sees the menu's messages with MSGF_MENU, and a
 *   message it handles is not the menu's (it ends the menu here);
 * - a hook on another thread of the process runs in that thread; the hook
 *   goes with that thread's end;
 * - GetAncestor (GA_PARENT, GA_ROOT, GA_ROOTOWNER), WindowFromPoint (a child
 *   transparent to the mouse, disabled or hidden is not the answer; outside
 *   every window, the desktop) and SetForegroundWindow/GetForegroundWindow
 *   (a child brings its top-level window to the foreground), which
 *   ReactOS's Start menu (CMenuFocusManager) calls from its hook.
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
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HHOOK;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT(__stdcall *HOOKPROC)(int, WPARAM, LPARAM);
typedef DWORD(__stdcall *THREADPROC)(void *);

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

#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WS_DISABLED 0x08000000
#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define WM_APP 0x8000
#define WM_NCHITTEST 0x0084
#define HTTRANSPARENT (-1)
#define PM_NOREMOVE 0
#define PM_REMOVE 1
#define WH_MSGFILTER (-1)
#define WH_GETMESSAGE 3
#define WH_MOUSE_LL 14
#define MSGF_MENU 2
#define MF_STRING 0
#define TPM_RETURNCMD 0x0100
#define GA_PARENT 1
#define GA_ROOT 2
#define GA_ROOTOWNER 3
#define HWND_MESSAGE ((HWND)-3)
#define INFINITE 0xFFFFFFFF
#define EXIT_STATUS 0x6014

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREADPROC start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) BOOL __stdcall AppendMenuW(HMENU menu, UINT flags, UINT id, const WCHAR *text);
__declspec(dllimport) BOOL __stdcall CallMsgFilterW(MSG *message, int code);
__declspec(dllimport) LRESULT __stdcall CallNextHookEx(HHOOK hook, int code, WPARAM w, LPARAM l);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HMENU __stdcall CreatePopupMenu(void);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall DestroyMenu(HMENU menu);
__declspec(dllimport) BOOL __stdcall EndMenu(void);
__declspec(dllimport) HWND __stdcall GetAncestor(HWND window, UINT flags);
__declspec(dllimport) HWND __stdcall GetDesktopWindow(void);
__declspec(dllimport) HWND __stdcall GetForegroundWindow(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall PostThreadMessageW(DWORD thread, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetForegroundWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) HHOOK __stdcall SetWindowsHookExW(int id, HOOKPROC procedure, HINSTANCE module, DWORD thread);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) int __stdcall TrackPopupMenu(HMENU menu, UINT flags, int x, int y, int reserved, HWND owner,
                                                   const RECT *rect);
__declspec(dllimport) BOOL __stdcall UnhookWindowsHookEx(HHOOK hook);
__declspec(dllimport) HWND __stdcall WindowFromPoint(POINT point);

static const WCHAR CLASS_NAME[] = L"MinoHooks";
static const WCHAR TRANSPARENT_CLASS[] = L"MinoHooksTransparent";
static HDESK desktop;

/* What the hooks saw. */
static char order[8];
static int order_length;
static int seen_code = -1;
static WPARAM seen_removed = 99;
static WPARAM seen_w;
static LPARAM seen_l;
static LRESULT b_got;
static HHOOK hook_b_handle;
static int filter_code;
static UINT filter_message;
static int menu_filter_saw;
static DWORD other_ran_in;
static WPARAM other_saw;
static DWORD other_tid;
static volatile int other_ready;

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

static void note(char letter)
{
    if (order_length < (int)sizeof order - 1)
        order[order_length++] = letter;
    order[order_length] = 0;
}

static void forget(void)
{
    order_length = 0;
    order[0] = 0;
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
    DbgPrint("[hooks] on WinSta0\\Default\n");
    return 1;
}

/* WH_GETMESSAGE, set first: notes 'a', changes WM_APP's wParam, returns
 * 0x5A. */
static LRESULT __stdcall hook_a(int code, WPARAM w, LPARAM l)
{
    MSG *message = (MSG *)l;
    if (message->message != WM_APP)
        return CallNextHookEx(0, code, w, l);
    note('a');
    seen_code = code;
    seen_removed = w;
    seen_w = message->wParam;
    seen_l = message->lParam;
    message->wParam = 77;
    return 0x5A;
}

/* WH_GETMESSAGE, set second: notes 'b', then calls the next hook. */
static LRESULT __stdcall hook_b(int code, WPARAM w, LPARAM l)
{
    MSG *message = (MSG *)l;
    if (message->message == WM_APP)
        note('b');
    b_got = CallNextHookEx(hook_b_handle, code, w, l);
    return b_got;
}

/* WH_MSGFILTER: handles WM_APP. */
static LRESULT __stdcall filter(int code, WPARAM w, LPARAM l)
{
    MSG *message = (MSG *)l;
    filter_code = code;
    filter_message = message->message;
    return message->message == WM_APP ? 1 : CallNextHookEx(0, code, w, l);
}

/* WH_MSGFILTER during TrackPopupMenu: WM_APP + 1 with MSGF_MENU ends the
 * menu, and is handled. */
static LRESULT __stdcall menu_filter(int code, WPARAM w, LPARAM l)
{
    MSG *message = (MSG *)l;
    if (code == MSGF_MENU && message->message == WM_APP + 1) {
        menu_filter_saw = 1;
        EndMenu();
        return 1;
    }
    return CallNextHookEx(0, code, w, l);
}

/* WH_GETMESSAGE set on the other thread: where it runs, what it saw. */
static LRESULT __stdcall other_hook(int code, WPARAM w, LPARAM l)
{
    MSG *message = (MSG *)l;
    if (message->message == WM_APP) {
        other_ran_in = GetCurrentThreadId();
        other_saw = message->wParam;
    }
    return CallNextHookEx(0, code, w, l);
}

/* The other thread: on the desktop, then one message, then its end. */
static DWORD __stdcall other_thread(void *parameter)
{
    MSG message;
    (void)parameter;
    if (!SetThreadDesktop(desktop))
        return 1;
    other_ready = 1;
    GetMessageW(&message, 0, 0, 0);
    return 0;
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    return DefWindowProcW(window, message, w, l);
}

/* A child transparent to the mouse. */
static LRESULT __stdcall transparent_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_NCHITTEST)
        return HTTRANSPARENT;
    return DefWindowProcW(window, message, w, l);
}

/* Posts WM_APP (w, l) to this thread, then takes it with GetMessage; gives
 * its wParam. */
static WPARAM get_app_message(WPARAM w, LPARAM l)
{
    MSG message;
    PostThreadMessageW(GetCurrentThreadId(), WM_APP, w, l);
    if (!GetMessageW(&message, 0, WM_APP, WM_APP))
        return 0;
    return message.wParam;
}

static void refusals(HINSTANCE instance)
{
    DWORD unknown, no_procedure, global_only, no_module;
    SetLastError(0);
    SetWindowsHookExW(99, hook_a, 0, GetCurrentThreadId());
    unknown = GetLastError();
    SetWindowsHookExW(WH_GETMESSAGE, 0, 0, GetCurrentThreadId());
    no_procedure = GetLastError();
    SetWindowsHookExW(WH_MOUSE_LL, hook_a, instance, GetCurrentThreadId());
    global_only = GetLastError();
    SetWindowsHookExW(WH_GETMESSAGE, hook_a, 0, 0);
    no_module = GetLastError();
    DbgPrint("[hooks] refusals: type 99 %lu, no procedure %lu, global-only %lu, global without a module %lu\n",
             unknown, no_procedure, global_only, no_module);
}

static void get_message_hooks(void)
{
    MSG message;
    HHOOK a = SetWindowsHookExW(WH_GETMESSAGE, hook_a, 0, GetCurrentThreadId());
    WPARAM given;
    WPARAM peeked, removed;
    BOOL second, again;
    DWORD error;
    LRESULT outside;

    DbgPrint("[hooks] WH_GETMESSAGE set: %d\n", a != 0);
    given = get_app_message(11, 22);
    DbgPrint("[hooks] GetMessage: the hook saw code %d, removed %u, wParam %u lParam %ld; GetMessage gives wParam %u\n",
             seen_code, seen_removed, seen_w, seen_l, given);

    PostThreadMessageW(GetCurrentThreadId(), WM_APP, 1, 0);
    PeekMessageW(&message, 0, WM_APP, WM_APP, PM_NOREMOVE);
    peeked = seen_removed;
    PeekMessageW(&message, 0, WM_APP, WM_APP, PM_REMOVE);
    removed = seen_removed;
    DbgPrint("[hooks] PeekMessage: removed %u, then %u\n", peeked, removed);

    hook_b_handle = SetWindowsHookExW(WH_GETMESSAGE, hook_b, 0, GetCurrentThreadId());
    forget();
    given = get_app_message(1, 0);
    DbgPrint("[hooks] two hooks: called %s, CallNextHookEx gave %lx, the message's wParam %u\n", order, b_got,
             given);

    second = UnhookWindowsHookEx(hook_b_handle);
    SetLastError(0);
    again = UnhookWindowsHookEx(hook_b_handle);
    error = GetLastError();
    forget();
    get_app_message(1, 0);
    DbgPrint("[hooks] the second unhooked: %d, again: %d (%lu); then called %s\n", second, again, error, order);

    UnhookWindowsHookEx(a);
    forget();
    given = get_app_message(5, 0);
    outside = CallNextHookEx(0, 0, 0, 0);
    DbgPrint("[hooks] all unhooked: called '%s', wParam %u; CallNextHookEx outside a hook: %ld\n", order, given,
             outside);
}

static void message_filters(HWND window)
{
    MSG message;
    HHOOK hook = SetWindowsHookExW(WH_MSGFILTER, filter, 0, GetCurrentThreadId());
    HMENU menu;
    BOOL handled;
    int command;

    memset(&message, 0, sizeof message);
    message.message = WM_APP;
    handled = CallMsgFilterW(&message, 0x4242);
    DbgPrint("[hooks] WH_MSGFILTER: CallMsgFilter %d, the filter saw code %x and %x\n", handled, filter_code,
             filter_message);
    UnhookWindowsHookEx(hook);
    handled = CallMsgFilterW(&message, 0x4242);
    DbgPrint("[hooks] WH_MSGFILTER unhooked: CallMsgFilter %d\n", handled);

    hook = SetWindowsHookExW(WH_MSGFILTER, menu_filter, 0, GetCurrentThreadId());
    menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, 1, L"Item");
    PostMessageW(window, WM_APP + 1, 0, 0);
    command = TrackPopupMenu(menu, TPM_RETURNCMD, 300, 300, 0, window, 0);
    DbgPrint("[hooks] TrackPopupMenu: the filter saw WM_APP+1 with MSGF_MENU %d, the menu ended: %d\n",
             menu_filter_saw, command);
    UnhookWindowsHookEx(hook);
    DestroyMenu(menu);
}

static void another_thread(void)
{
    HANDLE thread = CreateThread(0, 0, other_thread, 0, 0, &other_tid);
    HHOOK hook;
    BOOL unhooked;
    DWORD error;

    while (thread && !other_ready)
        Sleep(10);
    hook = SetWindowsHookExW(WH_GETMESSAGE, other_hook, 0, other_tid);
    PostThreadMessageW(other_tid, WM_APP, 33, 0);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    DbgPrint("[hooks] another thread hooked: %d, the hook ran in it: %d, its message %u\n", hook != 0,
             other_ran_in == other_tid, other_saw);
    SetLastError(0);
    unhooked = UnhookWindowsHookEx(hook);
    error = GetLastError();
    DbgPrint("[hooks] its thread ended: UnhookWindowsHookEx %d (%lu)\n", unhooked, error);
}

/* The centre of `window` on the screen. */
static POINT centre(HWND window)
{
    RECT rect;
    POINT point;
    GetWindowRect(window, &rect);
    point.x = (rect.left + rect.right) / 2;
    point.y = (rect.top + rect.bottom) / 2;
    return point;
}

/* The windows' names for the log. */
static const char *name(HWND window, HWND w, HWND c, HWND p)
{
    if (!window)
        return "0";
    if (window == w)
        return "W";
    if (window == c)
        return "C";
    if (window == p)
        return "P";
    if (window == GetDesktopWindow())
        return "the desktop";
    return "another";
}

static void shell_queries(HWND w, HINSTANCE instance)
{
    HWND c = CreateWindowExW(0, CLASS_NAME, L"C", WS_CHILD | WS_VISIBLE, 10, 10, 50, 50, w, 0, instance, 0);
    HWND t = CreateWindowExW(0, TRANSPARENT_CLASS, L"T", WS_CHILD | WS_VISIBLE, 80, 10, 50, 50, w, 0, instance, 0);
    HWND d = CreateWindowExW(0, CLASS_NAME, L"D", WS_CHILD | WS_VISIBLE | WS_DISABLED, 150, 10, 50, 50, w, 0,
                             instance, 0);
    HWND h = CreateWindowExW(0, CLASS_NAME, L"H", WS_CHILD, 220, 10, 50, 50, w, 0, instance, 0);
    HWND p = CreateWindowExW(0, CLASS_NAME, L"P", WS_POPUP | WS_VISIBLE, 600, 100, 100, 100, w, 0, instance, 0);
    HWND m = CreateWindowExW(0, CLASS_NAME, L"M", 0, 0, 0, 0, 0, HWND_MESSAGE, 0, instance, 0);
    RECT rect;
    POINT point;
    DWORD unknown, bad_type;
    HWND none, bad;
    HWND hidden_rect_window;

    DbgPrint("[hooks] GetAncestor: C parent %s, root %s, rootowner %s; W parent %s, root %s, rootowner %s\n",
             name(GetAncestor(c, GA_PARENT), w, c, p), name(GetAncestor(c, GA_ROOT), w, c, p),
             name(GetAncestor(c, GA_ROOTOWNER), w, c, p), name(GetAncestor(w, GA_PARENT), w, c, p),
             name(GetAncestor(w, GA_ROOT), w, c, p), name(GetAncestor(w, GA_ROOTOWNER), w, c, p));
    DbgPrint("[hooks] GetAncestor: P parent %s, root %s, rootowner %s; M root itself %d, parent not the desktop %d\n",
             name(GetAncestor(p, GA_PARENT), w, c, p), name(GetAncestor(p, GA_ROOT), w, c, p),
             name(GetAncestor(p, GA_ROOTOWNER), w, c, p), GetAncestor(m, GA_ROOT) == m,
             GetAncestor(m, GA_PARENT) != 0 && GetAncestor(m, GA_PARENT) != GetDesktopWindow());
    none = GetAncestor(GetDesktopWindow(), GA_ROOT);
    SetLastError(0);
    bad = GetAncestor((HWND)0x1234, GA_ROOT);
    unknown = GetLastError();
    SetLastError(0);
    GetAncestor(c, 4);
    bad_type = GetLastError();
    DbgPrint("[hooks] GetAncestor: of the desktop %s; an unknown window %s (%lu); type 4 (%lu)\n",
             name(none, w, c, p), name(bad, w, c, p), unknown, bad_type);

    GetWindowRect(w, &rect);
    point.x = rect.left + 60;
    point.y = rect.top + 8;
    hidden_rect_window = WindowFromPoint(centre(h));
    DbgPrint("[hooks] WindowFromPoint: C %s, the caption %s, T %s, D %s, H %s, P %s, outside %s\n",
             name(WindowFromPoint(centre(c)), w, c, p), name(WindowFromPoint(point), w, c, p),
             name(WindowFromPoint(centre(t)), w, c, p), name(WindowFromPoint(centre(d)), w, c, p),
             name(hidden_rect_window, w, c, p), name(WindowFromPoint(centre(p)), w, c, p),
             name(WindowFromPoint((POINT){5, 5}), w, c, p));

    {
        BOOL to_w = SetForegroundWindow(w);
        HWND after_w = GetForegroundWindow();
        BOOL to_p = SetForegroundWindow(p);
        HWND after_p = GetForegroundWindow();
        BOOL to_c = SetForegroundWindow(c);
        HWND after_c = GetForegroundWindow();
        DbgPrint("[hooks] SetForegroundWindow: W %d, then %s; P %d, then %s; C %d, then %s\n", to_w,
                 name(after_w, w, c, p), to_p, name(after_p, w, c, p), to_c, name(after_c, w, c, p));
    }
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND w;

    if (!take_a_desktop())
        ExitProcess(1);
    refusals(instance);
    get_message_hooks();

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    RegisterClassExW(&class_info);
    class_info.lpfnWndProc = transparent_procedure;
    class_info.lpszClassName = TRANSPARENT_CLASS;
    RegisterClassExW(&class_info);
    w = CreateWindowExW(0, CLASS_NAME, L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0, instance,
                        0);

    message_filters(w);
    another_thread();
    shell_queries(w, instance);
    DbgPrint("[hooks] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
