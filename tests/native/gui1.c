/*
 * M6, windows: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32. The scenario `gui` puts it on the
 * boot disk in the place of winlogon.exe, which smss starts as its initial
 * command (csrss makes it a CSR process): it gets a real user32, connected
 * to csrss and win32k, without winlogon's RPC server, services and GINA.
 *
 * Like winlogon, it registers as the logon process, creates the interactive
 * window station WinSta0 and a desktop, and goes on it. Then it registers a
 * class and creates a window of it: win32k sends the window procedure
 * WM_NCCREATE, WM_CREATE... through KeUserModeCallback. Each step and each
 * message goes to the debug port (DbgPrint), where the scenario looks for
 * them; the program ends with EXIT_STATUS.
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
    void *lpCreateParams;
    HINSTANCE hInstance;
    HMENU hMenu;
    HWND hwndParent;
    int cy;
    int cx;
    int y;
    int x;
    LONG style;
    const WCHAR *lpszName;
    const WCHAR *lpszClass;
    DWORD dwExStyle;
} CREATESTRUCTW;

#define MAXIMUM_ALLOWED 0x02000000
#define CS_GLOBALCLASS 0x4000
#define ERROR_CLASS_ALREADY_EXISTS 1410
#define ERROR_CLASS_DOES_NOT_EXIST 1411
#define WS_POPUP 0x80000000
#define WS_CHILD 0x40000000
#define WS_CLIPSIBLINGS 0x04000000
#define GWL_STYLE (-16)
#define GW_CHILD 5
#define WM_PARENTNOTIFY 0x0210
#define ERROR_TLW_WITH_WSCHILD 1406
#define ERROR_CANNOT_FIND_WND_CLASS 1407
#define COLOR_WINDOW 5
#define WM_CREATE 0x0001
#define WM_NCCREATE 0x0081

/* What the scenario expects when the program runs to its end. */
#define EXIT_STATUS 0x600D

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall GetClassInfoExW(HINSTANCE instance, const WCHAR *name, WNDCLASSEXW *class_info);
__declspec(dllimport) HWND __stdcall GetParent(HWND window);
__declspec(dllimport) HWND __stdcall GetWindow(HWND window, UINT command);
__declspec(dllimport) LONG __stdcall GetWindowLongW(HWND window, int index);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) int __stdcall GetWindowTextW(HWND window, WCHAR *text, int size);
__declspec(dllimport) BOOL __stdcall IsWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetWindowTextW(HWND window, const WCHAR *text);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

/* No C runtime: what GCC may call to clear or copy a structure. */
void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, unsigned int count)
{
    unsigned char *to = destination;
    const unsigned char *from = source;
    while (count--)
        *to++ = *from++;
    return destination;
}

static const WCHAR CLASS_NAME[] = L"MinoTestWindow";
static const WCHAR WINDOW_NAME[] = L"Mino";
#define CREATE_PARAMETER ((void *)0x1234)

/* Whether two strings are equal. */
static BOOL same(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

/* The messages the window procedure received, in order, until printed. */
static UINT received[32];
static unsigned int received_count;
/* What WM_PARENTNOTIFY gave. */
static WPARAM notified_w;
static LPARAM notified_l;

/* Prints the messages received since the last time. */
static void print_messages(const char *what)
{
    char text[32 * 5 + 1];
    char *at = text;
    unsigned int i;
    static const char digits[] = "0123456789abcdef";

    for (i = 0; i < received_count; i++) {
        int shift;
        for (shift = 12; shift >= 0; shift -= 4)
            *at++ = digits[(received[i] >> shift) & 15];
        *at++ = ' ';
    }
    *at = 0;
    DbgPrint("[gui] %s received: %s\n", what, text);
    received_count = 0;
}

static void check_callback_window(HWND window);

static LRESULT __stdcall window_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (received_count < 32)
        received[received_count++] = message;
    if (message == WM_PARENTNOTIFY) {
        notified_w = w;
        notified_l = l;
    }
    if ((message == WM_NCCREATE || message == WM_CREATE) && ((const CREATESTRUCTW *)l)->style == (LONG)WS_POPUP) {
        const CREATESTRUCTW *create = (const CREATESTRUCTW *)l;
        BOOL expected = create->lpCreateParams == CREATE_PARAMETER && same(create->lpszName, WINDOW_NAME)
                        && same(create->lpszClass, CLASS_NAME) && create->x == 100 && create->y == 50
                        && create->cx == 400 && create->cy == 300;
        DbgPrint("[gui] %s: CREATESTRUCT %s\n", message == WM_NCCREATE ? "WM_NCCREATE" : "WM_CREATE",
                 expected ? "as given" : "WRONG");
        if (message == WM_CREATE)
            check_callback_window(window);
    }
    return DefWindowProcW(window, message, w, l);
}

/* The TEB of the current thread. */
static const unsigned char *current_teb(void)
{
    const unsigned char *teb;
    __asm__("movl %%fs:0x18, %0" : "=r"(teb));
    return teb;
}

/* TEB.Win32ClientInfo, CLIENTINFO.CallbackWnd: during a call from win32k,
   the window and its WND (in this process's view of the desktop's heap),
   whose first word is its handle. */
static void check_callback_window(HWND window)
{
    const DWORD *callback = (const DWORD *)(current_teb() + 0x6CC + 0x28);
    BOOL right = callback[0] == (DWORD)window && callback[1] && *(const DWORD *)callback[1] == (DWORD)window;
    DbgPrint("[gui] CallbackWnd: %s\n", right ? "the window and its WND" : "WRONG");
}

/* A window procedure that refuses WM_NCCREATE. */
static LRESULT __stdcall refusing_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    if (message == WM_NCCREATE)
        return 0;
    return DefWindowProcW(window, message, w, l);
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it. */
static BOOL take_a_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), 1)) {
        DbgPrint("[gui] RegisterLogonProcess failed (%lu)\n", GetLastError());
        return 0;
    }
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, 0);
    if (!station || !SetProcessWindowStation(station)) {
        DbgPrint("[gui] no window station (%lu)\n", GetLastError());
        return 0;
    }
    desktop = CreateDesktopW(L"Default", 0, 0, 0, MAXIMUM_ALLOWED, 0);
    if (!desktop || !SetThreadDesktop(desktop) || !SwitchDesktop(desktop)) {
        DbgPrint("[gui] no desktop (%lu)\n", GetLastError());
        return 0;
    }
    DbgPrint("[gui] on WinSta0\\Default\n");
    return 1;
}

/* The class again, and user32's Button: GetClassInfoExW (NtUserGetClassInfo)
   and a second registration. */
static void check_classes(HINSTANCE instance, ATOM atom, const WNDCLASSEXW *registered)
{
    WNDCLASSEXW found;
    BOOL got;
    ATOM again;

    memset(&found, 0, sizeof found);
    found.cbSize = sizeof found;
    got = GetClassInfoExW(instance, CLASS_NAME, &found);
    DbgPrint("[gui] GetClassInfoExW: %s\n",
             (ATOM)got == atom && found.lpfnWndProc == registered->lpfnWndProc && found.hInstance == instance
                     && found.hbrBackground == registered->hbrBackground && found.style == registered->style
                 ? "the class as registered"
                 : "WRONG");
    memset(&found, 0, sizeof found);
    found.cbSize = sizeof found;
    got = GetClassInfoExW(0, L"Button", &found);
    DbgPrint("[gui] GetClassInfoExW(Button): %s\n",
             got && found.lpfnWndProc && !(found.style & CS_GLOBALCLASS) ? "user32's class" : "WRONG");
    SetLastError(0);
    got = GetClassInfoExW(instance, L"NoSuchClass", &found);
    DbgPrint("[gui] GetClassInfoExW(NoSuchClass): %d (%lu)\n", got, GetLastError());
    SetLastError(0);
    again = RegisterClassExW(registered);
    DbgPrint("[gui] RegisterClassExW again: %04x (%lu)\n", again, GetLastError());
}

/* What user32 reads of the window by itself (its WND, in the desktop's
   heap), a child window, and windows that cannot be created. */
static void check_window(HWND window, HINSTANCE instance)
{
    WCHAR text[16];
    RECT rect;
    HWND child;
    WNDCLASSEXW refusing;

    DbgPrint("[gui] IsWindow: %d\n", IsWindow(window));
    GetWindowTextW(window, text, 16);
    DbgPrint("[gui] GetWindowTextW: %s\n", same(text, WINDOW_NAME) ? "Mino" : "WRONG");
    print_messages("GetWindowTextW");
    SetWindowTextW(window, L"Mino, longer");
    GetWindowTextW(window, text, 16);
    DbgPrint("[gui] SetWindowTextW, longer: %s\n", same(text, L"Mino, longer") ? "as set" : "WRONG");
    SetWindowTextW(window, L"M");
    GetWindowTextW(window, text, 16);
    DbgPrint("[gui] SetWindowTextW, shorter: %s\n", same(text, L"M") ? "as set" : "WRONG");
    print_messages("SetWindowTextW and GetWindowTextW");
    DbgPrint("[gui] GetWindowLongW(GWL_STYLE): %08lx\n", (DWORD)GetWindowLongW(window, GWL_STYLE));
    GetWindowRect(window, &rect);
    DbgPrint("[gui] GetWindowRect: %ld %ld %ld %ld\n", rect.left, rect.top, rect.right, rect.bottom);

    SetLastError(0);
    child = CreateWindowExW(0, CLASS_NAME, L"Child", WS_CHILD, 10, 20, 100, 50, window, (HMENU)7, instance, 0);
    DbgPrint("[gui] child: %s (%lu)\n", child ? "a window" : "none", GetLastError());
    print_messages("the child and its parent");
    DbgPrint("[gui] WM_PARENTNOTIFY: %s\n", notified_w == (7 << 16 | WM_CREATE) && (HWND)notified_l == child ? "WM_CREATE, 7, the child" : "WRONG");
    DbgPrint("[gui] GetParent: %s\n", GetParent(child) == window ? "the window" : "WRONG");
    DbgPrint("[gui] GetWindow(GW_CHILD): %s\n", GetWindow(window, GW_CHILD) == child ? "the child" : "WRONG");
    GetWindowRect(child, &rect);
    DbgPrint("[gui] child GetWindowRect: %ld %ld %ld %ld\n", rect.left, rect.top, rect.right, rect.bottom);

    SetLastError(0);
    child = CreateWindowExW(0, CLASS_NAME, L"Orphan", WS_CHILD, 0, 0, 10, 10, 0, 0, instance, 0);
    DbgPrint("[gui] child without a parent: %p (%lu)\n", child, GetLastError());
    SetLastError(0);
    child = CreateWindowExW(0, L"NoSuchClass", L"None", WS_POPUP, 0, 0, 10, 10, 0, 0, instance, 0);
    DbgPrint("[gui] window of no class: %p (%lu)\n", child, GetLastError());
    memset(&refusing, 0, sizeof refusing);
    refusing.cbSize = sizeof refusing;
    refusing.lpfnWndProc = refusing_procedure;
    refusing.hInstance = instance;
    refusing.lpszClassName = L"MinoRefusing";
    RegisterClassExW(&refusing);
    child = CreateWindowExW(0, L"MinoRefusing", L"Refused", WS_POPUP, 0, 0, 10, 10, 0, 0, instance, 0);
    DbgPrint("[gui] window refusing WM_NCCREATE: %p\n", child);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    ATOM atom;
    HWND window;

    if (!take_a_desktop())
        ExitProcess(1);

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = window_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    atom = RegisterClassExW(&class_info);
    DbgPrint("[gui] RegisterClassExW: atom %04x (%lu)\n", atom, atom ? 0 : GetLastError());
    if (!atom)
        ExitProcess(2);
    check_classes(instance, atom, &class_info);

    SetLastError(0);
    window = CreateWindowExW(0, CLASS_NAME, WINDOW_NAME, WS_POPUP, 100, 50, 400, 300, 0, 0, instance,
                             CREATE_PARAMETER);
    DbgPrint("[gui] CreateWindowExW: %s (%lu)\n", window ? "a window" : "none", GetLastError());
    if (!window)
        ExitProcess(3);
    print_messages("the window");
    check_window(window, instance);

    DbgPrint("[gui] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
