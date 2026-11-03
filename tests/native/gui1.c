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

static LRESULT __stdcall window_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    DbgPrint("[gui] message %04x to %p\n", message, window);
    if (message == WM_NCCREATE || message == WM_CREATE) {
        const CREATESTRUCTW *create = (const CREATESTRUCTW *)l;
        BOOL expected = create->lpCreateParams == CREATE_PARAMETER && same(create->lpszName, WINDOW_NAME)
                        && same(create->lpszClass, CLASS_NAME) && create->x == 100 && create->y == 50
                        && create->cx == 400 && create->cy == 300 && (DWORD)create->style == WS_POPUP;
        DbgPrint("[gui] %s: CREATESTRUCT %s\n", message == WM_NCCREATE ? "WM_NCCREATE" : "WM_CREATE",
                 expected ? "as given" : "WRONG");
    }
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
    DbgPrint("[gui] CreateWindowExW: %p (%lu)\n", window, window ? 0 : GetLastError());
    if (!window)
        ExitProcess(3);

    DbgPrint("[gui] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
