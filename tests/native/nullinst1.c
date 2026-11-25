/*
 * A window class registered and a window created with a NULL instance, as
 * msi.dll makes its dialogs (dialog_register_class, dialog_run_message_loop):
 * a Win32 program (subsystem WINDOWS), compiled with MinGW and linked to
 * ReactOS's kernel32 and user32, which the scenario `class-null-instance`
 * puts on the boot disk in the place of winlogon.exe. user32 registers the
 * class under the program's module (RegisterClassExWOWW: GetModuleHandleW
 * of NULL); win32k finds it for a window created with a NULL instance, as
 * IntFindClass matches a NULL instance with any (win32k::class::ClassLists::
 * find). Mino looked for a class of the instance 0, found none, and the full
 * UI of msiexec (the 7-Zip MSI opened from explorer) showed nothing.
 * 1. RegisterClassW with a NULL instance, CreateWindowW with a NULL instance:
 *    the window exists, of that class, and its procedure got WM_CREATE;
 * 2. CreateWindowW with another program's instance does not find it.
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
} WNDCLASSW;

#define WS_OVERLAPPED 0x00000000
#define WS_SYSMENU 0x00080000
#define WM_CREATE 0x0001
#define CW_USEDEFAULT ((int)0x80000000)
#define COLOR_3DFACE 15
#define MAXIMUM_ALLOWED 0x02000000
#define ERROR_CANNOT_FIND_WND_CLASS 1407

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) int __stdcall GetClassNameW(HWND window, WCHAR *name, int count);
__declspec(dllimport) ATOM __stdcall RegisterClassW(const WNDCLASSW *info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
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

static int created;

static LRESULT __stdcall procedure(HWND hwnd, UINT message, WPARAM w, LPARAM l)
{
    created += message == WM_CREATE;
    return DefWindowProcW(hwnd, message, w, l);
}

static int same_wide(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSW info;
    HWND window, elsewhere;
    WCHAR class_name[64];
    int named;
    DWORD error;

    if (!take_a_desktop())
        ExitProcess(1);

    /* 1. msi.dll's way: a NULL instance for the class and for the window. */
    memset(&info, 0, sizeof info);
    info.lpfnWndProc = procedure;
    info.hInstance = 0;
    info.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    info.lpszClassName = L"MinoNullInstance";
    if (!RegisterClassW(&info))
        ExitProcess(2);
    SetLastError(0);
    window = CreateWindowExW(0, L"MinoNullInstance", L"N", WS_OVERLAPPED | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
                             CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, 0, 0);
    error = GetLastError();
    memset(class_name, 0, sizeof class_name);
    named = window && GetClassNameW(window, class_name, 64) && same_wide(class_name, L"MinoNullInstance");
    DbgPrint("[nullinst] step 1: a NULL instance: the window %d (error %lu), of the class %d, WM_CREATE %d\n",
             window != 0, error, named, created);

    /* 2. Another program's instance: not this program's private class. */
    SetLastError(0);
    elsewhere = CreateWindowExW(0, L"MinoNullInstance", L"E", WS_OVERLAPPED, 0, 0, 10, 10, 0, 0,
                                (HINSTANCE)0x00500000, 0);
    error = GetLastError();
    DbgPrint("[nullinst] step 2: another instance: the window %d, error %lu\n", elsewhere != 0, error);
    DbgPrint("[nullinst] done\n");
    ExitProcess(0);
    return 0;
}
