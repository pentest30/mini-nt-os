/*
 * The cursors: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which the scenario `cursor` puts
 * on the boot disk in the place of winlogon.exe (like `mouse`, see
 * mouse1.c). Its desktop on the screen, user32 has loaded the system
 * cursors (win32k's callback LOADDEFAULTCURSORS) and made the arrow the
 * thread's cursor; LoadCursor(NULL, IDC_*) finds them (LR_SHARED, the
 * system's). Its window, with a sizing frame, has the cross for its class
 * cursor; once it is painted, it says it waits, and the scenario moves the
 * mouse through QEMU's monitor:
 * - into its client area: WM_SETCURSOR (HTCLIENT, WM_MOUSEMOVE), and
 *   DefWindowProc takes the class cursor (FALSE);
 * - onto its left border: WM_SETCURSOR (HTLEFT), and DefWindowProc takes
 *   the system's IDC_SIZEWE (TRUE);
 * - back into its client area: the cross again, which the screen shows
 *   at the pointer.
 * A system cursor is not destroyed (DestroyCursor TRUE, it stays). Each
 * step goes to the debug port (DbgPrint); the program ends with
 * EXIT_STATUS.
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
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HDC;
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

typedef struct {
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
} PAINTSTRUCT;

#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define WS_THICKFRAME 0x00040000
#define WM_PAINT 0x000F
#define WM_SETCURSOR 0x0020
#define WM_MOUSEMOVE 0x0200
#define HTCLIENT 1
#define HTLEFT 10
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define IDC_ARROW ((const WCHAR *)32512)
#define IDC_CROSS ((const WCHAR *)32515)
#define IDC_SIZEWE ((const WCHAR *)32644)
#define EXIT_STATUS 0x600F

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall DestroyCursor(HCURSOR cursor);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HCURSOR __stdcall GetCursor(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HCURSOR __stdcall LoadCursorW(HINSTANCE instance, const WCHAR *name);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HCURSOR __stdcall SetCursor(HCURSOR cursor);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static const WCHAR CLASS_NAME[] = L"MinoCursor";
static HCURSOR arrow, cross, size_we;
static int painted;
/* 0: waits for the client area; 1: for the left border; 2: for the client
 * area again; 3: done. */
static int step;

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
    DbgPrint("[cursor] on WinSta0\\Default\n");
    return 1;
}

static LRESULT __stdcall cursor_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;
    LRESULT result;
    UINT hit = l & 0xFFFF, mouse = (l >> 16) & 0xFFFF;

    switch (message) {
    case WM_PAINT:
        BeginPaint(window, &paint);
        EndPaint(window, &paint);
        if (!painted)
            DbgPrint("[cursor] waiting\n");
        painted = 1;
        return 0;
    case WM_SETCURSOR:
        result = DefWindowProcW(window, message, w, l);
        if (step == 0 && hit == HTCLIENT) {
            DbgPrint("[cursor] WM_SETCURSOR in the client area: for itself %d, WM_MOUSEMOVE %d; DefWindowProc %ld, "
                     "the class cursor %d\n",
                     (HWND)w == window, mouse == WM_MOUSEMOVE, result, GetCursor() == cross);
            step = 1;
        } else if (step == 1 && hit == HTLEFT) {
            DbgPrint("[cursor] WM_SETCURSOR on the left border: DefWindowProc %ld, IDC_SIZEWE %d\n", result,
                     GetCursor() == size_we);
            step = 2;
        } else if (step == 2 && hit == HTCLIENT) {
            DbgPrint("[cursor] WM_SETCURSOR in the client area again: the class cursor %d\n", GetCursor() == cross);
            step = 3;
            PostQuitMessage(0);
        }
        return result;
    }
    return DefWindowProcW(window, message, w, l);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
    MSG message;
    HCURSOR previous;

    if (!take_a_desktop())
        ExitProcess(1);
    arrow = LoadCursorW(0, IDC_ARROW);
    DbgPrint("[cursor] IDC_ARROW: %d, shared %d, the thread's cursor %d\n", arrow != 0, LoadCursorW(0, IDC_ARROW) == arrow,
             GetCursor() == arrow);
    cross = LoadCursorW(0, IDC_CROSS);
    size_we = LoadCursorW(0, IDC_SIZEWE);
    DbgPrint("[cursor] IDC_CROSS %d, IDC_SIZEWE %d, all different %d\n", cross != 0, size_we != 0,
             cross != arrow && size_we != arrow && cross != size_we);
    previous = SetCursor(cross);
    DbgPrint("[cursor] SetCursor: the arrow before %d, the cross now %d\n", previous == arrow, GetCursor() == cross);
    SetCursor(arrow);

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = cursor_procedure;
    class_info.hInstance = instance;
    class_info.hCursor = cross;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    /* The pointer starts at the centre of the screen (640, 400), in its
     * client area; its left border is at x 200. */
    window = CreateWindowExW(0, CLASS_NAME, L"Cursor", WS_POPUP | WS_VISIBLE | WS_THICKFRAME, 200, 200, 800, 500, 0, 0,
                             instance, 0);
    if (!window)
        ExitProcess(3);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[cursor] DestroyCursor(IDC_CROSS): %d, still the same %d\n", DestroyCursor(cross),
             LoadCursorW(0, IDC_CROSS) == cross);
    DbgPrint("[cursor] done\n");
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
