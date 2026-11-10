/*
 * The icons: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which the scenario `icons` puts
 * on the boot disk in the place of winlogon.exe (like `cursor`, see
 * cursor1.c). Its desktop on the screen, user32 has loaded the system icons
 * (win32k's callback SETWNDICONS) after the system cursors; LoadIcon(NULL,
 * IDI_*) finds them. Three windows with a caption and a system menu:
 * - A, of a class without an icon: its caption shows the system's small
 *   IDI_WINLOGO;
 * - B, of a class whose icon is IDI_HAND: its caption shows it, at
 *   SM_CXSMICON x SM_CYSMICON; its client area draws it at 32 x 32 with
 *   DrawIconEx;
 * - C, of A's class, given IDI_ASTERISK by WM_SETICON (ICON_SMALL), which
 *   WM_GETICON gives back: its caption shows it.
 * Each step goes to the debug port (DbgPrint); the program ends with
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

#define WS_VISIBLE 0x10000000
#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WM_PAINT 0x000F
#define WM_GETICON 0x007F
#define WM_SETICON 0x0080
#define ICON_SMALL 0
#define ICON_BIG 1
#define DI_NORMAL 0x0003
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define IDI_APPLICATION ((const WCHAR *)32512)
#define IDI_HAND ((const WCHAR *)32513)
#define IDI_ASTERISK ((const WCHAR *)32516)
#define IDI_WINLOGO ((const WCHAR *)32517)
#define EXIT_STATUS 0x6010

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

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
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall DrawIconEx(HDC hdc, int x, int y, HICON icon, int width, int height, UINT step,
                                                HBRUSH brush, UINT flags);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HICON __stdcall LoadIconW(HINSTANCE instance, const WCHAR *name);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

#define WM_APP_DONE 0x8001

static const WCHAR PLAIN_CLASS[] = L"MinoIconPlain";
static const WCHAR HAND_CLASS[] = L"MinoIconHand";
static HICON hand;
static HWND window_b;
static int painted_b;

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
    DbgPrint("[icon] on WinSta0\\Default\n");
    return 1;
}

static LRESULT __stdcall icon_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;
    HDC hdc;
    BOOL drawn, refused;
    DWORD error;

    if (message == WM_PAINT && window == window_b) {
        hdc = BeginPaint(window, &paint);
        drawn = DrawIconEx(hdc, 20, 20, hand, 32, 32, 0, 0, DI_NORMAL);
        SetLastError(0);
        refused = !DrawIconEx(hdc, 80, 20, (HICON)0x00DEAD02, 32, 32, 0, 0, DI_NORMAL);
        error = GetLastError();
        EndPaint(window, &paint);
        if (!painted_b) {
            DbgPrint("[icon] DrawIconEx(IDI_HAND, 32 x 32): %d; a handle that is no icon: refused %d, error %lu\n",
                     drawn, refused, error);
            PostMessageW(window, WM_APP_DONE, 0, 0);
        }
        painted_b = 1;
        return 0;
    }
    if (message == WM_APP_DONE) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

static ATOM register_class(const WCHAR *name, HICON icon)
{
    WNDCLASSEXW class_info;

    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = icon_procedure;
    class_info.hInstance = GetModuleHandleW(0);
    class_info.hIcon = icon;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = name;
    return RegisterClassExW(&class_info);
}

DWORD __stdcall GuiStartup(void)
{
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window_a, window_c;
    HICON application, asterisk, previous, given;
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    application = LoadIconW(0, IDI_APPLICATION);
    hand = LoadIconW(0, IDI_HAND);
    asterisk = LoadIconW(0, IDI_ASTERISK);
    DbgPrint("[icon] IDI_APPLICATION %d, shared %d; IDI_HAND %d, IDI_ASTERISK %d, IDI_WINLOGO %d\n", application != 0,
             LoadIconW(0, IDI_APPLICATION) == application, hand != 0, asterisk != 0, LoadIconW(0, IDI_WINLOGO) != 0);

    if (!register_class(PLAIN_CLASS, 0) || !register_class(HAND_CLASS, hand))
        ExitProcess(2);
    window_a = CreateWindowExW(0, PLAIN_CLASS, L"A", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 100, 380, 250, 0, 0,
                               instance, 0);
    window_c = CreateWindowExW(0, PLAIN_CLASS, L"C", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 860, 100, 380, 250, 0, 0,
                               instance, 0);
    if (!window_a || !window_c)
        ExitProcess(3);
    previous = (HICON)SendMessageW(window_c, WM_SETICON, ICON_SMALL, (LPARAM)asterisk);
    given = (HICON)SendMessageW(window_c, WM_GETICON, ICON_SMALL, 0);
    DbgPrint("[icon] WM_SETICON(ICON_SMALL): none before %d; WM_GETICON gives it %d, no big one %d\n", previous == 0,
             given == asterisk, SendMessageW(window_c, WM_GETICON, ICON_BIG, 0) == 0);
    window_b = CreateWindowExW(0, HAND_CLASS, L"B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 450, 100, 380, 250, 0, 0,
                               instance, 0);
    if (!window_b)
        ExitProcess(4);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[icon] done\n");
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
