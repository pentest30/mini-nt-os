/*
 * SetForegroundWindow of a minimized window (win32k::input::
 * set_foreground_window, activate; co_IntSetForegroundWindow and
 * co_IntSetActiveWindow of ReactOS as the specification): a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's kernel32
 * and user32, which the scenario `foreground-minimized` puts on the boot
 * disk in the place of winlogon.exe (like sysmenu1.c). It takes a desktop
 * like winlogon, loads the US keyboard layout, and shows W at (100, 100,
 * 400 x 300) with a child C, and B at (550, 300, 300 x 200), then:
 * 1. C has the keyboard; ShowWindow(W, SW_MINIMIZE): B active, with the
 *    keyboard;
 * 2. SetForegroundWindow(W): W active and in the foreground, still
 *    minimized, nobody has the keyboard; W's WM_ACTIVATE says it is
 *    minimized (its high word), B gets WM_ACTIVATE (WA_INACTIVE) and
 *    WM_KILLFOCUS (to nobody);
 * 3. QEMU types a: W gets it as WM_SYSKEYDOWN (a system key: nobody has the
 *    keyboard);
 * 4. QEMU types Alt+Space then r: the window menu of the minimized W, its
 *    Restore: W restored, with the keyboard; W is minimized again and
 *    SetForegroundWindow(W) makes it active again;
 * 5. QEMU types Enter: DefWindowProc restores W (WM_SYSCHAR of Enter:
 *    SC_RESTORE), which gets the keyboard; then W is destroyed.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; a "[fgmin] keyboard:" line asks the scenario for its keys.
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
typedef void *HKL;
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

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WM_DESTROY 0x0002
#define WM_ACTIVATE 0x0006
#define WM_SETFOCUS 0x0007
#define WM_KILLFOCUS 0x0008
#define WM_SYSKEYDOWN 0x0104
#define WM_SYSKEYUP 0x0105
#define WM_SYSCOMMAND 0x0112
#define WM_INITMENUPOPUP 0x0117
#define SC_RESTORE 0xF120
#define SW_MINIMIZE 6
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define EXIT_STATUS 0x700A

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

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
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HWND __stdcall GetActiveWindow(void);
__declspec(dllimport) HWND __stdcall GetFocus(void);
__declspec(dllimport) HWND __stdcall GetForegroundWindow(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall IsIconic(HWND window);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HWND __stdcall SetFocus(HWND window);
__declspec(dllimport) BOOL __stdcall SetForegroundWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static HWND w, c, b;
/* The step whose keys come next (3 to 5). */
static int stage;
/* What W and B received since the last reset: W's last WM_ACTIVATE wParam
   and its WM_SETFOCUS, B's last WM_ACTIVATE wParam, its WM_KILLFOCUS and
   the window the last one named. */
static int w_activate = -1, w_setfocus, b_activate = -1, b_killfocus;
static HWND b_killfocus_to;

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

static void reset(void)
{
    w_activate = b_activate = -1;
    w_setfocus = b_killfocus = 0;
    b_killfocus_to = (HWND)1;
}

/* SetForegroundWindow(W), W minimized: what it gives, and what W and B
   received. */
static void set_foreground_minimized(int step)
{
    BOOL result;

    reset();
    result = SetForegroundWindow(w);
    DbgPrint("[fgmin] step %d: SetForegroundWindow %d; foreground W %d, active W %d, focus nobody %d, iconic %d\n",
             step, result, GetForegroundWindow() == w, GetActiveWindow() == w, GetFocus() == 0, IsIconic(w) != 0);
    DbgPrint("[fgmin] step %d: W WM_ACTIVATE %x, WM_SETFOCUS %d; B WM_ACTIVATE %x, WM_KILLFOCUS %d to nobody %d\n",
             step, w_activate, w_setfocus, b_activate, b_killfocus, b_killfocus_to == 0);
}

/* W's WM_SYSCOMMAND SC_RESTORE, from its window menu (step 4) or Enter
   (step 5), done by DefWindowProc. */
static LRESULT restore(HWND window, WPARAM wp, LPARAM lp)
{
    LRESULT result = DefWindowProcW(window, WM_SYSCOMMAND, wp, lp);

    DbgPrint("[fgmin] step %d: SC_RESTORE; iconic %d, active W %d, focus W %d\n", stage, IsIconic(w) != 0,
             GetActiveWindow() == w, GetFocus() == w);
    if (stage == 4) {
        ShowWindow(w, SW_MINIMIZE);
        DbgPrint("[fgmin] step 4: minimized again, active B %d\n", GetActiveWindow() == b);
        set_foreground_minimized(4);
        stage = 5;
        DbgPrint("[fgmin] keyboard: step 5\n");
    } else {
        DestroyWindow(b);
        DestroyWindow(w);
    }
    return result;
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (window == b) {
        if (message == WM_ACTIVATE)
            b_activate = (int)wp;
        if (message == WM_KILLFOCUS) {
            b_killfocus++;
            b_killfocus_to = (HWND)wp;
        }
        return DefWindowProcW(window, message, wp, lp);
    }
    if (window != w)
        return DefWindowProcW(window, message, wp, lp);
    switch (message) {
    case WM_ACTIVATE:
        w_activate = (int)wp;
        break;
    case WM_SETFOCUS:
        w_setfocus++;
        break;
    case WM_SYSKEYDOWN:
        if (stage == 3 && wp == 'A')
            DbgPrint("[fgmin] step 3: W WM_SYSKEYDOWN %x, focus nobody %d\n", wp, GetFocus() == 0);
        break;
    case WM_SYSKEYUP:
        if (stage == 3 && wp == 'A') {
            stage = 4;
            DbgPrint("[fgmin] keyboard: step 4\n");
        }
        break;
    case WM_INITMENUPOPUP:
        DbgPrint("[fgmin] step %d: WM_INITMENUPOPUP, the window menu %d\n", stage, (lp >> 16 & 0xFFFF) != 0);
        break;
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_RESTORE)
            return restore(window, wp, lp);
        break;
    case WM_DESTROY:
        DbgPrint("[fgmin] W destroyed\n");
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wp, lp);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    MSG message;

    if (!take_a_desktop())
        ExitProcess(1);
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        ExitProcess(2);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoFgMin";
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);
    w = CreateWindowExW(0, L"MinoFgMin", L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0, instance,
                        0);
    c = CreateWindowExW(0, L"MinoFgMin", L"C", WS_CHILD | WS_VISIBLE, 10, 10, 100, 30, w, 0, instance, 0);
    b = CreateWindowExW(0, L"MinoFgMin", L"B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 550, 300, 300, 200, 0, 0, instance,
                        0);
    if (!w || !c || !b)
        ExitProcess(4);

    SetForegroundWindow(w);
    SetFocus(c);
    ShowWindow(w, SW_MINIMIZE);
    DbgPrint("[fgmin] step 1: C had the keyboard; W minimized %d, active B %d, focus B %d\n", IsIconic(w) != 0,
             GetActiveWindow() == b, GetFocus() == b);

    set_foreground_minimized(2);
    stage = 3;
    DbgPrint("[fgmin] keyboard: step 3\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[fgmin] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
