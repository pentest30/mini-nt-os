/*
 * Moving and sizing a window with the keyboard (SC_MOVE and SC_SIZE from
 * the window menu: win32k::sizemove, DefWndStartSizeMove and
 * DefWndDoSizeMove of ReactOS as the specification): a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's kernel32
 * and user32, which the scenario `keyboard-move` puts on the boot disk in
 * the place of winlogon.exe (like sysmenu1.c). It takes a desktop like
 * winlogon, loads the US keyboard layout, and shows W at (100, 100,
 * 400 x 300), a dialog D without a thick frame and a hidden window H, then:
 * 1. SC_SIZE sent to D (no thick frame) and SC_MOVE sent to H (hidden)
 *    return at once, without WM_ENTERSIZEMOVE;
 * 2. QEMU types Alt+Space then m (Move): the cursor goes to the middle of
 *    W's caption (WM_ENTERSIZEMOVE), then right, right, down move it 8
 *    pixels each and W with it, and Enter ends: W at (116, 108);
 * 3. Alt+Space, m, then left three times and Escape: W back at (116, 108);
 * 4. Alt+Space, m, then the mouse moves (30, 20) and Enter: the mouse moves
 *    W too, to (146, 128);
 * 5. Alt+Space, s (Size): the loop waits for an edge; Escape gives up, no
 *    WM_ENTERSIZEMOVE;
 * 6. Alt+Space, s, then right picks the right edge (the cursor goes to its
 *    middle), right twice widens W by 16, Enter ends;
 * 7. Alt+Space, s, then down picks the bottom edge, up three times makes W
 *    24 pixels shorter, Enter ends;
 * 8. Alt+Space, m, then W's WM_ENTERSIZEMOVE sleeps while QEMU types right,
 *    right and Enter: all three wait in the queue when the loop starts, and
 *    W still moves 16 pixels (each arrow moves it at once, before the mouse
 *    move it makes, which comes behind Enter);
 * 9. W minimized, then made active by SetForegroundWindow (nobody has the
 *    keyboard: its keys are system keys); SC_MOVE posted to it: right, right
 *    and Enter move its bar 16 pixels, and it stays minimized (no
 *    SC_RESTORE); then W is destroyed.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; a "[kbdmove] keyboard:" line, or the WM_SYSCOMMAND and
 * WM_ENTERSIZEMOVE of a step, asks the scenario for its keys.
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
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

typedef struct {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_POPUP 0x80000000
#define WS_CAPTION 0x00C00000
#define WS_SYSMENU 0x00080000
#define WS_VISIBLE 0x10000000
#define WM_DESTROY 0x0002
#define WM_SYSCOMMAND 0x0112
#define WM_ENTERSIZEMOVE 0x0231
#define WM_EXITSIZEMOVE 0x0232
#define SC_SIZE 0xF000
#define SC_MOVE 0xF010
#define SC_RESTORE 0xF120
#define SW_MINIMIZE 6
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define EXIT_STATUS 0x7009

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
__declspec(dllimport) BOOL __stdcall GetCursorPos(POINT *point);
__declspec(dllimport) HWND __stdcall GetFocus(void);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall IsIconic(HWND window);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetForegroundWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static HWND w;
/* The step of W's next WM_SYSCOMMAND (2 to 9), and the WM_ENTERSIZEMOVE and
   WM_EXITSIZEMOVE received: by W, and by the other windows; the SC_RESTORE
   W received. */
static int stage = 2, entered, exited, others_entered, restores;

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

/* W's WM_SYSCOMMAND of SC_MOVE or SC_SIZE, done by DefWindowProc: where W
   is after the loop, and what the loop sent. */
static LRESULT size_move(HWND window, WPARAM wp, LPARAM lp)
{
    int before = entered, step = stage;
    RECT rect;
    LRESULT result;

    DbgPrint("[kbdmove] step %d: WM_SYSCOMMAND %x\n", step, wp & 0xFFF0);
    result = DefWindowProcW(window, WM_SYSCOMMAND, wp, lp);
    GetWindowRect(w, &rect);
    DbgPrint("[kbdmove] step %d: done, W at (%d, %d)-(%d, %d), WM_ENTERSIZEMOVE %d, WM_EXITSIZEMOVE %d\n", step,
             rect.left, rect.top, rect.right, rect.bottom, entered - before, exited);
    stage++;
    if (stage <= 8) {
        DbgPrint("[kbdmove] keyboard: step %d\n", stage);
    } else if (stage == 9) {
        ShowWindow(w, SW_MINIMIZE);
        SetForegroundWindow(w);
        DbgPrint("[kbdmove] step 9: W minimized and active: iconic %d, active W %d, focus nobody %d\n", IsIconic(w),
                 GetActiveWindow() == w, GetFocus() == 0);
        PostMessageW(w, WM_SYSCOMMAND, SC_MOVE, 0);
    } else {
        DbgPrint("[kbdmove] step 9: iconic %d, SC_RESTORE %d\n", IsIconic(w), restores);
        DestroyWindow(w);
    }
    return result;
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    POINT cursor;

    if (window != w) {
        if (message == WM_ENTERSIZEMOVE)
            others_entered++;
        return DefWindowProcW(window, message, wp, lp);
    }
    switch (message) {
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_MOVE || (wp & 0xFFF0) == SC_SIZE)
            return size_move(window, wp, lp);
        if ((wp & 0xFFF0) == SC_RESTORE)
            restores++;
        break;
    case WM_ENTERSIZEMOVE:
        entered++;
        GetCursorPos(&cursor);
        DbgPrint("[kbdmove] step %d: WM_ENTERSIZEMOVE, the cursor at (%d, %d)\n", stage, cursor.x, cursor.y);
        /* Step 8: the keys QEMU types meanwhile wait in the queue. */
        if (stage == 8)
            Sleep(2000);
        return 0;
    case WM_EXITSIZEMOVE:
        exited++;
        return 0;
    case WM_DESTROY:
        DbgPrint("[kbdmove] W destroyed\n");
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wp, lp);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND d, h;
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
    class_info.lpszClassName = L"MinoKbdMove";
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);
    w = CreateWindowExW(0, L"MinoKbdMove", L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0, instance,
                        0);
    /* A dialog frame, not a thick one. */
    d = CreateWindowExW(0, L"MinoKbdMove", L"D", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 700, 500, 200, 100,
                        0, 0, instance, 0);
    h = CreateWindowExW(0, L"MinoKbdMove", L"H", WS_OVERLAPPEDWINDOW, 700, 150, 200, 100, 0, 0, instance, 0);
    if (!w || !d || !h)
        ExitProcess(4);

    SendMessageW(d, WM_SYSCOMMAND, SC_SIZE, 0);
    SendMessageW(h, WM_SYSCOMMAND, SC_MOVE, 0);
    DbgPrint("[kbdmove] step 1: SC_SIZE without a thick frame, SC_MOVE of a hidden window: WM_ENTERSIZEMOVE %d\n",
             others_entered);

    SetForegroundWindow(w);
    DbgPrint("[kbdmove] keyboard: step 2\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[kbdmove] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
