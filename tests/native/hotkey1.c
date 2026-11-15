/*
 * Hotkeys (RegisterHotKey): a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the
 * scenario `hotkey` puts on the boot disk in the place of winlogon.exe (like
 * keys1.c). winlogon waits for Ctrl+Alt+Del, the SAS, as a hotkey of its SAS
 * window (RegisterHotKeys of `sas.c`: MOD_CONTROL | MOD_ALT, VK_DELETE);
 * win32k had no hotkeys, and the logon screen that asks for Ctrl+Alt+Del
 * never got it. The program takes a desktop like winlogon, loads the US
 * keyboard layout and opens a window, which gets the keyboard, then:
 * 1. RegisterHotKey: Ctrl+Alt+Delete for the window; the same combination
 *    again refused (ERROR_HOTKEY_ALREADY_REGISTERED), an unknown modifier
 *    (ERROR_INVALID_FLAGS), the desktop window, another thread's
 *    (ERROR_WINDOW_OF_OTHER_THREAD); Ctrl+Shift+Esc for the thread;
 * 2. QEMU's monitor types Ctrl+Alt+Delete, Ctrl+Shift+Esc, then Delete: the
 *    first is WM_HOTKEY to the window (its identifier, MAKELONG(the
 *    modifiers, the key)) and gives no WM_KEYDOWN of Delete, the second is
 *    WM_HOTKEY to the thread (no window), the third an ordinary key;
 * 3. UnregisterHotKey: the window's (then nothing left), the thread's;
 * 4. Ctrl+Alt+Delete again: an ordinary key now, no WM_HOTKEY.
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
typedef long LONG;
typedef short SHORT;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HDC;
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

#define WS_OVERLAPPED 0x00000000
#define WS_CAPTION 0x00C00000
#define WS_SYSMENU 0x00080000
#define WS_VISIBLE 0x10000000
#define WM_PAINT 0x000F
#define WM_KEYDOWN 0x0100
#define WM_SYSKEYDOWN 0x0104
#define WM_HOTKEY 0x0312
#define MOD_ALT 0x0001
#define MOD_CONTROL 0x0002
#define MOD_SHIFT 0x0004
#define MOD_NOREPEAT 0x4000
#define VK_CONTROL 0x11
#define VK_ESCAPE 0x1B
#define VK_DELETE 0x2E
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define EXIT_STATUS 0x7008

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) HWND __stdcall GetDesktopWindow(void);
__declspec(dllimport) SHORT __stdcall GetKeyState(int key);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterHotKey(HWND window, int id, UINT modifiers, UINT vk);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UnregisterHotKey(HWND window, int id);

static const WCHAR CLASS_NAME[] = L"MinoHotKey";
static int painted;
/* What the keys gave: the hotkeys, the WM_KEYDOWN of Delete with Ctrl
   down, the last WM_HOTKEY of the window and of the thread. */
static int window_hotkeys, thread_hotkeys, ctrl_deletes;
static WPARAM window_id = 99, thread_id = 99;
static LPARAM window_keys, thread_keys;
/* The hotkeys are gone (step 3). */
static int unregistered;

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

/* The result of a registration, and its error. */
static void registration(const char *what, BOOL result)
{
    DbgPrint("[hotkey] %s: %d, error %lu\n", what, result, result ? 0 : GetLastError());
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    switch (message) {
    case WM_PAINT:
        BeginPaint(window, &paint);
        EndPaint(window, &paint);
        if (!painted)
            DbgPrint("[hotkey] waiting\n");
        painted = 1;
        return 0;
    case WM_HOTKEY:
        window_hotkeys++;
        window_id = w;
        window_keys = l;
        return 0;
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        if (w != VK_DELETE)
            return 0;
        if (GetKeyState(VK_CONTROL) < 0) {
            ctrl_deletes++;
            if (unregistered) {
                DbgPrint("[hotkey] step 4: Ctrl+Alt+Delete without the hotkey: a key %d, hotkeys %d\n",
                         ctrl_deletes, window_hotkeys + thread_hotkeys);
                PostQuitMessage(0);
            }
            return 0;
        }
        /* Delete alone: steps 2 and 3. */
        DbgPrint("[hotkey] step 2: WM_HOTKEY to the window %d: id %u, %08lx; to the thread %d: id %u, %08lx; "
                 "Ctrl+Delete keys %d\n",
                 window_hotkeys, window_id, window_keys, thread_hotkeys, thread_id, thread_keys,
                 ctrl_deletes);
        {
            BOOL mine = UnregisterHotKey(window, 0);
            BOOL again = UnregisterHotKey(window, 0);
            BOOL thread = UnregisterHotKey(0, 3);
            DbgPrint("[hotkey] step 3: UnregisterHotKey %d, again %d, the thread's %d\n", mine, again, thread);
        }
        window_hotkeys = thread_hotkeys = ctrl_deletes = 0;
        unregistered = 1;
        DbgPrint("[hotkey] unregistered\n");
        return 0;
    }
    return DefWindowProcW(window, message, w, l);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;
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
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);
    window = CreateWindowExW(0, CLASS_NAME, L"Hotkeys", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 300,
                             200, 200, 100, 0, 0, instance, 0);
    if (!window)
        ExitProcess(4);

    SetLastError(0);
    registration("step 1: Ctrl+Alt+Delete", RegisterHotKey(window, 0, MOD_CONTROL | MOD_ALT, VK_DELETE));
    registration("step 1: again", RegisterHotKey(window, 1, MOD_CONTROL | MOD_ALT, VK_DELETE));
    registration("step 1: MOD_NOREPEAT", RegisterHotKey(window, 2, MOD_NOREPEAT, 'Q'));
    registration("step 1: the desktop window", RegisterHotKey(GetDesktopWindow(), 4, MOD_ALT, 'Z'));
    registration("step 1: Ctrl+Shift+Esc for the thread", RegisterHotKey(0, 3, MOD_CONTROL | MOD_SHIFT, VK_ESCAPE));

    while (GetMessageW(&message, 0, 0, 0) > 0) {
        if (message.hwnd == 0 && message.message == WM_HOTKEY) {
            thread_hotkeys++;
            thread_id = message.wParam;
            thread_keys = message.lParam;
            continue;
        }
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[hotkey] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
