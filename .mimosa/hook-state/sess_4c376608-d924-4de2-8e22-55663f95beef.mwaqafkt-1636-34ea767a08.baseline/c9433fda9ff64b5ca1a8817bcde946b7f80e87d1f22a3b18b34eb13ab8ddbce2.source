/*
 * M5, console: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which the scenario `keyboard`
 * puts on the boot disk in the place of winlogon.exe (like `gui`, see
 * gui1.c). It takes a desktop like winlogon, loads the US keyboard layout
 * (LoadKeyboardLayoutW, as winlogon does), and opens a window, which
 * becomes the foreground window and gets the keyboard (WM_ACTIVATE,
 * WM_SETFOCUS). Once it is painted, it says it waits; the scenario then
 * types keys through QEMU's monitor (`keys =`), which the raw input thread
 * turns into WM_KEYDOWN and WM_KEYUP for the window, and TranslateMessage
 * into WM_CHAR. On Enter, it says what it was typed, with GetKeyState,
 * GetKeyboardState and ToUnicodeEx; then it takes the keyboard from its
 * window (SetFocus(NULL)): the next key is a system key (WM_SYSKEYDOWN)
 * for the active window, after which it gives the keyboard back and ends
 * with EXIT_STATUS. Each result goes to the debug port (DbgPrint), where
 * the scenario looks for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short ATOM;
typedef unsigned char BYTE;
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
#define WM_ACTIVATE 0x0006
#define WM_SETFOCUS 0x0007
#define WM_PAINT 0x000F
#define WM_KEYDOWN 0x0100
#define WM_KEYUP 0x0101
#define WM_CHAR 0x0102
#define WM_SYSKEYDOWN 0x0104
#define WM_SYSKEYUP 0x0105
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define VK_SHIFT 0x10
#define VK_RETURN 0x0D
#define EXIT_STATUS 0x600D

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
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) SHORT __stdcall GetAsyncKeyState(int key);
__declspec(dllimport) BOOL __stdcall GetKeyboardState(BYTE *state);
__declspec(dllimport) SHORT __stdcall GetKeyState(int key);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) HWND __stdcall SetFocus(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) int __stdcall ToUnicodeEx(UINT vk, UINT scan, const BYTE *state, WCHAR *buffer, int count,
                                                UINT flags, HKL layout);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static const WCHAR CLASS_NAME[] = L"MinoKeys";
static int painted;
/* Enter typed: the window no longer has the keyboard (SetFocus(NULL)). */
static int unfocused;
static char typed[64];
static unsigned typed_count;

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
    DbgPrint("[keys] on WinSta0\\Default\n");
    return 1;
}

/* What the thread's key state says on Enter (Shift is up), and a
   translation by ToUnicodeEx with Shift down. */
static void report(void)
{
    BYTE state[256];
    WCHAR chars[4] = {0, 0, 0, 0};
    int count;
    SHORT shift = GetKeyState(VK_SHIFT);
    SHORT enter = GetKeyState(VK_RETURN);
    SHORT async = GetAsyncKeyState('I');

    memset(state, 0, sizeof state);
    GetKeyboardState(state);
    DbgPrint("[keys] typed: %s; GetKeyState: Shift %04x, Enter %04x; GetAsyncKeyState(I) %04x; "
             "GetKeyboardState: Shift %02x, H %02x\n",
             typed, (unsigned short)shift, (unsigned short)enter, (unsigned short)async, state[VK_SHIFT],
             state['H']);
    state[VK_SHIFT] = 0x80;
    count = ToUnicodeEx('Q', 0x10, state, chars, 4, 0, 0);
    DbgPrint("[keys] ToUnicodeEx(Q, Shift): %d, %04x\n", count, chars[0]);
}

static LRESULT __stdcall keys_procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    PAINTSTRUCT paint;

    switch (message) {
    case WM_ACTIVATE:
        DbgPrint("[keys] WM_ACTIVATE %u\n", w);
        break;
    case WM_SETFOCUS:
        DbgPrint("[keys] WM_SETFOCUS\n");
        break;
    case WM_PAINT:
        BeginPaint(window, &paint);
        EndPaint(window, &paint);
        if (!painted)
            DbgPrint("[keys] waiting\n");
        painted = 1;
        return 0;
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
        DbgPrint("[keys] %s %02x %08lx\n",
                 message == WM_KEYDOWN   ? "down"
                 : message == WM_KEYUP   ? "up"
                 : message == WM_SYSKEYDOWN ? "sysdown"
                                         : "sysup",
                 w, l);
        /* Without the keyboard, a key is a system key for the active
           window (Enter's release too, if it comes after SetFocus); once
           A is released, the keyboard back, the program ends. */
        if (message == WM_SYSKEYUP && unfocused && w == 'A') {
            HWND before = SetFocus(window);
            DbgPrint("[keys] SetFocus(window): before it, %s\n", before ? "WRONG" : "none");
            PostQuitMessage(0);
        }
        return 0;
    case WM_CHAR:
        DbgPrint("[keys] char %02x %08lx; Shift %04x\n", w, l, (unsigned short)GetKeyState(VK_SHIFT));
        if (w == '\r') {
            HWND previous;
            report();
            previous = SetFocus(0);
            DbgPrint("[keys] SetFocus(NULL): before it, %s\n", previous == window ? "the window" : "WRONG");
            unfocused = 1;
            DbgPrint("[keys] unfocused\n");
        } else if (typed_count < sizeof typed - 1) {
            typed[typed_count++] = (char)w;
        }
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
    HKL layout;

    if (!take_a_desktop())
        ExitProcess(1);
    layout = LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE);
    DbgPrint("[keys] LoadKeyboardLayoutW: %s\n", layout ? "loaded" : "none");
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = keys_procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    window = CreateWindowExW(0, CLASS_NAME, L"Keys", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 300, 200,
                             200, 100, 0, 0, instance, 0);
    if (!window)
        ExitProcess(3);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[keys] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
