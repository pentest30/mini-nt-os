/*
 * The arrows that leave a menu by its ends (MENU_DoNextMenu of ReactOS as
 * the specification, win32k::menutrack::do_next_menu): a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's kernel32
 * and user32, which the scenario `next-menu` puts on the boot disk in the
 * place of winlogon.exe (like sysmenu1.c). It takes a desktop like
 * winlogon, loads the US keyboard layout, and shows W, its bar File, Edit,
 * Help, and W2, its bar Other, then:
 * 1. QEMU types F10, left, down: from the first item of the bar, left goes
 *    to the window menu (WM_NEXTMENU VK_LEFT, the bar left), which down
 *    opens; Escape twice;
 * 2. Alt+Space opens the window menu; right goes to the bar and opens File
 *    (WM_NEXTMENU VK_RIGHT, the window menu left: GetSystemMenu's); left
 *    goes back and opens the window menu; left again goes to the last item
 *    of the bar, Help, and opens it; right goes to the window menu; Escape
 *    twice;
 * 3. F10, right, down: inside the bar, right moves to Edit, no WM_NEXTMENU;
 * 4. F10, left: W answers WM_NEXTMENU with W2 and its bar, so the tracking
 *    goes there; down opens Other (WM_INITMENUPOPUP to W2), k chooses its
 *    item (WM_COMMAND to W2);
 * 5. F10, left: W answers with W2 and GetSystemMenu(W2); down opens W2's
 *    window menu; Escape twice. Then W and W2 are destroyed.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; a "[nextmenu] keyboard:" line, or a popup of a step, asks the
 * scenario for its keys.
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

typedef struct {
    HMENU hmenuIn;
    HMENU hmenuNext;
    HWND hwndNext;
} MDINEXTMENU;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_VISIBLE 0x10000000
#define WM_DESTROY 0x0002
#define WM_COMMAND 0x0111
#define WM_INITMENUPOPUP 0x0117
#define WM_EXITMENULOOP 0x0212
#define WM_NEXTMENU 0x0213
#define VK_LEFT 0x25
#define MF_STRING 0x0000
#define MF_POPUP 0x0010
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define EXIT_STATUS 0x7009

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);

__declspec(dllimport) BOOL __stdcall AppendMenuW(HMENU menu, UINT flags, UINT id, const WCHAR *text);
__declspec(dllimport) HMENU __stdcall CreateMenu(void);
__declspec(dllimport) HMENU __stdcall CreatePopupMenu(void);
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
__declspec(dllimport) HMENU __stdcall GetMenu(HWND window);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HMENU __stdcall GetSystemMenu(HWND window, BOOL revert);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetForegroundWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetMenu(HWND window, HMENU menu);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static HWND w, w2;
static HMENU file, edit, help, other;
/* The step (1 to 5), the popups it opened, and the WM_NEXTMENU so far. */
static int step = 1, popups, nexts;

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

/* The name of a menu of W or W2, as the logs show it. */
static const char *name_of(HMENU menu)
{
    if (menu == file)
        return "File";
    if (menu == edit)
        return "Edit";
    if (menu == help)
        return "Help";
    if (menu == other)
        return "Other";
    if (menu == GetMenu(w))
        return "the bar";
    if (menu == GetSystemMenu(w, 0))
        return "the window menu";
    if (menu == GetSystemMenu(w2, 0))
        return "W2's window menu";
    return "another menu";
}

static void next_step(void)
{
    step++;
    popups = 0;
    DbgPrint("[nextmenu] keyboard: step %d\n", step);
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    MDINEXTMENU *next;

    if (window == w2) {
        if (message == WM_INITMENUPOPUP) {
            DbgPrint("[nextmenu] step %d: W2 popup: %s, system %d\n", step, name_of((HMENU)wp),
                     (int)((lp >> 16) & 0xFFFF));
            return 0;
        }
        if (message == WM_COMMAND) {
            DbgPrint("[nextmenu] step %d: W2 WM_COMMAND %x\n", step, wp & 0xFFFF);
            next_step();
            return 0;
        }
        return DefWindowProcW(window, message, wp, lp);
    }
    if (window != w)
        return DefWindowProcW(window, message, wp, lp);
    switch (message) {
    case WM_NEXTMENU:
        next = (MDINEXTMENU *)lp;
        nexts++;
        DbgPrint("[nextmenu] step %d: WM_NEXTMENU %d: %s, from %s\n", step, nexts, wp == VK_LEFT ? "left" : "right",
                 name_of(next->hmenuIn));
        if (step == 4) {
            next->hmenuNext = GetMenu(w2);
            next->hwndNext = w2;
        } else if (step == 5) {
            next->hmenuNext = GetSystemMenu(w2, 0);
            next->hwndNext = w2;
        }
        return 0;
    case WM_INITMENUPOPUP:
        popups++;
        DbgPrint("[nextmenu] step %d: popup %d: %s, system %d\n", step, popups, name_of((HMENU)wp),
                 (int)((lp >> 16) & 0xFFFF));
        return 0;
    case WM_EXITMENULOOP:
        DbgPrint("[nextmenu] step %d: the menu loop is over, WM_NEXTMENU so far %d\n", step, nexts);
        /* Step 4 ends with W2's WM_COMMAND, posted after the loop. */
        if (step < 4)
            next_step();
        else if (step == 5) {
            DestroyWindow(w2);
            DestroyWindow(w);
        }
        return 0;
    case WM_DESTROY:
        DbgPrint("[nextmenu] W destroyed\n");
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wp, lp);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HMENU bar, bar2;
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
    class_info.lpszClassName = L"MinoNextMenu";
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);

    file = CreatePopupMenu();
    edit = CreatePopupMenu();
    help = CreatePopupMenu();
    other = CreatePopupMenu();
    bar = CreateMenu();
    bar2 = CreateMenu();
    if (!file || !edit || !help || !other || !bar || !bar2)
        ExitProcess(4);
    AppendMenuW(file, MF_STRING, 0x101, L"&New");
    AppendMenuW(edit, MF_STRING, 0x201, L"&Copy");
    AppendMenuW(help, MF_STRING, 0x301, L"&About");
    AppendMenuW(other, MF_STRING, 0x401, L"O&k");
    AppendMenuW(bar, MF_POPUP, (UINT)file, L"&File");
    AppendMenuW(bar, MF_POPUP, (UINT)edit, L"&Edit");
    AppendMenuW(bar, MF_POPUP, (UINT)help, L"&Help");
    AppendMenuW(bar2, MF_POPUP, (UINT)other, L"&Other");

    w = CreateWindowExW(0, L"MinoNextMenu", L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0, instance,
                        0);
    w2 = CreateWindowExW(0, L"MinoNextMenu", L"W2", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 600, 150, 300, 200, 0, 0,
                         instance, 0);
    if (!w || !w2 || !SetMenu(w, bar) || !SetMenu(w2, bar2))
        ExitProcess(5);

    SetForegroundWindow(w);
    DbgPrint("[nextmenu] keyboard: step 1\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[nextmenu] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
