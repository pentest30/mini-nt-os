/*
 * The window menu (the system menu, win32k::sysmenu) and the activation of
 * a hidden window: a Win32 program (subsystem WINDOWS), compiled with MinGW
 * and linked to ReactOS's kernel32 and user32, which the scenario
 * `window-menu` puts on the boot disk in the place of winlogon.exe (like
 * minmax1.c). It takes a desktop like winlogon, loads the US keyboard
 * layout, and shows two overlapped windows, W at (100, 100, 400 x 300) and
 * B, then:
 * 1. W active, ShowWindow(W, SW_HIDE): B becomes active, the foreground
 *    window and takes the keyboard (co_WinPosShowWindow hands the activation
 *    over); SW_SHOW makes W active again;
 * 2. GetSystemMenu(W, FALSE): user32's SYSMENU, seven items from Restore to
 *    Close, the same handle each time, Restore with its glyph
 *    (HBMMENU_POPUP_RESTORE), Close the default item; GetSystemMenu(TRUE)
 *    gives none, the next one is new; none for a window without WS_SYSMENU;
 *    an item of the program's own appended (Min&o, 0x0110);
 * 3. QEMU types Alt+Space then n: the window menu opens (WM_INITMENUPOPUP,
 *    the high word of lParam TRUE, the menu GetSystemMenu gives), Minimize
 *    sends WM_SYSCOMMAND SC_MINIMIZE, and W is minimized; when the menu
 *    showed, Restore was grayed, not Minimize nor Maximize, Close the
 *    default;
 * 4. the mouse clicks the minimized W's icon (12, 786): its menu opens, and
 *    r restores it (when the menu showed, Minimize was grayed, Restore the
 *    default);
 * 5. the mouse clicks W's icon (112, 112): the menu opens under it, and x
 *    maximizes W;
 * 6. Alt+Space then o: the item of the program, WM_SYSCOMMAND 0x0110;
 * 7. a right click in the client area of the maximized W (400, 300):
 *    user32 sends WM_CONTEXTMENU (W, the point on the screen), and
 *    DefWindowProc opens no menu;
 * 8. a right click on its caption (400, 10) (WM_NCRBUTTONDOWN, the mouse
 *    held until the button is up, then WM_CONTEXTMENU): DefWindowProc opens
 *    the window menu there (its window at the point, WM_ENTERIDLE), and r
 *    restores W; when the menu showed, Maximize was grayed, Close the
 *    default (TrackPopupMenu sets a window menu as from the icon);
 * 9. a right click on the restored W's caption (250, 110): the menu opens
 *    there, and the right button chooses Maximize (TPM_RIGHTBUTTON);
 * 10. a double click on the maximized W's icon (9, 9) closes it (SC_CLOSE,
 *    WM_CLOSE, WM_DESTROY).
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; a "[sysmenu] keyboard:" or "[sysmenu] mouse:" line asks the
 * scenario for its keys or its mouse.
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
typedef void *HBITMAP;
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

typedef struct {
    UINT cbSize;
    UINT fMask;
    UINT fType;
    UINT fState;
    UINT wID;
    HMENU hSubMenu;
    HBITMAP hbmpChecked;
    HBITMAP hbmpUnchecked;
    DWORD dwItemData;
    WCHAR *dwTypeData;
    UINT cch;
    HBITMAP hbmpItem;
} MENUITEMINFOW;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_POPUP 0x80000000
#define WS_CAPTION 0x00C00000
#define WS_VISIBLE 0x10000000
#define SW_HIDE 0
#define SW_SHOW 5
#define WM_DESTROY 0x0002
#define WM_CONTEXTMENU 0x007B
#define WM_SYSCOMMAND 0x0112
#define WM_INITMENUPOPUP 0x0117
#define WM_ENTERIDLE 0x0121
#define MSGF_MENU 2
#define SC_MINIMIZE 0xF020
#define SC_MAXIMIZE 0xF030
#define SC_CLOSE 0xF060
#define SC_RESTORE 0xF120
#define SC_MOUSEMENU 0xF090
#define SC_KEYMENU 0xF100
#define MF_STRING 0x0000
#define MF_GRAYED 0x0001
#define MF_BYCOMMAND 0x0000
#define MIIM_BITMAP 0x0080
#define HBMMENU_POPUP_RESTORE 9
#define MINO_COMMAND 0x0110
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define EXIT_STATUS 0x7009

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);

__declspec(dllimport) BOOL __stdcall AppendMenuW(HMENU menu, UINT flags, UINT id, const WCHAR *text);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HWND __stdcall GetActiveWindow(void);
__declspec(dllimport) HWND __stdcall GetFocus(void);
__declspec(dllimport) HWND __stdcall GetForegroundWindow(void);
__declspec(dllimport) UINT __stdcall GetMenuDefaultItem(HMENU menu, UINT by_position, UINT flags);
__declspec(dllimport) int __stdcall GetMenuItemCount(HMENU menu);
__declspec(dllimport) UINT __stdcall GetMenuItemID(HMENU menu, int position);
__declspec(dllimport) BOOL __stdcall GetMenuItemRect(HWND window, HMENU menu, UINT item, RECT *rect);
__declspec(dllimport) BOOL __stdcall GetMenuItemInfoW(HMENU menu, UINT item, BOOL by_position, MENUITEMINFOW *info);
__declspec(dllimport) UINT __stdcall GetMenuState(HMENU menu, UINT id, UINT flags);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HMENU __stdcall GetSystemMenu(HWND window, BOOL revert);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall IsIconic(HWND window);
__declspec(dllimport) BOOL __stdcall IsZoomed(HWND window);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *klid, UINT flags);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetForegroundWindow(HWND window);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall ShowWindow(HWND window, int command);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

static HWND w, b;
/* The step whose WM_SYSCOMMAND W waits for (3 to 6, then 8 to 10), the
   window menus opened so far, the last one whose place was told, and the
   WM_CONTEXTMENU received. */
static int stage = 3, popups, placed, contexts;

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

/* Is the item grayed in W's window menu (as it was last shown)? */
static int grayed(UINT id)
{
    return (GetMenuState(GetSystemMenu(w, 0), id, MF_BYCOMMAND) & MF_GRAYED) != 0;
}

/* What W's window menu showed: the grayed items and the default one. */
static void shown(int step)
{
    DbgPrint("[sysmenu] step %d: the menu showed Restore grayed %d, Minimize grayed %d, Maximize grayed %d, "
             "default %x\n",
             step, grayed(SC_RESTORE), grayed(SC_MINIMIZE), grayed(SC_MAXIMIZE),
             GetMenuDefaultItem(GetSystemMenu(w, 0), 0, 0));
}

/* WM_SYSCOMMAND of W at each step, after DefWindowProc did it. */
static void command_done(UINT command)
{
    switch (stage) {
    case 3:
        DbgPrint("[sysmenu] step 3: WM_SYSCOMMAND %x, iconic %d, active B %d\n", command, IsIconic(w),
                 GetActiveWindow() == b);
        shown(3);
        DbgPrint("[sysmenu] mouse: the icon of the minimized W\n");
        break;
    case 4:
        DbgPrint("[sysmenu] step 4: WM_SYSCOMMAND %x, iconic %d, zoomed %d\n", command, IsIconic(w), IsZoomed(w));
        shown(4);
        DbgPrint("[sysmenu] mouse: the icon\n");
        break;
    case 5:
        DbgPrint("[sysmenu] step 5: WM_SYSCOMMAND %x, zoomed %d\n", command, IsZoomed(w));
        shown(5);
        DbgPrint("[sysmenu] keyboard: Alt+Space and o\n");
        break;
    case 6:
        DbgPrint("[sysmenu] step 6: WM_SYSCOMMAND %x, the item added\n", command);
        DbgPrint("[sysmenu] mouse: a right click in the client area\n");
        /* Step 7 has no command. */
        stage = 8;
        return;
    case 8:
        DbgPrint("[sysmenu] step 8: WM_SYSCOMMAND %x, zoomed %d\n", command, IsZoomed(w));
        shown(8);
        DbgPrint("[sysmenu] mouse: a right click on the restored caption\n");
        break;
    case 9:
        DbgPrint("[sysmenu] step 9: WM_SYSCOMMAND %x, zoomed %d\n", command, IsZoomed(w));
        DbgPrint("[sysmenu] mouse: a double click on the icon\n");
        break;
    default:
        break;
    }
    stage++;
}

/* WM_CONTEXTMENU of W: what DefWindowProc did with it (the window menus it
   opened, until it returned). */
static LRESULT context_menu(HWND window, WPARAM wp, LPARAM lp)
{
    int before = popups;
    LRESULT result = DefWindowProcW(window, WM_CONTEXTMENU, wp, lp);

    contexts++;
    DbgPrint("[sysmenu] step %d: WM_CONTEXTMENU W %d at (%d, %d), menus opened %d\n", contexts == 1 ? 7 : stage,
             (HWND)wp == w, (int)(short)(lp & 0xFFFF), (int)(short)((lp >> 16) & 0xFFFF), popups - before);
    if (contexts == 1)
        DbgPrint("[sysmenu] mouse: a right click on the caption\n");
    return result;
}

/* WM_ENTERIDLE of a window menu opened by a right click (steps 8 and 9),
   once it shows: where its window is, and Maximize in it (on the screen:
   GetMenuItemRect without a window takes the menu's). */
static void menu_shown(HWND popup)
{
    RECT place, maximize;

    if (placed == popups || (stage != 8 && stage != 9))
        return;
    placed = popups;
    GetWindowRect(popup, &place);
    if (!GetMenuItemRect(0, GetSystemMenu(w, 0), 4, &maximize))
        maximize.left = maximize.top = maximize.right = maximize.bottom = -1;
    DbgPrint("[sysmenu] step %d: the menu at (%d, %d); Maximize (%d, %d)-(%d, %d)\n", stage, place.left, place.top,
             maximize.left, maximize.top, maximize.right, maximize.bottom);
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    LRESULT result;

    if (window != w)
        return DefWindowProcW(window, message, wp, lp);
    switch (message) {
    case WM_INITMENUPOPUP:
        if ((lp >> 16) != 0) {
            popups++;
            DbgPrint("[sysmenu] popup %d: the window menu %d\n", popups, (HMENU)wp == GetSystemMenu(w, 0));
        }
        return 0;
    case WM_ENTERIDLE:
        if (wp == MSGF_MENU)
            menu_shown((HWND)lp);
        return 0;
    case WM_CONTEXTMENU:
        return context_menu(window, wp, lp);
    case WM_SYSCOMMAND:
        /* What opens the menu is not a step. */
        if ((wp & 0xFFF0) == SC_KEYMENU || (wp & 0xFFF0) == SC_MOUSEMENU)
            return DefWindowProcW(window, message, wp, lp);
        if (stage == 10) {
            DbgPrint("[sysmenu] step 10: WM_SYSCOMMAND %x\n", wp & 0xFFF0);
            return DefWindowProcW(window, message, wp, lp);
        }
        if (wp == MINO_COMMAND) {
            command_done(MINO_COMMAND);
            return 0;
        }
        result = DefWindowProcW(window, message, wp, lp);
        command_done(wp & 0xFFF0);
        return result;
    case WM_DESTROY:
        DbgPrint("[sysmenu] W destroyed\n");
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wp, lp);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    MENUITEMINFOW info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND n;
    HMENU sys, fresh;
    MSG message;
    int count;
    BOOL active, same, reverted, none;

    if (!take_a_desktop())
        ExitProcess(1);
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        ExitProcess(2);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = L"MinoSysMenu";
    if (!RegisterClassExW(&class_info))
        ExitProcess(3);
    w = CreateWindowExW(0, L"MinoSysMenu", L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, 0, instance,
                        0);
    b = CreateWindowExW(0, L"MinoSysMenu", L"B", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 600, 150, 300, 200, 0, 0,
                        instance, 0);
    /* Hidden, without a window menu. */
    n = CreateWindowExW(0, L"MinoSysMenu", L"N", WS_POPUP | WS_CAPTION, 700, 500, 100, 80, 0, 0, instance, 0);
    if (!w || !b || !n)
        ExitProcess(4);

    SetForegroundWindow(w);
    active = GetActiveWindow() == w;
    ShowWindow(w, SW_HIDE);
    DbgPrint("[sysmenu] step 1: W active %d; SW_HIDE: active B %d, foreground B %d, focus B %d\n", active,
             GetActiveWindow() == b, GetForegroundWindow() == b, GetFocus() == b);
    ShowWindow(w, SW_SHOW);
    DbgPrint("[sysmenu] step 1: SW_SHOW: active W %d\n", GetActiveWindow() == w);

    sys = GetSystemMenu(w, 0);
    count = GetMenuItemCount(sys);
    same = GetSystemMenu(w, 0) == sys;
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.fMask = MIIM_BITMAP;
    GetMenuItemInfoW(sys, SC_RESTORE, 0, &info);
    DbgPrint("[sysmenu] step 2: GetSystemMenu %d: %d items, %x to %x, the same %d; Restore's glyph %d, default %x\n",
             sys != 0, count, GetMenuItemID(sys, 0), GetMenuItemID(sys, count - 1), same,
             info.hbmpItem == (HBITMAP)HBMMENU_POPUP_RESTORE, GetMenuDefaultItem(sys, 0, 0));
    reverted = GetSystemMenu(w, 1) == 0;
    fresh = GetSystemMenu(w, 0);
    none = GetSystemMenu(n, 0) == 0;
    DbgPrint("[sysmenu] step 2: GetSystemMenu(TRUE) none %d, then a new one %d (%d items); without WS_SYSMENU none "
             "%d\n",
             reverted, fresh != 0, GetMenuItemCount(fresh), none);
    AppendMenuW(fresh, MF_STRING, MINO_COMMAND, L"Min&o");
    DbgPrint("[sysmenu] step 2: appended, %d items\n", GetMenuItemCount(GetSystemMenu(w, 0)));

    SetForegroundWindow(w);
    DbgPrint("[sysmenu] keyboard: Alt+Space and n\n");
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DbgPrint("[sysmenu] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
