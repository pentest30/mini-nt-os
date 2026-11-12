/*
 * Menus that user32 reads itself: a Win32 program (subsystem WINDOWS),
 * compiled with MinGW and linked to ReactOS's kernel32 and user32, which the
 * scenario `menu` puts on the boot disk in the place of winlogon.exe (like
 * `caret`, see caret1.c). On WinSta0\Default, it builds a bar (File, Edit,
 * Help) and reads it back through user32, which finds the menus and their
 * items in the desktop's heap:
 * - IsMenu, GetMenuItemCount, GetSubMenu, GetMenuItemID, GetMenuState,
 *   GetMenuStringW, GetMenuItemInfoW;
 * - InsertMenuW by position and by identifier, ModifyMenuW, CheckMenuItem,
 *   CheckMenuRadioItem, EnableMenuItem, SetMenuDefaultItem and
 *   GetMenuDefaultItem, SetMenuContextHelpId, SetMenuInfo and GetMenuInfo;
 * - a window takes the bar (GetMenu), which no other window may take, nor a
 *   child; RemoveMenu keeps the submenu, DeleteMenu destroys it;
 *   LoadMenuIndirectW builds a menu from a template; DestroyMenu takes its
 *   submenus;
 * - TrackPopupMenuEx (win32k::menutrack): a popup menu (Open, a separator,
 *   Gray, Sub with Inner, Exit) in a window of the class #32768 that the
 *   owner W never activates; the keys the scenario types when "[menu]
 *   tracking N" shows (the owner writes it at its first WM_ENTERIDLE): the
 *   arrows, Enter, a letter; mouse messages that W posts to the menu's
 *   window, at the screen's coordinates; EndMenu; the notifications W hears;
 *   the rectangle a menu avoids; Sub's submenu opened by the mouse the
 *   scenario moves;
 * - the bar (win32k::menutrack::track_mouse_menu_bar, track_kbd_menu_bar):
 *   WM_NCHITTEST gives HTMENU over it; WM_NCLBUTTONDOWN on File opens its
 *   menu (SC_MOUSEMENU), which stays open after the release, closes when
 *   the mouse goes to Help, whose click posts WM_COMMAND; a second click
 *   on File closes the bar; WM_CANCELMODE ends it; the keys the scenario
 *   types at "[menu] keys N" (Alt, Alt+letter, F10, the arrows, Escape, a
 *   letter no item has) go through DefWindowProc to SC_KEYMENU; at last
 *   the real mouse clicks File, whose menu stays open for the scenario's
 *   capture of the screen, until a timer ends it.
 * Each step goes to the debug port (DbgPrint, a line each, its values taken
 * before); the program ends with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short WORD;
typedef unsigned short ATOM;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef unsigned long ULONG_PTR;
typedef int BOOL;
typedef long LONG;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HBITMAP;
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
    LONG x;
    LONG y;
} POINT;

typedef struct {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

typedef void *HDC;
typedef DWORD COLORREF;

typedef struct {
    DWORD cbSize;
    RECT rcBar;
    HMENU hMenu;
    HWND hwndMenu;
    DWORD focus; /* fBarFocused : 1, fFocused : 1 */
} MENUBARINFO;

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
    ULONG_PTR dwItemData;
    WCHAR *dwTypeData;
    UINT cch;
    HBITMAP hbmpItem;
} MENUITEMINFOW;

typedef struct {
    UINT cbSize;
    RECT rcExclude;
} TPMPARAMS;

typedef struct {
    DWORD cbSize;
    DWORD fMask;
    DWORD dwStyle;
    UINT cyMax;
    HBRUSH hbrBack;
    DWORD dwContextHelpID;
    ULONG_PTR dwMenuData;
} MENUINFO;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WM_APP 0x8000
#define COLOR_WINDOW 5
#define MAXIMUM_ALLOWED 0x02000000
#define MF_STRING 0x0000
#define MF_GRAYED 0x0001
#define MF_CHECKED 0x0008
#define MF_POPUP 0x0010
#define MF_END 0x0080
#define MF_BYCOMMAND 0x0000
#define MF_BYPOSITION 0x0400
#define MF_SEPARATOR 0x0800
#define MF_HELP 0x4000
#define MF_HILITE 0x0080
#define MF_UNHILITE 0x0000
#define OBJID_MENU (-3)
#define COLOR_MENU 4
#define COLOR_BTNSHADOW 16
#define MF_ENABLED 0x0000
#define MF_UNCHECKED 0x0000
#define MIIM_STATE 0x0001
#define MIIM_ID 0x0002
#define MIIM_SUBMENU 0x0004
#define MIIM_STRING 0x0040
#define MIIM_FTYPE 0x0100
#define MIM_MENUDATA 0x0008
#define WM_COMMAND 0x0111
#define WM_TIMER 0x0113
#define WM_INITMENU 0x0116
#define WM_INITMENUPOPUP 0x0117
#define WM_MENUSELECT 0x011F
#define WM_MENUCHAR 0x0120
#define WM_ENTERIDLE 0x0121
#define WM_UNINITMENUPOPUP 0x0125
#define WM_MOUSEMOVE 0x0200
#define WM_LBUTTONDOWN 0x0201
#define WM_LBUTTONUP 0x0202
#define WM_CANCELMODE 0x001F
#define WM_NCHITTEST 0x0084
#define WM_NCLBUTTONDOWN 0x00A1
#define HTMENU 5
#define WM_ENTERMENULOOP 0x0211
#define WM_EXITMENULOOP 0x0212
#define MN_GETHMENU 0x01E1
#define MSGF_MENU 2
#define MK_LBUTTON 1
#define PM_REMOVE 1
#define TPM_NONOTIFY 0x0080
#define TPM_RETURNCMD 0x0100
#define SM_CXDLGFRAME 7
#define COLOR_HIGHLIGHT 13
#define KLF_ACTIVATE 0x00000001
#define MAKELPARAM(low, high) ((LPARAM)(((high) << 16) | ((low)&0xFFFF)))
#define EXIT_STATUS 0x6014

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) BOOL __stdcall AppendMenuW(HMENU menu, UINT flags, ULONG_PTR id, const WCHAR *item);
__declspec(dllimport) DWORD __stdcall CheckMenuItem(HMENU menu, UINT item, UINT check);
__declspec(dllimport) BOOL __stdcall CheckMenuRadioItem(HMENU menu, UINT first, UINT last, UINT check, UINT flags);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HMENU __stdcall CreateMenu(void);
__declspec(dllimport) HMENU __stdcall CreatePopupMenu(void);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall DeleteMenu(HMENU menu, UINT position, UINT flags);
__declspec(dllimport) BOOL __stdcall DestroyMenu(HMENU menu);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EnableMenuItem(HMENU menu, UINT item, UINT enable);
__declspec(dllimport) HMENU __stdcall GetMenu(HWND window);
__declspec(dllimport) DWORD __stdcall GetMenuContextHelpId(HMENU menu);
__declspec(dllimport) UINT __stdcall GetMenuDefaultItem(HMENU menu, UINT by_position, UINT flags);
__declspec(dllimport) BOOL __stdcall GetMenuInfo(HMENU menu, MENUINFO *info);
__declspec(dllimport) int __stdcall GetMenuItemCount(HMENU menu);
__declspec(dllimport) UINT __stdcall GetMenuItemID(HMENU menu, int position);
__declspec(dllimport) BOOL __stdcall GetMenuItemInfoW(HMENU menu, UINT item, BOOL by_position, MENUITEMINFOW *info);
__declspec(dllimport) UINT __stdcall GetMenuState(HMENU menu, UINT item, UINT flags);
__declspec(dllimport) int __stdcall GetMenuStringW(HMENU menu, UINT item, WCHAR *text, int max, UINT flags);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT min, UINT max);
__declspec(dllimport) HMENU __stdcall GetSubMenu(HMENU menu, int position);
__declspec(dllimport) BOOL __stdcall InsertMenuW(HMENU menu, UINT position, UINT flags, ULONG_PTR id,
                                                 const WCHAR *item);
__declspec(dllimport) BOOL __stdcall IsMenu(HMENU menu);
__declspec(dllimport) HMENU __stdcall LoadMenuIndirectW(const void *template_);
__declspec(dllimport) BOOL __stdcall ModifyMenuW(HMENU menu, UINT position, UINT flags, ULONG_PTR id,
                                                 const WCHAR *item);
__declspec(dllimport) BOOL __stdcall PostMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) void __stdcall PostQuitMessage(int code);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall RemoveMenu(HMENU menu, UINT position, UINT flags);
__declspec(dllimport) BOOL __stdcall SetMenu(HWND window, HMENU menu);
__declspec(dllimport) BOOL __stdcall SetMenuContextHelpId(HMENU menu, DWORD id);
__declspec(dllimport) BOOL __stdcall SetMenuDefaultItem(HMENU menu, UINT item, UINT by_position);
__declspec(dllimport) BOOL __stdcall SetMenuInfo(HMENU menu, const MENUINFO *info);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall DrawMenuBar(HWND window);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall GetMenuBarInfo(HWND window, LONG object, LONG item, MENUBARINFO *info);
__declspec(dllimport) BOOL __stdcall GetMenuItemRect(HWND window, HMENU menu, UINT item, RECT *rect);
__declspec(dllimport) DWORD __stdcall GetSysColor(int index);
__declspec(dllimport) HDC __stdcall GetWindowDC(HWND window);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall HiliteMenuItem(HWND window, HMENU menu, UINT item, UINT hilite);
__declspec(dllimport) int __stdcall MenuItemFromPoint(HWND window, HMENU menu, POINT point);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC hdc);
__declspec(dllimport) COLORREF __stdcall GetPixel(HDC hdc, int x, int y);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall EndMenu(void);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) BOOL __stdcall IsWindow(HWND window);
__declspec(dllimport) BOOL __stdcall KillTimer(HWND window, ULONG_PTR id);
__declspec(dllimport) void *__stdcall LoadKeyboardLayoutW(const WCHAR *name, UINT flags);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) ULONG_PTR __stdcall SetTimer(HWND window, ULONG_PTR id, UINT elapse, void *procedure);
__declspec(dllimport) BOOL __stdcall TrackPopupMenu(HMENU menu, UINT flags, int x, int y, int reserved, HWND window,
                                                    const RECT *rect);
__declspec(dllimport) BOOL __stdcall TrackPopupMenuEx(HMENU menu, UINT flags, int x, int y, HWND window,
                                                      TPMPARAMS *params);

static const WCHAR CLASS_NAME[] = L"MinoMenu";
static HINSTANCE instance;
static HWND w;

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
    /* The keys the scenario types (a popup menu's tracking). */
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        return 0;
    DbgPrint("[menu] on WinSta0\\Default\n");
    return 1;
}

/* The popup menu that TrackPopupMenuEx shows (Open, a separator, Gray,
 * Sub with Inner, Exit), and what W hears while it is tracked. */
static HMENU pop, sub;
/* The bar and its menus (below). */
static HMENU bar, file, edit;
static struct {
    int run, announced, step;
    int enter, enter_popup, init, init_popups, selects, uninit, exits, idles, idle_flag;
    HMENU init_menu, popups[4];
    WPARAM last_select, menu_char;
    LPARAM last_select_menu;
    HWND popup;
    RECT popup_rect;
    int checks[6];
    int bar_focus;
    HWND bar_menu;
} track;

/* The middle of the item `position` of `menu` on the screen. */
static LPARAM item_middle(HMENU menu, UINT position)
{
    RECT rect;
    GetMenuItemRect(0, menu, position, &rect);
    return MAKELPARAM((rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2);
}

/* The colour at (x, y) of the screen, through the menu's window DC. */
static COLORREF popup_pixel(int x, int y)
{
    HDC hdc = GetWindowDC(track.popup);
    COLORREF color = GetPixel(hdc, x - track.popup_rect.left, y - track.popup_rect.top);
    ReleaseDC(track.popup, hdc);
    return color;
}

/* The pixels of the row `y` of `rect` (on the screen) that are (or are
 * not) `color`, through one window DC. */
static int count_in_row(RECT rect, int y, COLORREF color, BOOL equal)
{
    HDC hdc = GetWindowDC(track.popup);
    int x, count = 0;
    for (x = rect.left; x < rect.right; x++)
        if ((GetPixel(hdc, x - track.popup_rect.left, y - track.popup_rect.top) == color) == equal)
            count++;
    ReleaseDC(track.popup, hdc);
    return count;
}

/* The most pixels of `color` (or not of it) in a row of `rect`. */
static int most_in_a_row(RECT rect, COLORREF color, BOOL equal)
{
    int y, most = 0;
    for (y = rect.top; y < rect.bottom; y++) {
        int count = count_in_row(rect, y, color, equal);
        if (count > most)
            most = count;
    }
    return most;
}

/* GetMenuBarInfo of W's bar, item `item` (0: the bar): fBarFocused and
 * fFocused, and the window of the item's open menu. */
static void bar_info(LONG item)
{
    MENUBARINFO info;
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    GetMenuBarInfo(w, OBJID_MENU, item, &info);
    track.bar_focus = (int)(info.focus & 3);
    track.bar_menu = info.hwndMenu;
}

/* WM_ENTERIDLE: the menu waits for input. The first one of a run writes
 * the marker the scenario's keys wait for; the runs without keys act here,
 * a step each time the menu waits again. */
static void idle(WPARAM flag, HWND popup)
{
    RECT client, open, separator;

    track.idles++;
    if (!track.announced) {
        track.announced = 1;
        track.idle_flag = (int)flag;
        track.popup = popup;
        GetWindowRect(popup, &track.popup_rect);
        DbgPrint("[menu] tracking %d\n", track.run);
    }
    switch (track.run * 10 + track.step) {
    case 10:
        /* Shown where asked, its frame a dialog's, its menu MN_GETHMENU's;
         * a menu already shown is not shown twice. */
        GetClientRect(popup, &client);
        track.checks[0] = flag == MSGF_MENU && popup != 0;
        track.checks[1] = SendMessageW(popup, MN_GETHMENU, 0, 0) == (LRESULT)pop;
        track.checks[2] = track.popup_rect.left == 150 && track.popup_rect.top == 160;
        track.checks[3] = (track.popup_rect.right - track.popup_rect.left) - client.right ==
                          2 * GetSystemMetrics(SM_CXDLGFRAME);
        SetLastError(0);
        track.checks[4] = TrackPopupMenuEx(pop, 0, 10, 10, w, 0);
        track.checks[5] = (int)GetLastError();
        track.step++;
        break;
    case 30:
        /* The mouse over Open. */
        PostMessageW(track.popup, WM_MOUSEMOVE, 0, item_middle(pop, 0));
        track.step++;
        break;
    case 31:
        /* Open hilited (COLOR_HIGHLIGHT, its text drawn over it); the
         * separator an etched line. Then a click on Open. */
        GetMenuItemRect(0, pop, 0, &open);
        GetMenuItemRect(0, pop, 1, &separator);
        track.checks[0] = popup_pixel(open.left + 1, open.top + 1) == GetSysColor(COLOR_HIGHLIGHT);
        track.checks[1] = most_in_a_row(open, GetSysColor(COLOR_HIGHLIGHT), 0) > 5;
        track.checks[2] = most_in_a_row(separator, GetSysColor(COLOR_BTNSHADOW), 1) > (separator.right - separator.left) / 2;
        /* Over Sub: its submenu opens, to the right of the menu. */
        PostMessageW(track.popup, WM_MOUSEMOVE, 0, item_middle(pop, 3));
        track.step++;
        break;
    case 32:
        GetMenuItemRect(0, sub, 0, &open);
        track.checks[3] = track.init_popups == 2 && track.popups[1] == sub;
        track.checks[4] = open.left >= track.popup_rect.right - 2 * GetSystemMetrics(SM_CXDLGFRAME);
        /* Back on Open, clicked: Sub's submenu closes, Open is chosen. The
         * messages go to the first menu's window: WM_ENTERIDLE names the
         * submenu's, which its closing destroys, with its messages. */
        track.checks[5] = popup != track.popup;
        PostMessageW(track.popup, WM_MOUSEMOVE, 0, item_middle(pop, 0));
        PostMessageW(track.popup, WM_LBUTTONDOWN, MK_LBUTTON, item_middle(pop, 0));
        PostMessageW(track.popup, WM_LBUTTONUP, 0, item_middle(pop, 0));
        track.step++;
        break;
    case 40:
        /* EndMenu ends the tracking. */
        EndMenu();
        track.step++;
        break;
    case 50:
        /* The last menu: the scenario moves the mouse over Sub, whose
         * submenu opens, for the capture. */
        track.step++;
        break;
    case 51:
        if (track.init_popups < 2)
            break;
        GetMenuItemRect(0, pop, 3, &open);
        GetMenuItemRect(0, sub, 0, &separator);
        DbgPrint("[menu] the mouse's menu at %d,%d to %d,%d; Sub %d,%d to %d,%d; Inner %d,%d to %d,%d\n",
                 track.popup_rect.left, track.popup_rect.top, track.popup_rect.right, track.popup_rect.bottom,
                 open.left, open.top, open.right, open.bottom, separator.left, separator.top, separator.right,
                 separator.bottom);
        EndMenu();
        track.step++;
        break;
    case 60:
        /* The bar: File's menu opened by the button down on File. Released
         * there, it stays open. */
        bar_info(1);
        track.checks[0] = track.init_popups == 1 && track.popups[0] == file && track.enter_popup == 0;
        track.checks[1] = track.bar_focus;
        track.checks[2] = track.bar_menu != 0;
        PostMessageW(w, WM_LBUTTONUP, 0, item_middle(bar, 0));
        track.step++;
        break;
    case 61:
        /* Still open; over Help, it closes, Help is selected. */
        track.checks[3] = IsWindow(track.bar_menu);
        PostMessageW(w, WM_MOUSEMOVE, 0, item_middle(bar, 1));
        track.step++;
        break;
    case 62:
        /* File's menu gone (its window, from step 60), Help focused. */
        track.checks[4] = !IsWindow(track.bar_menu);
        bar_info(2);
        track.checks[4] = track.checks[4] && track.uninit == 1 && track.bar_focus == 3;
        PostMessageW(w, WM_LBUTTONDOWN, MK_LBUTTON, item_middle(bar, 1));
        PostMessageW(w, WM_LBUTTONUP, 0, item_middle(bar, 1));
        track.step++;
        break;
    case 70:
        /* A second click on File, open: the bar closes. */
        PostMessageW(w, WM_LBUTTONUP, 0, item_middle(bar, 0));
        PostMessageW(w, WM_LBUTTONDOWN, MK_LBUTTON, item_middle(bar, 0));
        PostMessageW(w, WM_LBUTTONUP, 0, item_middle(bar, 0));
        track.step++;
        break;
    case 80:
        /* WM_CANCELMODE to W ends the bar's tracking (DefWindowProc). */
        SendMessageW(w, WM_CANCELMODE, 0, 0);
        track.step++;
        break;
    case 140:
        /* The real mouse clicked File: its menu open under the bar, for
         * the capture, ended (EndMenu) a while after it. */
        if (track.init_popups < 1)
            break;
        bar_info(1);
        GetWindowRect(track.bar_menu, &open);
        DbgPrint("[menu] the bar clicked: File's menu %d, focused %d, at %d,%d to %d,%d\n",
                 track.popups[0] == file, track.bar_focus, open.left, open.top, open.right, open.bottom);
        DbgPrint("[menu] done\n");
        SetTimer(w, 1, 4000, 0);
        track.step++;
        break;
    }
}

/* A run of TrackPopupMenuEx: what W hears is counted from 0. */
static void begin(int run)
{
    memset(&track, 0, sizeof track);
    track.run = run;
}

/* No WM_COMMAND left in W's queue; the one posted otherwise, its wParam. */
static WPARAM posted_command(void)
{
    MSG message;
    if (!PeekMessageW(&message, w, WM_COMMAND, WM_COMMAND, PM_REMOVE))
        return 0;
    return message.wParam;
}

/* Messages to W, the way its loop gives them, until a tracking ends. */
static void pump_until_tracked(void)
{
    MSG message;
    while (!track.exits && GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

/* A tracking of the bar from the keys the scenario types at "[menu] keys
 * N": what W heard, and the WM_COMMAND posted. */
static void keyboard_run(int run)
{
    begin(run);
    DbgPrint("[menu] keys %d\n", run);
    pump_until_tracked();
    DbgPrint("[menu] keys %d: WM_COMMAND %d; ENTERMENULOOP %d %d, INITMENU %d, INITMENUPOPUP %d, UNINITMENUPOPUP %d, "
             "WM_MENUCHAR %x\n",
             run, (int)posted_command(), track.enter, track.enter_popup, track.init_menu == bar, track.init_popups,
             track.uninit, (unsigned)track.menu_char);
}

/* The bar (win32k::menutrack::track_mouse_menu_bar, track_kbd_menu_bar):
 * the mouse by messages, the keys, at last the real mouse. */
static void bar_runs(void)
{
    LPARAM file_middle = item_middle(bar, 0), help_middle = item_middle(bar, 1);
    LRESULT hit = SendMessageW(w, WM_NCHITTEST, 0, file_middle);
    LRESULT client = SendMessageW(w, WM_NCHITTEST, 0, MAKELPARAM(300, 300));
    DbgPrint("[menu] the bar: File at %ld,%ld, Help at %ld,%ld; WM_NCHITTEST %ld, in the client area %ld\n",
             (long)(file_middle & 0xFFFF), (long)(file_middle >> 16), (long)(help_middle & 0xFFFF),
             (long)(help_middle >> 16), (long)hit, (long)client);

    /* 6: a click on File opens its menu; over Help, Help is chosen. */
    begin(6);
    SendMessageW(w, WM_NCLBUTTONDOWN, HTMENU, file_middle);
    DbgPrint("[menu] the bar 6: File's menu %d, focused %d, its window %d, open after the release %d, "
             "Help after it %d; WM_COMMAND %d, EXITMENULOOP %d\n",
             track.checks[0], track.checks[1], track.checks[2], track.checks[3], track.checks[4],
             (int)posted_command(), track.exits);

    /* 7: a second click on File closes the bar. */
    begin(7);
    SendMessageW(w, WM_NCLBUTTONDOWN, HTMENU, file_middle);
    DbgPrint("[menu] the bar 7, clicked twice: WM_COMMAND %d, INITMENUPOPUP %d, UNINITMENUPOPUP %d, "
             "EXITMENULOOP %d\n",
             (int)posted_command(), track.init_popups, track.uninit, track.exits);

    /* 8: WM_CANCELMODE. */
    begin(8);
    SendMessageW(w, WM_NCLBUTTONDOWN, HTMENU, file_middle);
    DbgPrint("[menu] the bar 8, WM_CANCELMODE: WM_COMMAND %d, UNINITMENUPOPUP %d, EXITMENULOOP %d\n",
             (int)posted_command(), track.uninit, track.exits);

    /* 9 to 13: the keys. */
    keyboard_run(9);
    keyboard_run(10);
    keyboard_run(11);
    keyboard_run(12);
    keyboard_run(13);

    /* 14: the real mouse clicks File, left open for the capture. */
    begin(14);
    track.step = 0;
    DbgPrint("[menu] click the bar\n");
    pump_until_tracked();
}

static void popups(void)
{
    int result, error, menu_result, menu_error, params_result, params_error;
    TPMPARAMS params;
    HMENU empty;

    pop = CreatePopupMenu();
    sub = CreatePopupMenu();
    AppendMenuW(pop, MF_STRING, 201, L"&Open\tCtrl+O");
    AppendMenuW(pop, MF_SEPARATOR, 0, 0);
    AppendMenuW(pop, MF_STRING | MF_GRAYED, 202, L"&Gray");
    AppendMenuW(sub, MF_STRING, 301, L"&Inner");
    AppendMenuW(pop, MF_POPUP, (ULONG_PTR)sub, L"&Sub");
    AppendMenuW(pop, MF_STRING, 203, L"E&xit");

    /* What TrackPopupMenuEx refuses. */
    SetLastError(0);
    result = TrackPopupMenuEx(pop, 0x10000, 150, 160, w, 0);
    error = (int)GetLastError();
    SetLastError(0);
    menu_result = TrackPopupMenuEx((HMENU)0x1234, 0, 150, 160, w, 0);
    menu_error = (int)GetLastError();
    memset(&params, 0, sizeof params);
    params.cbSize = 16;
    SetLastError(0);
    params_result = TrackPopupMenuEx(pop, 0, 150, 160, w, &params);
    params_error = (int)GetLastError();
    DbgPrint("[menu] TrackPopupMenuEx refuses: a flag %d (%d), a menu %d (%d), a TPMPARAMS %d (%d)\n", result, error,
             menu_result, menu_error, params_result, params_error);
    empty = CreatePopupMenu();
    begin(0);
    result = TrackPopupMenuEx(empty, TPM_RETURNCMD, 150, 160, w, 0);
    DbgPrint("[menu] an empty menu: %d, notified %d %d %d %d %d, never waits %d\n", result, track.enter, track.init,
             track.init_popups, track.uninit, track.exits, track.idles == 0);
    DestroyMenu(empty);

    /* 1: down down down right Enter: Open, Gray (a separator skipped), Sub,
     * its submenu opened on Inner, chosen; TPM_RETURNCMD returns it. */
    begin(1);
    result = TrackPopupMenuEx(pop, TPM_RETURNCMD, 150, 160, w, 0);
    DbgPrint("[menu] tracked 1: MSGF_MENU %d, MN_GETHMENU %d, at 150,160 %d, a dialog's frame %d, again %d (%d)\n",
             track.checks[0], track.checks[1], track.checks[2], track.checks[3], track.checks[4], track.checks[5]);
    DbgPrint("[menu] TrackPopupMenuEx 1: %d; ENTERMENULOOP %d %d, INITMENU %d %d, INITMENUPOPUP %d %d %d, "
             "MENUSELECT %d %x %x, UNINITMENUPOPUP %d, EXITMENULOOP %d, its window gone %d, WM_COMMAND %d\n",
             result, track.enter, track.enter_popup, track.init, track.init_menu == pop, track.init_popups,
             track.popups[0] == pop, track.popups[1] == sub, track.selects, (unsigned)track.last_select,
             (unsigned)track.last_select_menu, track.uninit, track.exits, !IsWindow(track.popup),
             (int)posted_command());

    /* 2: Sub's submenu opened (right), closed (Escape), opened again,
     * closed (left): the tracking goes on; q (no item: WM_MENUCHAR,
     * ignored), then x: Exit, posted as WM_COMMAND (TrackPopupMenu, without
     * TPM_RETURNCMD). */
    begin(2);
    result = TrackPopupMenu(pop, 0, 150, 160, 0, w, 0);
    DbgPrint("[menu] TrackPopupMenu 2: %d; INITMENUPOPUP %d, UNINITMENUPOPUP %d, WM_MENUCHAR %x, WM_COMMAND %d\n",
             result, track.init_popups, track.uninit, (unsigned)track.menu_char, (int)posted_command());

    /* 3: the mouse, by the messages W posts to the menu's window. */
    begin(3);
    result = TrackPopupMenuEx(pop, TPM_RETURNCMD, 150, 160, w, 0);
    DbgPrint("[menu] TrackPopupMenuEx 3, the mouse: %d; Open hilited %d, its text %d, the separator %d; "
             "Sub opens %d, at the right %d, WM_ENTERIDLE names it %d\n",
             result, track.checks[0], track.checks[1], track.checks[2], track.checks[3], track.checks[4],
             track.checks[5]);

    /* 4: TPM_NONOTIFY, a rectangle to avoid (the menu goes to its right),
     * EndMenu. */
    begin(4);
    params.cbSize = sizeof params;
    params.rcExclude.left = 100;
    params.rcExclude.top = 150;
    params.rcExclude.right = 300;
    params.rcExclude.bottom = 250;
    result = TrackPopupMenuEx(pop, TPM_RETURNCMD | TPM_NONOTIFY, 150, 160, w, &params);
    DbgPrint("[menu] TrackPopupMenuEx 4, EndMenu: %d; at %d,%d; notified %d\n", result, track.popup_rect.left,
             track.popup_rect.top, track.enter + track.init + track.init_popups + track.uninit + track.exits);

    /* 5: the real mouse over Sub. */
    begin(5);
    result = TrackPopupMenuEx(pop, TPM_RETURNCMD, 150, 160, w, 0);

    bar_runs();
}

/* `text` in ASCII (what the test writes is ASCII), at most 31 characters. */
static const char *ascii(const WCHAR *text, char *out)
{
    int i;
    for (i = 0; i < 31 && text[i]; i++)
        out[i] = (char)text[i];
    out[i] = 0;
    return out;
}

static HMENU bar, file, edit;

/* The bar: File (New, Open, a separator, Exit after the insertions), Edit
 * (Undo, Cut, Copy), Help on the right. */
static void build(void)
{
    BOOL is_bar, is_file;
    int count;

    bar = CreateMenu();
    file = CreatePopupMenu();
    edit = CreatePopupMenu();
    is_bar = IsMenu(bar);
    is_file = IsMenu(file);
    count = GetMenuItemCount(bar);
    DbgPrint("[menu] CreateMenu: IsMenu %d %d, %d items\n", is_bar, is_file, count);
    AppendMenuW(file, MF_STRING, 101, L"&Open");
    AppendMenuW(file, MF_SEPARATOR, 0, 0);
    AppendMenuW(file, MF_STRING, 102, L"E&xit");
    AppendMenuW(bar, MF_POPUP, (ULONG_PTR)file, L"&File");
    AppendMenuW(edit, MF_STRING, 201, L"&Undo");
    AppendMenuW(edit, MF_STRING, 202, L"Cu&t");
    AppendMenuW(edit, MF_STRING, 203, L"&Copy");
    AppendMenuW(bar, MF_POPUP, (ULONG_PTR)edit, L"&Edit");
    AppendMenuW(bar, MF_STRING | MF_HELP, 300, L"&Help");
}

static void read_back(void)
{
    int bar_count = GetMenuItemCount(bar);
    int file_count = GetMenuItemCount(file);
    BOOL first = GetSubMenu(bar, 0) == file;
    BOOL second = GetSubMenu(bar, 1) == edit;
    BOOL third = GetSubMenu(bar, 2) == 0;
    UINT open = GetMenuItemID(file, 0);
    UINT separator = GetMenuItemID(file, 1);
    UINT popup = GetMenuItemID(bar, 0);
    UINT separator_state = GetMenuState(file, 1, MF_BYPOSITION);
    UINT popup_state = GetMenuState(bar, 0, MF_BYPOSITION);
    UINT exit_state = GetMenuState(bar, 102, MF_BYCOMMAND);
    UINT help_state = GetMenuState(bar, 300, MF_BYCOMMAND);
    WCHAR text[32];
    WCHAR other[32];
    char a[32], b[32];
    int length = GetMenuStringW(bar, 0, text, 32, MF_BYPOSITION);
    int exit_length = GetMenuStringW(bar, 102, other, 32, MF_BYCOMMAND);
    MENUITEMINFOW info;
    BOOL got;

    DbgPrint("[menu] items: bar %d, File %d; GetSubMenu: File %d, Edit %d, Help none %d\n", bar_count, file_count,
             first, second, third);
    DbgPrint("[menu] GetMenuItemID: %u %u %d\n", open, separator, (int)popup);
    DbgPrint("[menu] GetMenuState: separator %x, File popup %x, Exit by command %x, Help %x\n", separator_state,
             popup_state, exit_state, help_state);
    DbgPrint("[menu] GetMenuStringW: %s %d, by command %s %d\n", ascii(text, a), length, ascii(other, b),
             exit_length);
    memset(&info, 0, sizeof info);
    memset(text, 0, sizeof text);
    info.cbSize = sizeof info;
    info.fMask = MIIM_ID | MIIM_SUBMENU | MIIM_STRING | MIIM_FTYPE | MIIM_STATE;
    info.dwTypeData = text;
    info.cch = 32;
    got = GetMenuItemInfoW(bar, 1, 1, &info);
    DbgPrint("[menu] GetMenuItemInfoW %d: submenu Edit %d, id %d, text %s %u, type %x, state %x\n", got,
             info.hSubMenu == edit, info.wID == (UINT)(ULONG_PTR)edit, ascii(text, a), info.cch, info.fType,
             info.fState);
}

static void change(void)
{
    UINT ids[5];
    int i;
    WCHAR text[32];
    char a[32];
    DWORD checked, unchecked, again;
    BOOL radio;
    UINT radio_state, undo_state;
    UINT grayed, enabled, missing;
    BOOL set;
    UINT by_id, by_position;
    MENUINFO info;
    DWORD help;
    BOOL got;

    InsertMenuW(file, 102, MF_BYCOMMAND | MF_STRING, 103, L"&Save");
    InsertMenuW(file, 0, MF_BYPOSITION | MF_STRING, 100, L"&New");
    for (i = 0; i < 5; i++)
        ids[i] = GetMenuItemID(file, i);
    DbgPrint("[menu] InsertMenuW: %u %u %u %u %u\n", ids[0], ids[1], ids[2], ids[3], ids[4]);

    ModifyMenuW(file, 103, MF_BYCOMMAND | MF_STRING, 104, L"Save &As");
    GetMenuStringW(file, 3, text, 32, MF_BYPOSITION);
    ids[0] = GetMenuItemID(file, 3);
    DbgPrint("[menu] ModifyMenuW: %u %s\n", ids[0], ascii(text, a));

    checked = CheckMenuItem(file, 101, MF_CHECKED);
    again = GetMenuState(file, 101, MF_BYCOMMAND) & MF_CHECKED;
    unchecked = CheckMenuItem(file, 101, MF_UNCHECKED);
    radio = CheckMenuRadioItem(edit, 201, 203, 202, MF_BYCOMMAND);
    radio_state = GetMenuState(edit, 202, MF_BYCOMMAND);
    undo_state = GetMenuState(edit, 201, MF_BYCOMMAND);
    DbgPrint("[menu] CheckMenuItem: %lu %lu %lu; CheckMenuRadioItem %d: %x, Undo %x\n", checked, again, unchecked,
             radio, radio_state, undo_state);

    /* By command from the bar: win32k finds 104 in File (user32 gives it
     * the bar as it is). */
    grayed = EnableMenuItem(bar, 104, MF_GRAYED);
    enabled = EnableMenuItem(bar, 104, MF_ENABLED);
    missing = EnableMenuItem(file, 999, MF_ENABLED);
    DbgPrint("[menu] EnableMenuItem: %u %u %d\n", grayed, enabled, (int)missing);

    set = SetMenuDefaultItem(file, 101, 0);
    by_id = GetMenuDefaultItem(file, 0, 0);
    by_position = GetMenuDefaultItem(file, 1, 0);
    DbgPrint("[menu] default item %d: %u at %u\n", set, by_id, by_position);

    SetMenuContextHelpId(bar, 77);
    help = GetMenuContextHelpId(bar);
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.fMask = MIM_MENUDATA;
    info.dwMenuData = 0x1234;
    SetMenuInfo(bar, &info);
    info.dwMenuData = 0;
    got = GetMenuInfo(bar, &info);
    DbgPrint("[menu] help %lu, data %d %lx\n", help, got, info.dwMenuData);
}

static void windows(void)
{
    HWND other = CreateWindowExW(0, CLASS_NAME, L"O", WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, 0, 0, instance, 0);
    HWND child = CreateWindowExW(0, CLASS_NAME, L"C", WS_CHILD, 0, 0, 20, 20, w, (HMENU)5, instance, 0);
    BOOL got = GetMenu(w) == bar;
    BOOL taken, of_child;
    DWORD taken_error, child_error;

    SetLastError(0);
    taken = SetMenu(other, bar);
    taken_error = GetLastError();
    SetLastError(0);
    of_child = SetMenu(child, edit);
    child_error = GetLastError();
    DbgPrint("[menu] GetMenu %d; SetMenu of another window's bar: %d (%lu), of a child: %d (%lu)\n", got, taken,
             taken_error, of_child, child_error);
}

static void remove_and_load(void)
{
    BOOL removed = RemoveMenu(bar, 1, MF_BYPOSITION);
    int count = GetMenuItemCount(bar);
    BOOL lives = IsMenu(edit);
    BOOL deleted;
    BOOL gone;
    /* MENUITEMTEMPLATEHEADER (version 0, offset 0), then POPUP "&View"
     * (MF_POPUP | MF_END) { "&Big" 401, "&Small" 402 (MF_END) }. */
    static const WORD template_[] = {
        0,         0,         MF_POPUP | MF_END, '&', 'V', 'i', 'e', 'w', 0, 0, 401, '&', 'B', 'i', 'g', 0, MF_END,
        402,       '&',       'S',               'm', 'a', 'l', 'l', 0,
    };
    HMENU loaded;
    HMENU view;
    int loaded_count, view_count;
    UINT small;
    WCHAR text[32];
    char a[32];
    BOOL destroyed, loaded_gone, view_gone;

    AppendMenuW(bar, MF_POPUP, (ULONG_PTR)edit, L"&Edit");
    deleted = DeleteMenu(bar, (UINT)(ULONG_PTR)edit, MF_BYCOMMAND);
    gone = !IsMenu(edit);
    DbgPrint("[menu] RemoveMenu %d: %d items, Edit lives %d; DeleteMenu %d: Edit gone %d\n", removed, count, lives,
             deleted, gone);

    loaded = LoadMenuIndirectW(template_);
    view = GetSubMenu(loaded, 0);
    loaded_count = GetMenuItemCount(loaded);
    view_count = GetMenuItemCount(view);
    small = GetMenuItemID(view, 1);
    GetMenuStringW(view, 402, text, 32, MF_BYCOMMAND);
    DbgPrint("[menu] LoadMenuIndirectW: %d item, View %d items, %u %s\n", loaded_count, view_count, small,
             ascii(text, a));
    destroyed = DestroyMenu(loaded);
    loaded_gone = !IsMenu(loaded);
    view_gone = !IsMenu(view);
    DbgPrint("[menu] DestroyMenu %d: gone %d, its submenu gone %d\n", destroyed, loaded_gone, view_gone);
}

/* The colour at (x, y) of W, on the screen (its window DC). */
static COLORREF window_pixel(int x, int y)
{
    HDC hdc = GetWindowDC(w);
    COLORREF color = GetPixel(hdc, x, y);
    ReleaseDC(w, hdc);
    return color;
}

/* The pixels inside `rect` (on the screen, without its edge) that are not
 * `background`: the text, smoothed. */
static int count_pixels(const RECT *rect, RECT window, COLORREF background)
{
    int x, y, count = 0;
    for (y = rect->top + 1; y < rect->bottom - 1; y++)
        for (x = rect->left + 1; x < rect->right - 1; x++)
            if (window_pixel(x - window.left, y - window.top) != background)
                count++;
    return count;
}

/* W's bar (File, Edit, Help): between its caption and its client area, the
 * items from its left, Help on its right; MenuItemFromPoint, HiliteMenuItem
 * on the screen, DrawMenuBar after a longer title. */
static void bar_checks(void)
{
    MENUBARINFO info, item_info;
    RECT window, client, file_rect, edit_rect, help_rect, moved;
    POINT middle, outside;
    BOOL got, item_got, file_got, edit_got, help_got, same, stays;
    int height, border, client_top, at_edit, away, text, hilited, sunken, flat;
    UINT state, after;

    GetWindowRect(w, &window);
    GetClientRect(w, &client);
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    got = GetMenuBarInfo(w, OBJID_MENU, 0, &info);
    file_got = GetMenuItemRect(w, bar, 0, &file_rect);
    edit_got = GetMenuItemRect(w, bar, 1, &edit_rect);
    help_got = GetMenuItemRect(w, bar, 2, &help_rect);
    height = info.rcBar.bottom - info.rcBar.top;
    /* The frame is as thick at the bottom as on the right. */
    border = window.right - info.rcBar.right;
    client_top = window.bottom - border - (client.bottom - client.top);
    DbgPrint("[menu] GetMenuBarInfo %d: menu %d, %d high, the frame's width each side %d, the client area under it "
             "%d\n",
             got, info.hMenu == bar, height, info.rcBar.left - window.left == border, info.rcBar.bottom == client_top);
    DbgPrint("[menu] GetMenuItemRect %d %d %d: File at the bar's left %d, Edit after it %d, Help at its right %d, "
             "%d high\n",
             file_got, edit_got, help_got, file_rect.left == info.rcBar.left, edit_rect.left == file_rect.right,
             help_rect.right == info.rcBar.right, file_rect.bottom - file_rect.top);
    memset(&item_info, 0, sizeof item_info);
    item_info.cbSize = sizeof item_info;
    item_got = GetMenuBarInfo(w, OBJID_MENU, 2, &item_info);
    same = item_info.rcBar.left == edit_rect.left && item_info.rcBar.top == edit_rect.top && item_info.rcBar.right == edit_rect.right &&
           item_info.rcBar.bottom == edit_rect.bottom;
    middle.x = (edit_rect.left + edit_rect.right) / 2;
    middle.y = (edit_rect.top + edit_rect.bottom) / 2;
    outside.x = window.left + 1;
    outside.y = window.bottom - 2;
    at_edit = MenuItemFromPoint(w, bar, middle);
    away = MenuItemFromPoint(w, bar, outside);
    DbgPrint("[menu] GetMenuBarInfo of Edit %d: its rectangle %d; MenuItemFromPoint: Edit %d, elsewhere %d\n",
             item_got, same, at_edit, away);

    text = count_pixels(&file_rect, window, GetSysColor(COLOR_MENU));
    HiliteMenuItem(w, bar, 0, MF_BYPOSITION | MF_HILITE);
    state = GetMenuState(bar, 0, MF_BYPOSITION) & MF_HILITE;
    sunken = window_pixel(file_rect.left - window.left, file_rect.top - window.top) == GetSysColor(COLOR_BTNSHADOW);
    hilited = count_pixels(&file_rect, window, GetSysColor(COLOR_MENU));
    HiliteMenuItem(w, bar, 0, MF_BYPOSITION | MF_UNHILITE);
    after = GetMenuState(bar, 0, MF_BYPOSITION) & MF_HILITE;
    flat = window_pixel(file_rect.left - window.left, file_rect.top - window.top) == GetSysColor(COLOR_MENU);
    DbgPrint("[menu] the text of File drawn %d; HiliteMenuItem: %x, sunken %d, text %d; unlit: %x, flat %d\n",
             text > 20, state, sunken, hilited > 20, after, flat);

    ModifyMenuW(bar, 0, MF_BYPOSITION | MF_STRING, (ULONG_PTR)file, L"&Fichier");
    GetMenuItemRect(w, bar, 1, &moved);
    stays = moved.left == edit_rect.left;
    DrawMenuBar(w);
    GetMenuItemRect(w, bar, 1, &moved);
    DbgPrint("[menu] ModifyMenuW: Edit stays %d until DrawMenuBar, then moves right %d\n", stays,
             moved.left > edit_rect.left);
}

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_APP:
        read_back();
        change();
        windows();
        bar_checks();
        remove_and_load();
        popups();
        PostQuitMessage(0);
        return 0;
    case WM_ENTERMENULOOP:
        track.enter++;
        track.enter_popup = (int)wparam;
        return 0;
    case WM_INITMENU:
        track.init++;
        track.init_menu = (HMENU)wparam;
        return 0;
    case WM_INITMENUPOPUP:
        if (track.init_popups < 4)
            track.popups[track.init_popups] = (HMENU)wparam;
        track.init_popups++;
        return 0;
    case WM_MENUSELECT:
        track.selects++;
        track.last_select = wparam;
        track.last_select_menu = lparam;
        return 0;
    case WM_UNINITMENUPOPUP:
        track.uninit++;
        return 0;
    case WM_EXITMENULOOP:
        track.exits++;
        return 0;
    case WM_MENUCHAR:
        /* MNC_IGNORE. */
        track.menu_char = wparam;
        return 0;
    case WM_ENTERIDLE:
        idle(wparam, (HWND)lparam);
        return 0;
    case WM_TIMER:
        KillTimer(window, wparam);
        EndMenu();
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    MSG message;

    instance = GetModuleHandleW(0);
    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    build();
    w = CreateWindowExW(0, CLASS_NAME, L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 400, 300, 0, bar, instance,
                        0);
    if (!w)
        ExitProcess(3);
    PostMessageW(w, WM_APP, 0, 0);
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    /* Its windows go with the process: the scenario captures the screen
     * meanwhile. */
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
