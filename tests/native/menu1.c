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
 *   submenus.
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
#define MF_ENABLED 0x0000
#define MF_UNCHECKED 0x0000
#define MIIM_STATE 0x0001
#define MIIM_ID 0x0002
#define MIIM_SUBMENU 0x0004
#define MIIM_STRING 0x0040
#define MIIM_FTYPE 0x0100
#define MIM_MENUDATA 0x0008
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
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);

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
    DbgPrint("[menu] on WinSta0\\Default\n");
    return 1;
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

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_APP) {
        read_back();
        change();
        windows();
        remove_and_load();
        DbgPrint("[menu] done\n");
        PostQuitMessage(0);
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
