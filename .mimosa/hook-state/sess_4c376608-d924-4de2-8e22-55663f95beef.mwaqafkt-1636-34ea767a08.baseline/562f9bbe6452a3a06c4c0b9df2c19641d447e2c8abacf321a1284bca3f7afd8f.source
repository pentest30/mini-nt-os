/*
 * comctl32's ListView: a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32 and user32, which the scenario
 * `listview` puts on the boot disk in the place of winlogon.exe (like
 * gui1.c). It takes a desktop like winlogon, loads comctl32 (whose
 * DllMain registers its classes), opens a parent window and, in it, a
 * ListView in report view (SysListView32, control id 100), as taskmgr's
 * process page does, then checks:
 * - SystemParametersInfo: SPI_GETNONCLIENTMETRICS (the message font,
 *   Tahoma of 8 points) and SPI_GETICONTITLELOGFONT (the ListView's default
 *   font);
 * - the ListView is created (its WM_CREATE loads uxtheme for OpenThemeData)
 *   and has a header;
 * - GetDlgItem finds it (user32 lists the parent's children:
 *   NtUserBuildHwndList), EnumChildWindows sees it and its header,
 *   EnumThreadWindows and EnumWindows the parent;
 * - a column and three items, read back;
 * - once painted: the ListView's background and the parent's.
 * Then it ends with EXIT_STATUS. Each result goes to the debug port
 * (DbgPrint), where the scenario looks for it.
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
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMODULE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HBRUSH;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL(__stdcall *WNDENUMPROC)(HWND, LPARAM);

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
    LONG lfHeight;
    LONG lfWidth;
    LONG lfEscapement;
    LONG lfOrientation;
    LONG lfWeight;
    BYTE lfItalic;
    BYTE lfUnderline;
    BYTE lfStrikeOut;
    BYTE lfCharSet;
    BYTE lfOutPrecision;
    BYTE lfClipPrecision;
    BYTE lfQuality;
    BYTE lfPitchAndFamily;
    WCHAR lfFaceName[32];
} LOGFONTW;

typedef struct {
    UINT cbSize;
    int iBorderWidth;
    int iScrollWidth;
    int iScrollHeight;
    int iCaptionWidth;
    int iCaptionHeight;
    LOGFONTW lfCaptionFont;
    int iSmCaptionWidth;
    int iSmCaptionHeight;
    LOGFONTW lfSmCaptionFont;
    int iMenuWidth;
    int iMenuHeight;
    LOGFONTW lfMenuFont;
    LOGFONTW lfStatusFont;
    LOGFONTW lfMessageFont;
} NONCLIENTMETRICSW;

typedef struct {
    UINT mask;
    int fmt;
    int cx;
    WCHAR *pszText;
    int cchTextMax;
    int iSubItem;
    int iImage;
    int iOrder;
} LVCOLUMNW;

typedef struct {
    UINT mask;
    int iItem;
    int iSubItem;
    UINT state;
    UINT stateMask;
    WCHAR *pszText;
    int cchTextMax;
    int iImage;
    LPARAM lParam;
    int iIndent;
} LVITEMW;

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define LVS_REPORT 0x0001
#define LVCF_WIDTH 0x0002
#define LVCF_TEXT 0x0004
#define LVIF_TEXT 0x0001
#define LVM_GETITEMCOUNT 0x1004
#define LVM_GETHEADER 0x101F
#define LVM_INSERTITEMW 0x104D
#define LVM_INSERTCOLUMNW 0x1061
#define LVM_GETITEMTEXTW 0x1073
#define SPI_GETICONTITLELOGFONT 0x001F
#define SPI_GETNONCLIENTMETRICS 0x0029
#define PM_REMOVE 0x0001
#define COLOR_BTNFACE 15
#define MAXIMUM_ALLOWED 0x02000000
#define EXIT_STATUS 0x7003

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) HMODULE __stdcall LoadLibraryW(const WCHAR *name);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) BOOL __stdcall EnumChildWindows(HWND parent, WNDENUMPROC procedure, LPARAM l);
__declspec(dllimport) BOOL __stdcall EnumThreadWindows(DWORD thread, WNDENUMPROC procedure, LPARAM l);
__declspec(dllimport) BOOL __stdcall EnumWindows(WNDENUMPROC procedure, LPARAM l);
__declspec(dllimport) HWND __stdcall GetDlgItem(HWND dialog, int id);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SystemParametersInfoW(UINT action, UINT param, void *pv, UINT win_ini);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG *message);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);

static HWND parent;
static HWND list;

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

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM w, LPARAM l)
{
    return DefWindowProcW(window, message, w, l);
}

/* Counts the windows an enumeration gives, and whether `list` was one. */
static int counted;
static int saw_list;

static BOOL __stdcall count(HWND window, LPARAM l)
{
    (void)l;
    counted++;
    if (window == list)
        saw_list = 1;
    return 1;
}

/* Whether `face` is Tahoma. */
static int is_tahoma(const WCHAR *face)
{
    const WCHAR *tahoma = L"Tahoma";
    while (*tahoma && *face == *tahoma)
        face++, tahoma++;
    return *tahoma == 0 && *face == 0;
}

static void system_parameters(void)
{
    NONCLIENTMETRICSW metrics;
    LOGFONTW font;
    BOOL got;

    memset(&metrics, 0, sizeof metrics);
    metrics.cbSize = sizeof metrics;
    got = SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof metrics, &metrics, 0);
    DbgPrint("[list] SPI_GETNONCLIENTMETRICS: %d, message font Tahoma %d, height %ld, caption weight %ld\n", got,
             is_tahoma(metrics.lfMessageFont.lfFaceName), metrics.lfMessageFont.lfHeight,
             metrics.lfCaptionFont.lfWeight);
    memset(&font, 0, sizeof font);
    got = SystemParametersInfoW(SPI_GETICONTITLELOGFONT, sizeof font, &font, 0);
    DbgPrint("[list] SPI_GETICONTITLELOGFONT: %d, Tahoma %d, height %ld\n", got, is_tahoma(font.lfFaceName),
             font.lfHeight);
}

static void items(void)
{
    static WCHAR column_name[] = L"Image";
    static WCHAR *names[] = {L"System", L"smss.exe", L"csrss.exe"};
    LVCOLUMNW column;
    LVITEMW item;
    WCHAR text[32];
    int i;

    memset(&column, 0, sizeof column);
    column.mask = LVCF_TEXT | LVCF_WIDTH;
    column.cx = 150;
    column.pszText = column_name;
    DbgPrint("[list] column inserted at %ld\n", SendMessageW(list, LVM_INSERTCOLUMNW, 0, (LPARAM)&column));
    for (i = 0; i < 3; i++) {
        memset(&item, 0, sizeof item);
        item.mask = LVIF_TEXT;
        item.iItem = i;
        item.pszText = names[i];
        SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)&item);
    }
    memset(&item, 0, sizeof item);
    memset(text, 0, sizeof text);
    item.iSubItem = 0;
    item.pszText = text;
    item.cchTextMax = 32;
    SendMessageW(list, LVM_GETITEMTEXTW, 1, (LPARAM)&item);
    DbgPrint("[list] items: %ld, the second %ls\n", SendMessageW(list, LVM_GETITEMCOUNT, 0, 0), text);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    MSG message;
    int i;

    if (!take_a_desktop())
        ExitProcess(1);
    system_parameters();
    DbgPrint("[list] comctl32 %s\n", LoadLibraryW(L"comctl32.dll") ? "loaded" : "missing");
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    class_info.lpszClassName = L"MinoList";
    if (!RegisterClassExW(&class_info))
        ExitProcess(2);
    parent = CreateWindowExW(0, L"MinoList", L"Processes", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 500, 300, 0,
                             0, instance, 0);
    if (!parent)
        ExitProcess(3);
    list = CreateWindowExW(0, L"SysListView32", L"", WS_CHILD | WS_VISIBLE | LVS_REPORT, 10, 10, 400, 200, parent,
                           (HMENU)100, instance, 0);
    DbgPrint("[list] ListView %s; header %s\n", list ? "created" : "missing",
             list && SendMessageW(list, LVM_GETHEADER, 0, 0) ? "present" : "missing");
    DbgPrint("[list] GetDlgItem(100) is the ListView: %d\n", list && GetDlgItem(parent, 100) == list);
    counted = saw_list = 0;
    EnumChildWindows(parent, count, 0);
    DbgPrint("[list] EnumChildWindows: %d, the ListView among them %d\n", counted, saw_list);
    counted = 0;
    EnumThreadWindows(GetCurrentThreadId(), count, 0);
    DbgPrint("[list] EnumThreadWindows: %d\n", counted);
    counted = 0;
    EnumWindows(count, 0);
    DbgPrint("[list] EnumWindows: %d\n", counted);
    if (list)
        items();
    UpdateWindow(parent);
    for (i = 0; i < 100; i++) {
        while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Sleep(20);
    }
    DbgPrint("[list] painted\n");
    Sleep(5000);
    ExitProcess(EXIT_STATUS);
    return 0;
}
