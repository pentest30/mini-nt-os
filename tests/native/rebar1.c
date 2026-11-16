/*
 * The address bar of explorer's folder window: comctl32's ReBar with a
 * ComboBoxEx band titled "Address" (as browseui's CDockSite::GetRBBandInfo
 * makes it) after two toolbar bands. A Win32 program (subsystem WINDOWS),
 * compiled with MinGW and linked to ReactOS's kernel32 and user32, which
 * takes the place of winlogon.exe.
 *
 * comctl32 of ReactOS asks SPI_GETNONCLIENTMETRICS with Vista's 504 bytes;
 * refused, the ReBar made its font of garbage, its band's header was
 * millions of pixels wide and the ReBar 32767 high: the folder view went
 * off the window. Logs SPI_GETNONCLIENTMETRICS of 500, 504 and 503 bytes,
 * the ReBar's font and the band's place, and GetComboBoxInfo, which the
 * address bar asks.
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

typedef struct {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    void *hCursor;
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
    UINT cbSize;
    UINT fMask;
    UINT fStyle;
    DWORD clrFore;
    DWORD clrBack;
    WCHAR *lpText;
    UINT cch;
    int iImage;
    HWND hwndChild;
    UINT cxMinChild;
    UINT cyMinChild;
    UINT cx;
    void *hbmBack;
    UINT wID;
    UINT cyChild;
    UINT cyMaxChild;
    UINT cyIntegral;
    UINT cxIdeal;
    LPARAM lParam;
    UINT cxHeader;
    RECT rcChevronLocation;
    UINT uChevronState;
} REBARBANDINFOW;

#define WS_CHILD 0x40000000
#define WS_VISIBLE 0x10000000
#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define MAXIMUM_ALLOWED 0x02000000
#define WM_USER 0x0400
#define RB_GETRECT (WM_USER + 9)
#define RB_INSERTBANDW (WM_USER + 10)
#define RBBIM_STYLE 0x0001
#define RBBIM_TEXT 0x0004
#define RBBIM_CHILD 0x0010
#define RBBIM_CHILDSIZE 0x0020
#define RBBIM_ID 0x0100
#define RBBIM_IDEALSIZE 0x0200
#define RBBIM_LPARAM 0x0400
#define RBBS_BREAK 0x0001
#define RBBS_FIXEDBMP 0x0020
#define SPI_GETNONCLIENTMETRICS 0x0029
#define EXIT_STATUS 0x6017

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) HMODULE __stdcall LoadLibraryW(const WCHAR *name);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);
__declspec(dllimport) BOOL __stdcall SystemParametersInfoW(UINT action, UINT param, void *data, UINT win_ini);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *class_name, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     HMENU menu, HINSTANCE instance, void *param);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall DestroyWindow(HWND window);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall GetComboBoxInfo(HWND window, void *info);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) void *__stdcall GetDC(HWND window);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, void *hdc);
__declspec(dllimport) void *__stdcall SelectObject(void *hdc, void *object);
__declspec(dllimport) int __stdcall GetObjectW(void *object, int size, void *buffer);
__declspec(dllimport) BOOL __stdcall GetTextExtentPoint32W(void *hdc, const WCHAR *text, int count, void *size);
__declspec(dllimport) LRESULT __stdcall SendMessageW(HWND window, UINT message, WPARAM w, LPARAM l);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static const WCHAR CLASS_NAME[] = L"MinoRebar";

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

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

/* A band of `child`, as CDockSite::GetRBBandInfo makes it. */
static void insert(HWND rebar, HWND child, UINT style, UINT id, WCHAR *text, UINT min_x, UINT min_y)
{
    REBARBANDINFOW band;
    memset(&band, 0, sizeof band);
    band.cbSize = sizeof band;
    band.fMask = RBBIM_LPARAM | RBBIM_IDEALSIZE | RBBIM_ID | RBBIM_CHILDSIZE | RBBIM_CHILD | RBBIM_TEXT | RBBIM_STYLE;
    band.fStyle = style;
    band.lpText = text;
    band.cch = 40;
    band.hwndChild = child;
    band.cxMinChild = min_x;
    band.cyMinChild = min_y;
    band.wID = id;
    band.cyChild = min_y;
    band.cxIdeal = min_x;
    SendMessageW(rebar, RB_INSERTBANDW, (WPARAM)-1, (LPARAM)&band);
}

static void variant(HWND parent, HINSTANCE instance, const char *name, UINT style)
{
    static WCHAR empty[] = L"";
    static WCHAR address[] = L"Address";
    HWND rebar = CreateWindowExW(0x80, L"ReBarWindow32", L"", 0x5680b649, 0, 0, 700, 60, parent, 0, instance, 0);
    HWND tools = CreateWindowExW(0, L"ToolbarWindow32", L"", WS_CHILD | WS_VISIBLE | 0x94c, 0, 0, 0, 0, rebar, 0,
                                 instance, 0);
    HWND links = CreateWindowExW(0, L"ToolbarWindow32", L"", WS_CHILD | WS_VISIBLE | 0x94c, 0, 0, 0, 0, rebar, 0,
                                 instance, 0);
    HWND combo = CreateWindowExW(0x80, L"ComboBoxEx32", L"", 0x52010052, 0, 0, 500, 250, rebar, 0, instance, 0);
    RECT bar, band, child;

    insert(rebar, tools, RBBS_FIXEDBMP, 1, empty, 400, 19);
    insert(rebar, links, RBBS_FIXEDBMP | RBBS_BREAK, 2, empty, 400, 30);
    insert(rebar, combo, style, 3, address, 100, 22);
    memset(&band, 0, sizeof band);
    SendMessageW(rebar, RB_GETRECT, 2, (LPARAM)&band);
    GetWindowRect(rebar, &bar);
    GetWindowRect(combo, &child);
    DbgPrint("[rebar] %s: band %ld %ld %ld %ld, the combo at %ld %ld, %ld x %ld, the bar %ld high\n", name, band.left,
             band.top, band.right, band.bottom, child.left - bar.left, child.top - bar.top, child.right - child.left,
             child.bottom - child.top, bar.bottom - bar.top);
    DestroyWindow(rebar);
}

/* The ReBar's font (REBAR_Create: lfMenuFont of SPI_GETNONCLIENTMETRICS)
 * and what it measures of the band's title. */
static void rebar_font(HWND parent, HINSTANCE instance)
{
    HWND rebar = CreateWindowExW(0x80, L"ReBarWindow32", L"", 0x5680b649, 0, 0, 700, 60, parent, 0, instance, 0);
    void *font = (void *)SendMessageW(rebar, 0x31 /* WM_GETFONT */, 0, 0);
    void *hdc = GetDC(0);
    void *old = SelectObject(hdc, font);
    LONG size[2] = {0, 0};
    LONG logfont[23];
    BOOL measured = GetTextExtentPoint32W(hdc, L"Address", 7, (void *)size);
    int got = GetObjectW(font, sizeof logfont, logfont);
    SelectObject(hdc, old);
    ReleaseDC(0, hdc);
    DbgPrint("[rebar] its font: LOGFONT %d bytes, height %ld; \"Address\" %d, %ld x %ld\n", got, logfont[0], measured,
             size[0], size[1]);
    DestroyWindow(rebar);
}

/* SPI_GETNONCLIENTMETRICS with XP's NONCLIENTMETRICSW (500 bytes), Vista's
 * (504: iPaddedBorderWidth after it, which comctl32 of ReactOS has), and a
 * size neither is. */
static void non_client_metrics(void)
{
    static DWORD metrics[126];
    BOOL xp, vista, odd;
    DWORD odd_error;

    memset(metrics, 0x77, sizeof metrics);
    metrics[0] = 500;
    xp = SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, 500, metrics, 0);
    DbgPrint("[rebar] SPI_GETNONCLIENTMETRICS of 500 bytes: %d, cbSize %lu, lfMenuFont height %ld, after it %lx\n", xp,
             metrics[0], (long)metrics[224 / 4], metrics[125]);
    memset(metrics, 0x77, sizeof metrics);
    metrics[0] = 504;
    vista = SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, 504, metrics, 0);
    DbgPrint("[rebar] SPI_GETNONCLIENTMETRICS of 504 bytes: %d, cbSize %lu, iPaddedBorderWidth %lu\n", vista,
             metrics[0], metrics[125]);
    memset(metrics, 0x77, sizeof metrics);
    metrics[0] = 503;
    SetLastError(0);
    odd = SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, 503, metrics, 0);
    odd_error = GetLastError();
    DbgPrint("[rebar] SPI_GETNONCLIENTMETRICS of 503 bytes: %d (%lu)\n", odd, odd_error);
}

/* GetComboBoxInfo of a ComboBox of user32 (CBS_DROPDOWN): CB_GETCOMBOBOXINFO
 * to the control, which fills COMBOBOXINFO (52 bytes: its parts, then the
 * combo box, its edit and its list); refused with a cbSize too small. The
 * address bar and the Run box ask it. */
static void combo_box_info(HWND parent, HINSTANCE instance)
{
    HWND combo = CreateWindowExW(0, L"ComboBox", L"", WS_CHILD | WS_VISIBLE | 0x0002 /* CBS_DROPDOWN */, 10, 300,
                                 200, 150, parent, 0, instance, 0);
    DWORD info[13];
    BOOL got, small;
    DWORD small_error;

    memset(info, 0, sizeof info);
    info[0] = sizeof info;
    got = GetComboBoxInfo(combo, info);
    DbgPrint("[rebar] GetComboBoxInfo %d: the combo box %d, an edit %d, a list %d\n", got, (HWND)info[10] == combo,
             info[11] != 0, info[12] != 0);
    memset(info, 0, sizeof info);
    info[0] = 20;
    SetLastError(0);
    small = GetComboBoxInfo(combo, info);
    small_error = GetLastError();
    DbgPrint("[rebar] GetComboBoxInfo of 20 bytes %d (%lu)\n", small, small_error);
    DestroyWindow(combo);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND window;

    if (!take_a_desktop())
        ExitProcess(1);
    non_client_metrics();
    DbgPrint("[rebar] comctl32 %s\n", LoadLibraryW(L"comctl32.dll") ? "loaded" : "missing");
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.lpszClassName = CLASS_NAME;
    RegisterClassExW(&class_info);
    window = CreateWindowExW(0, CLASS_NAME, L"R", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 20, 20, 800, 400, 0, 0, instance,
                             0);
    combo_box_info(window, instance);
    rebar_font(window, instance);
    variant(window, instance, "the address band beside the links", RBBS_FIXEDBMP);
    variant(window, instance, "the address band on a row of its own", RBBS_FIXEDBMP | RBBS_BREAK);
    DbgPrint("[rebar] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
