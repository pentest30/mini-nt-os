/*
 * LockWindowUpdate and DrawCaption: a Win32 program (subsystem WINDOWS),
 * compiled with MinGW and linked to ReactOS's kernel32, user32 and gdi32,
 * which the scenario `caption` puts on the boot disk in the place of
 * winlogon.exe. explorer's folder window (browseui's CShellBrowser) locks
 * itself while it makes its view, and unlocks only if the lock was taken;
 * user32 repaints a window's caption after WM_SETTEXT by DrawCaption
 * (DC_DRAWCAPTIONMD). On WinSta0\Default, W (300 x 200 at 100, 100, white,
 * with a child C) and V (beside it), then:
 * 1. W's caption wiped black, SetWindowText repaints it;
 * 2. LockWindowUpdate(W); V refused; the DCs of W (taken before the lock
 *    too) and of C paint nothing (an empty clip box), unless
 *    DCX_LOCKWINDOWUPDATE; V's DC paints; W's caption, wiped before the
 *    lock, stays black after SetWindowText;
 * 3. LockWindowUpdate(NULL): W's whole client area to update, its DCs paint
 *    again, its WM_PAINT and its caption repainted;
 * 4. unlocking without a lock, V locked then unlocked, a bad handle, a
 *    destroyed window that was locked (the lock goes with it);
 * 5. DrawCaption in a rectangle of the screen's DC: the caption's colour,
 *    active or not, a button's face (DC_INBUTTON), the gradient
 *    (DC_GRADIENT), W's text (DC_TEXT; none without a window), its icon
 *    (DC_ICON), and the errors.
 * Each step goes to the debug port (DbgPrint, a line each); the program
 * ends with EXIT_STATUS.
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
typedef void *HMENU;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *HRGN;
typedef void *HWINSTA;
typedef void *HDESK;
typedef unsigned int WPARAM;
typedef long LPARAM;
typedef long LRESULT;
typedef DWORD COLORREF;
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

#define WS_OVERLAPPEDWINDOW 0x00CF0000
#define WS_VISIBLE 0x10000000
#define WS_CHILD 0x40000000
#define WM_PAINT 0x000F
#define COLOR_ACTIVECAPTION 2
#define COLOR_INACTIVECAPTION 3
#define COLOR_WINDOW 5
#define COLOR_BTNFACE 15
#define MAXIMUM_ALLOWED 0x02000000
#define PM_REMOVE 0x0001
#define DCX_CACHE 0x0002
#define DCX_LOCKWINDOWUPDATE 0x0400
#define BLACKNESS 0x00000042
#define NULLREGION 1
#define SIMPLEREGION 2
#define DC_ACTIVE 0x0001
#define DC_ICON 0x0004
#define DC_TEXT 0x0008
#define DC_INBUTTON 0x0010
#define DC_GRADIENT 0x0020
#define EXIT_STATUS 0x6018

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) void __stdcall SetLastError(DWORD error);

__declspec(dllimport) int __stdcall GetClipBox(HDC hdc, RECT *rect);
__declspec(dllimport) COLORREF __stdcall GetPixel(HDC hdc, int x, int y);
__declspec(dllimport) BOOL __stdcall PatBlt(HDC hdc, int x, int y, int width, int height, DWORD rop);

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
__declspec(dllimport) BOOL __stdcall DrawCaption(HWND window, HDC hdc, const RECT *rect, UINT flags);
__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) HDC __stdcall GetDC(HWND window);
__declspec(dllimport) HDC __stdcall GetDCEx(HWND window, HRGN clip, DWORD flags);
__declspec(dllimport) DWORD __stdcall GetSysColor(int index);
__declspec(dllimport) BOOL __stdcall GetUpdateRect(HWND window, RECT *rect, BOOL erase);
__declspec(dllimport) HDC __stdcall GetWindowDC(HWND window);
__declspec(dllimport) BOOL __stdcall LockWindowUpdate(HWND window);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT min, UINT max, UINT remove);
__declspec(dllimport) ATOM __stdcall RegisterClassExW(const WNDCLASSEXW *class_info);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) int __stdcall ReleaseDC(HWND window, HDC hdc);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SetWindowTextW(HWND window, const WCHAR *text);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

static const WCHAR CLASS_NAME[] = L"MinoCaption";
static HWND w;
static int painted;

/* Where W's caption shows, on the screen: past its title and before its
 * buttons. */
#define CAPTION_X 300
#define CAPTION_Y 112

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

static LRESULT __stdcall procedure(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (message == WM_PAINT && window == w)
        painted++;
    return DefWindowProcW(window, message, wp, lp);
}

static void pump(void)
{
    MSG message;
    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
        DispatchMessageW(&message);
}

/* The colour at (x, y) of the screen. */
static COLORREF screen_pixel(int x, int y)
{
    HDC hdc = GetDC(0);
    COLORREF color = GetPixel(hdc, x, y);
    ReleaseDC(0, hdc);
    return color;
}

/* The clip box's complexity of a DC of `window` taken with `flags` (0:
 * GetDC). */
static int clip_of(HWND window, DWORD flags)
{
    RECT box;
    HDC hdc = flags ? GetDCEx(window, 0, flags) : GetDC(window);
    int complexity = GetClipBox(hdc, &box);
    ReleaseDC(window, hdc);
    return complexity;
}

/* W's caption painted black through its window DC. */
static void wipe_caption(void)
{
    HDC hdc = GetWindowDC(w);
    PatBlt(hdc, 0, 0, 300, 30, BLACKNESS);
    ReleaseDC(w, hdc);
}

/* The pixels of the screen in (left, top)-(right, bottom) that are not
 * `color`. */
static int differing(HDC hdc, int left, int top, int right, int bottom, COLORREF color)
{
    int x, y, count = 0;
    for (y = top; y < bottom; y++)
        for (x = left; x < right; x++)
            if (GetPixel(hdc, x, y) != color)
                count++;
    return count;
}

static void locking(HWND v, HWND c, HINSTANCE instance)
{
    HDC before = GetDC(w);
    HDC lockless;
    RECT box, update, client;
    BOOL lock_w, lock_v, unlocked, has_update, again, lock_v2, unlock_v, bad, lock_x, lock_v3, unlock_v3;
    int clip_w, clip_before, clip_child, clip_lockless, clip_v, before_after;
    DWORD bad_error;
    COLORREF behind, caption;
    HWND x;

    wipe_caption();
    lock_w = LockWindowUpdate(w);
    lock_v = LockWindowUpdate(v);
    DbgPrint("[caption] step 2: LockWindowUpdate W %d, V %d\n", lock_w, lock_v);
    clip_w = clip_of(w, 0);
    clip_before = GetClipBox(before, &box);
    clip_child = clip_of(c, 0);
    clip_lockless = clip_of(w, DCX_CACHE | DCX_LOCKWINDOWUPDATE);
    clip_v = clip_of(v, 0);
    {
        HDC hdc = GetDC(w);
        PatBlt(hdc, 100, 100, 40, 40, BLACKNESS);
        ReleaseDC(w, hdc);
    }
    lockless = GetDCEx(w, 0, DCX_CACHE | DCX_LOCKWINDOWUPDATE);
    behind = GetPixel(lockless, 110, 110);
    ReleaseDC(w, lockless);
    SetWindowTextW(w, L"Locked");
    pump();
    caption = screen_pixel(CAPTION_X, CAPTION_Y);
    DbgPrint("[caption] step 2: clip boxes W %d, taken before %d, its child %d, DCX_LOCKWINDOWUPDATE %d, V %d; "
             "PatBlt leaves %06lx, the caption after SetWindowText %06lx\n",
             clip_w, clip_before, clip_child, clip_lockless, clip_v, behind, caption);

    painted = 0;
    unlocked = LockWindowUpdate(0);
    has_update = GetUpdateRect(w, &update, 0);
    GetClientRect(w, &client);
    before_after = GetClipBox(before, &box);
    ReleaseDC(w, before);
    pump();
    caption = screen_pixel(CAPTION_X, CAPTION_Y);
    DbgPrint("[caption] step 3: LockWindowUpdate(NULL) %d; to update %d, the client area %d; the DC taken before %d; "
             "WM_PAINT %d, the caption black %d\n",
             unlocked, has_update,
             update.left == 0 && update.top == 0 && update.right == client.right && update.bottom == client.bottom,
             before_after, painted > 0, caption == 0);

    again = LockWindowUpdate(0);
    lock_v2 = LockWindowUpdate(v);
    unlock_v = LockWindowUpdate(0);
    SetLastError(0);
    bad = LockWindowUpdate((HWND)0x1234);
    bad_error = GetLastError();
    x = CreateWindowExW(0, CLASS_NAME, L"X", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 500, 300, 100, 100, 0, 0, instance, 0);
    lock_x = LockWindowUpdate(x);
    DestroyWindow(x);
    lock_v3 = LockWindowUpdate(v);
    unlock_v3 = LockWindowUpdate(0);
    pump();
    DbgPrint("[caption] step 4: unlocking unlocked %d; V %d, then %d; a bad handle %d (%lu); a destroyed window %d, "
             "then V %d, %d\n",
             again, lock_v2, unlock_v, bad, bad_error, lock_x, lock_v3, unlock_v3);
}

static void drawing(void)
{
    HDC hdc = GetDC(0);
    RECT rect = {20, 500, 220, 518};
    COLORREF active = GetSysColor(COLOR_ACTIVECAPTION);
    BOOL drawn[8];
    int seen[8];
    COLORREF left, right;
    DWORD errors[3];

    drawn[0] = DrawCaption(w, hdc, &rect, DC_ACTIVE);
    seen[0] = GetPixel(hdc, 120, 509) == active;
    drawn[1] = DrawCaption(w, hdc, &rect, 0);
    seen[1] = GetPixel(hdc, 120, 509) == GetSysColor(COLOR_INACTIVECAPTION);
    drawn[2] = DrawCaption(w, hdc, &rect, DC_INBUTTON | DC_ACTIVE);
    seen[2] = GetPixel(hdc, 120, 509) == GetSysColor(COLOR_BTNFACE);
    DbgPrint("[caption] step 5: DrawCaption active %d %d, inactive %d %d, in a button %d %d\n", drawn[0], seen[0],
             drawn[1], seen[1], drawn[2], seen[2]);

    drawn[3] = DrawCaption(w, hdc, &rect, DC_ACTIVE | DC_GRADIENT);
    left = GetPixel(hdc, 20, 509);
    right = GetPixel(hdc, 219, 509);
    DbgPrint("[caption] step 5: DC_GRADIENT %d: from the caption's colour %d, lighter at the right %d\n", drawn[3],
             left == active, (right & 0xff) > (left & 0xff) && (right >> 16) > (left >> 16));

    drawn[4] = DrawCaption(w, hdc, &rect, DC_ACTIVE | DC_TEXT);
    seen[4] = differing(hdc, 20, 500, 220, 518, active);
    drawn[5] = DrawCaption(0, hdc, &rect, DC_ACTIVE | DC_TEXT);
    seen[5] = differing(hdc, 20, 500, 220, 518, active);
    drawn[6] = DrawCaption(w, hdc, &rect, DC_ACTIVE | DC_ICON);
    seen[6] = differing(hdc, 20, 500, 40, 518, active);
    drawn[7] = DrawCaption(w, hdc, &rect, DC_ACTIVE);
    seen[7] = differing(hdc, 20, 500, 220, 518, active);
    DbgPrint("[caption] step 5: W's text %d %d, without a window %d %d, its icon %d %d, neither %d %d\n", drawn[4],
             seen[4] > 20, drawn[5], seen[5], drawn[6], seen[6] > 20, drawn[7], seen[7]);

    SetLastError(0);
    drawn[0] = DrawCaption(w, hdc, 0, DC_ACTIVE);
    errors[0] = GetLastError();
    SetLastError(0);
    drawn[1] = DrawCaption((HWND)0x1234, hdc, &rect, DC_ACTIVE);
    errors[1] = GetLastError();
    SetLastError(0);
    drawn[2] = DrawCaption(w, (HDC)0x1234, &rect, DC_ACTIVE);
    errors[2] = GetLastError();
    DbgPrint("[caption] step 5: no rectangle %d (%lu), a bad window %d (%lu), a bad DC %d (%lu)\n", drawn[0], errors[0],
             drawn[1], errors[1], drawn[2], errors[2]);
    ReleaseDC(0, hdc);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW class_info;
    HINSTANCE instance = GetModuleHandleW(0);
    HWND v, c;
    COLORREF wiped, repainted;

    if (!take_a_desktop())
        ExitProcess(1);
    memset(&class_info, 0, sizeof class_info);
    class_info.cbSize = sizeof class_info;
    class_info.lpfnWndProc = procedure;
    class_info.hInstance = instance;
    class_info.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    class_info.lpszClassName = CLASS_NAME;
    RegisterClassExW(&class_info);
    w = CreateWindowExW(0, CLASS_NAME, L"W", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 300, 200, 0, 0, instance, 0);
    c = CreateWindowExW(0, CLASS_NAME, L"C", WS_CHILD | WS_VISIBLE, 10, 10, 50, 50, w, 0, instance, 0);
    v = CreateWindowExW(0, CLASS_NAME, L"V", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 500, 100, 200, 150, 0, 0, instance, 0);
    pump();

    wipe_caption();
    wiped = screen_pixel(CAPTION_X, CAPTION_Y);
    SetWindowTextW(w, L"Retitled");
    repainted = screen_pixel(CAPTION_X, CAPTION_Y);
    DbgPrint("[caption] step 1: the caption wiped %06lx, after SetWindowText black %d\n", wiped, repainted == 0);

    locking(v, c, instance);
    drawing();
    DbgPrint("[caption] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
