/*
 * The display settings (M6), first probe: a Win32 program (subsystem
 * WINDOWS), built with MinGW and linked to ReactOS's kernel32, user32 and
 * gdi32, which the scenario `display-mode` puts in the place of winlogon.exe.
 * Like winlogon, it takes WinSta0\Default. Then, of what user32 asks win32k
 * of the display (NtUserEnumDisplayDevices, NtUserEnumDisplaySettings,
 * NtUserChangeDisplaySettings):
 * 1. EnumDisplayDevices: the adapter \\.\DISPLAY1, attached to the desktop
 *    and primary, with its registry key; its monitor; nothing after them;
 * 2. EnumDisplaySettings: the mode in use (1280x800, 32 bits, 60 Hz); the
 *    driver's modes, from 640x480 up, sorted, 800x600 among them, nothing
 *    after the last; another device refused; none in the registry yet;
 * 3. ChangeDisplaySettings that change nothing: CDS_TEST of 800x600
 *    (successful), a size the driver has not and 16 bits (DISP_CHANGE_BADMODE),
 *    CDS_NORESET without CDS_UPDATEREGISTRY (DISP_CHANGE_BADFLAGS), another
 *    device (DISP_CHANGE_BADPARAM): the screen stays 1280x800, and no window
 *    hears of it;
 * 4. QEMU moves the mouse to the bottom-right corner (1279, 799);
 * 5. ChangeDisplaySettings to 800x600, CDS_UPDATEREGISTRY: WM_DISPLAYCHANGE
 *    (32, MAKELONG(800, 600)) once to its window and once to the window of
 *    its second thread, during the call; then the system metrics
 *    (SM_CXSCREEN, SM_CXFULLSCREEN, SM_CXVIRTUALSCREEN...), the mode in use,
 *    the monitor (rcMonitor, rcWork), the desktop window, GetDeviceCaps of a
 *    DC of the screen (HORZRES, VERTRES), the pointer kept on the screen
 *    (799, 599); the registry's mode (ENUM_REGISTRY_SETTINGS), which
 *    ChangeDisplaySettings(NULL) takes back: the mode in use already, no
 *    WM_DISPLAYCHANGE;
 * 6. its window goes to the bottom-right corner of the new screen and paints
 *    itself green: the scenario checks QEMU's screen (800 x 600, the corner
 *    green, the desktop's colour elsewhere).
 * One line of the debug port (DbgPrint) for each. Then it waits.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef long LPARAM;
typedef unsigned int WPARAM;
typedef long LRESULT;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HKL;
typedef void *HDC;
typedef void *HBRUSH;
typedef void *HMONITOR;
typedef void *HINSTANCE;
typedef LRESULT(__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef DWORD(__stdcall *THREADPROC)(void *);

typedef struct {
    LONG left, top, right, bottom;
} RECT;

typedef struct {
    LONG x, y;
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
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HANDLE hIcon;
    HANDLE hCursor;
    HBRUSH hbrBackground;
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
    HANDLE hIconSm;
} WNDCLASSEXW;

typedef struct {
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    BYTE rgbReserved[32];
} PAINTSTRUCT;

typedef struct {
    DWORD cbSize;
    RECT rcMonitor;
    RECT rcWork;
    DWORD dwFlags;
} MONITORINFO;

/* DEVMODEW of NT 5 (220 bytes), the display's fields. */
typedef struct {
    WCHAR dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    LONG dmPositionX, dmPositionY;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
    short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
    WCHAR dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    DWORD dmDisplayFlags;
    DWORD dmDisplayFrequency;
    DWORD dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2;
    DWORD dmPanningWidth, dmPanningHeight;
} DEVMODEW;

typedef struct {
    DWORD cb;
    WCHAR DeviceName[32];
    WCHAR DeviceString[128];
    DWORD StateFlags;
    WCHAR DeviceID[128];
    WCHAR DeviceKey[128];
} DISPLAY_DEVICEW;

typedef char devmode_is_220_bytes[sizeof(DEVMODEW) == 220 ? 1 : -1];
typedef char display_device_is_840_bytes[sizeof(DISPLAY_DEVICEW) == 840 ? 1 : -1];

#define MAXIMUM_ALLOWED 0x02000000
#define KLF_ACTIVATE 0x00000001
#define WS_POPUP 0x80000000
#define WS_VISIBLE 0x10000000
#define WM_DESTROY 0x0002
#define WM_PAINT 0x000F
#define WM_DISPLAYCHANGE 0x007E
#define SWP_NOZORDER 0x0004
#define SWP_NOACTIVATE 0x0010
#define PM_REMOVE 0x0001
#define INFINITE 0xFFFFFFFF
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define SM_CXFULLSCREEN 16
#define SM_CYFULLSCREEN 17
#define SM_CXMAXIMIZED 61
#define SM_CYMAXIMIZED 62
#define SM_CXVIRTUALSCREEN 78
#define SM_CYVIRTUALSCREEN 79
#define HORZRES 8
#define VERTRES 10
#define BITSPIXEL 12
#define DM_BITSPERPEL 0x00040000
#define DM_PELSWIDTH 0x00080000
#define DM_PELSHEIGHT 0x00100000
#define DM_DISPLAYFREQUENCY 0x00400000
#define CDS_TEST 0x00000002
#define CDS_NORESET 0x10000000
#define DISP_CHANGE_SUCCESSFUL 0
#define DISP_CHANGE_BADMODE (-2)
#define DISP_CHANGE_BADFLAGS (-4)
#define DISP_CHANGE_BADPARAM (-5)
#define ENUM_CURRENT_SETTINGS ((DWORD)-1)
#define ENUM_REGISTRY_SETTINGS ((DWORD)-2)
#define CDS_UPDATEREGISTRY 0x00000001
#define DISPLAY_DEVICE_ATTACHED_TO_DESKTOP 0x1
#define DISPLAY_DEVICE_PRIMARY_DEVICE 0x4
#define MONITOR_DEFAULTTOPRIMARY 1
#define EXIT_STATUS 0x6052
/* The green of its window: RGB(0x20, 0xA0, 0x40). */
#define GREEN 0x0040A020

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HINSTANCE __stdcall GetModuleHandleW(const WCHAR *name);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREADPROC start, void *parameter,
                                                    DWORD flags, DWORD *id);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *name, UINT flags);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);
__declspec(dllimport) WORD __stdcall RegisterClassExW(const WNDCLASSEXW *klass);
__declspec(dllimport) HWND __stdcall CreateWindowExW(DWORD ex_style, const WCHAR *klass, const WCHAR *name,
                                                     DWORD style, int x, int y, int width, int height, HWND parent,
                                                     void *menu, HINSTANCE instance, void *parameter);
__declspec(dllimport) LRESULT __stdcall DefWindowProcW(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
__declspec(dllimport) BOOL __stdcall GetMessageW(MSG *message, HWND window, UINT first, UINT last);
__declspec(dllimport) BOOL __stdcall PeekMessageW(MSG *message, HWND window, UINT first, UINT last, UINT remove);
__declspec(dllimport) LRESULT __stdcall DispatchMessageW(const MSG *message);
__declspec(dllimport) HDC __stdcall BeginPaint(HWND window, PAINTSTRUCT *paint);
__declspec(dllimport) BOOL __stdcall EndPaint(HWND window, const PAINTSTRUCT *paint);
__declspec(dllimport) int __stdcall FillRect(HDC dc, const RECT *rect, HBRUSH brush);
__declspec(dllimport) BOOL __stdcall SetWindowPos(HWND window, HWND after, int x, int y, int width, int height,
                                                  UINT flags);
__declspec(dllimport) BOOL __stdcall UpdateWindow(HWND window);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) BOOL __stdcall GetCursorPos(POINT *point);
__declspec(dllimport) HWND __stdcall GetDesktopWindow(void);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) HMONITOR __stdcall MonitorFromPoint(POINT point, DWORD flags);
__declspec(dllimport) BOOL __stdcall GetMonitorInfoW(HMONITOR monitor, MONITORINFO *info);
__declspec(dllimport) BOOL __stdcall EnumDisplayDevicesW(const WCHAR *device, DWORD index, DISPLAY_DEVICEW *out,
                                                         DWORD flags);
__declspec(dllimport) BOOL __stdcall EnumDisplaySettingsW(const WCHAR *device, DWORD mode, DEVMODEW *out);
__declspec(dllimport) BOOL __stdcall EnumDisplaySettingsExW(const WCHAR *device, DWORD mode, DEVMODEW *out,
                                                            DWORD flags);
__declspec(dllimport) LONG __stdcall ChangeDisplaySettingsW(DEVMODEW *mode, DWORD flags);
__declspec(dllimport) LONG __stdcall ChangeDisplaySettingsExW(const WCHAR *device, DEVMODEW *mode, HWND window,
                                                              DWORD flags, void *parameter);
__declspec(dllimport) HDC __stdcall CreateDCW(const WCHAR *driver, const WCHAR *device, const WCHAR *output,
                                              void *mode);
__declspec(dllimport) BOOL __stdcall DeleteDC(HDC dc);
__declspec(dllimport) int __stdcall GetDeviceCaps(HDC dc, int index);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(DWORD color);

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

/* `text` in ASCII (non-ASCII as '?'), at most 127 characters. */
static const char *ascii(const WCHAR *text, char *out)
{
    int i;
    for (i = 0; i < 127 && text[i]; i++)
        out[i] = text[i] < 0x80 ? (char)text[i] : '?';
    out[i] = 0;
    return out;
}

/* The UTF-16 text `a` is the ASCII text `b`. */
static int same(const WCHAR *a, const char *b)
{
    while (*a && *a == (WCHAR)*b)
        a++, b++;
    return *a == (WCHAR)*b;
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it, and the
 * keyboard layout. */
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
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        return 0;
    DbgPrint("[display] on WinSta0\\Default\n");
    return 1;
}

/* What each window heard of WM_DISPLAYCHANGE: how many, the last one. */
static struct {
    int count;
    WPARAM wparam;
    LPARAM lparam;
} heard[2];
static HWND main_window, other_window;
static HBRUSH green;

static LRESULT __stdcall window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    PAINTSTRUCT paint;
    RECT rect = {0, 0, 1000, 1000};

    switch (message) {
    case WM_DISPLAYCHANGE: {
        int which = window == other_window;
        heard[which].count++;
        heard[which].wparam = wparam;
        heard[which].lparam = lparam;
        return 0;
    }
    case WM_PAINT:
        BeginPaint(window, &paint);
        FillRect(paint.hdc, &rect, green);
        EndPaint(window, &paint);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

static HANDLE other_ready;

/* The second thread: a hidden top-level window of its own, and its
 * messages. */
static DWORD __stdcall other_thread(void *parameter)
{
    MSG message;
    (void)parameter;
    other_window = CreateWindowExW(0, L"MinoDisplay", L"other", WS_POPUP, 0, 0, 50, 50, 0, 0, GetModuleHandleW(0), 0);
    SetEvent(other_ready);
    while (GetMessageW(&message, 0, 0, 0) > 0)
        DispatchMessageW(&message);
    return 0;
}

/* Its own messages, without waiting. */
static void pump(void)
{
    MSG message;
    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE))
        DispatchMessageW(&message);
}

/* 1. The adapter and its monitor. */
static void check_devices(void)
{
    DISPLAY_DEVICEW adapter, monitor, none;
    char name[128], string[128], key[128], monitor_name[128];
    BOOL got_adapter, got_monitor, more_adapters, more_monitors;

    memset(&adapter, 0, sizeof adapter);
    adapter.cb = sizeof adapter;
    got_adapter = EnumDisplayDevicesW(0, 0, &adapter, 0);
    memset(&monitor, 0, sizeof monitor);
    monitor.cb = sizeof monitor;
    got_monitor = EnumDisplayDevicesW(adapter.DeviceName, 0, &monitor, 0);
    none.cb = sizeof none;
    more_adapters = EnumDisplayDevicesW(0, 1, &none, 0);
    more_monitors = EnumDisplayDevicesW(adapter.DeviceName, 1, &none, 0);
    DbgPrint("[display] adapter %d: %s \"%s\", flags %lx, key %s\n", got_adapter, ascii(adapter.DeviceName, name),
             ascii(adapter.DeviceString, string), adapter.StateFlags, ascii(adapter.DeviceKey, key));
    DbgPrint("[display] monitor %d: %s, flags %lx; another adapter %d, another monitor %d\n", got_monitor,
             ascii(monitor.DeviceName, monitor_name), monitor.StateFlags, more_adapters, more_monitors);
    if (got_adapter && same(adapter.DeviceName, "\\\\.\\DISPLAY1") &&
        (adapter.StateFlags & (DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE)) ==
            (DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE) &&
        got_monitor && same(monitor.DeviceName, "\\\\.\\DISPLAY1\\Monitor0") && !more_adapters && !more_monitors)
        DbgPrint("[display] step 1: one adapter, attached and primary, one monitor\n");
}

/* 2. The modes. */
static void check_modes(void)
{
    DEVMODEW mode;
    DWORD index, count = 0, last_width = 0, last_height = 0;
    int sorted = 1, has_800 = 0, all_32 = 1;
    BOOL current, registry;
    LONG other_device;

    memset(&mode, 0, sizeof mode);
    mode.dmSize = sizeof mode;
    current = EnumDisplaySettingsW(0, ENUM_CURRENT_SETTINGS, &mode);
    DbgPrint("[display] current %d: %lux%lu, %lu bits, %lu Hz, fields %lx\n", current, mode.dmPelsWidth,
             mode.dmPelsHeight, mode.dmBitsPerPel, mode.dmDisplayFrequency, mode.dmFields);
    for (index = 0; index < 64; index++) {
        memset(&mode, 0, sizeof mode);
        mode.dmSize = sizeof mode;
        if (!EnumDisplaySettingsW(0, index, &mode))
            break;
        count++;
        if (index == 0)
            DbgPrint("[display] first mode %lux%lu\n", mode.dmPelsWidth, mode.dmPelsHeight);
        if (mode.dmPelsWidth < last_width || (mode.dmPelsWidth == last_width && mode.dmPelsHeight <= last_height))
            sorted = 0;
        last_width = mode.dmPelsWidth;
        last_height = mode.dmPelsHeight;
        if (mode.dmPelsWidth == 800 && mode.dmPelsHeight == 600)
            has_800 = 1;
        if (mode.dmBitsPerPel != 32 || mode.dmDisplayFrequency != 60)
            all_32 = 0;
    }
    memset(&mode, 0, sizeof mode);
    mode.dmSize = sizeof mode;
    other_device = EnumDisplaySettingsExW(L"\\\\.\\DISPLAY2", ENUM_CURRENT_SETTINGS, &mode, 0);
    registry = EnumDisplaySettingsW(0, ENUM_REGISTRY_SETTINGS, &mode);
    DbgPrint("[display] %lu modes, sorted %d, 800x600 %d, all 32 bits at 60 Hz %d, last %lux%lu; another device %ld, "
             "the registry's %d\n",
             count, sorted, has_800, all_32, last_width, last_height, other_device, registry);
}

/* A DEVMODE of `width` x `height`, `bits` bits per pixel (0: not given). */
static void mode_of(DEVMODEW *mode, DWORD width, DWORD height, DWORD bits)
{
    memset(mode, 0, sizeof *mode);
    mode->dmSize = sizeof *mode;
    mode->dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | (bits ? DM_BITSPERPEL : 0);
    mode->dmPelsWidth = width;
    mode->dmPelsHeight = height;
    mode->dmBitsPerPel = bits;
}

/* 3. Requests that change nothing. */
static void check_refusals(void)
{
    DEVMODEW mode;
    LONG test, odd, sixteen, flags, device;

    mode_of(&mode, 800, 600, 32);
    test = ChangeDisplaySettingsW(&mode, CDS_TEST);
    mode_of(&mode, 1000, 700, 0);
    odd = ChangeDisplaySettingsW(&mode, 0);
    mode_of(&mode, 800, 600, 16);
    sixteen = ChangeDisplaySettingsW(&mode, 0);
    mode_of(&mode, 800, 600, 0);
    flags = ChangeDisplaySettingsW(&mode, CDS_NORESET);
    device = ChangeDisplaySettingsExW(L"\\\\.\\DISPLAY9", &mode, 0, 0, 0);
    pump();
    DbgPrint("[display] step 3: CDS_TEST %ld, 1000x700 %ld, 16 bits %ld, CDS_NORESET %ld, another device %ld; "
             "the screen %dx%d, WM_DISPLAYCHANGE %d %d\n",
             test, odd, sixteen, flags, device, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
             heard[0].count, heard[1].count);
}

/* 5. The change to 800x600, and what follows it. */
static void change_to_800(void)
{
    DEVMODEW mode;
    MONITORINFO info;
    RECT desktop;
    POINT corner = {0, 0}, cursor;
    HDC dc;
    LONG result, again;
    BOOL registry;
    int horz, vert, bits;

    mode_of(&mode, 800, 600, 0);
    result = ChangeDisplaySettingsW(&mode, CDS_UPDATEREGISTRY);
    DbgPrint("[display] step 5: ChangeDisplaySettings 800x600: %ld; WM_DISPLAYCHANGE to its window %d (%u, %08lx), "
             "to its other thread's %d (%u, %08lx)\n",
             result, heard[0].count, heard[0].wparam, heard[0].lparam, heard[1].count, heard[1].wparam,
             heard[1].lparam);
    DbgPrint("[display] metrics: screen %dx%d, full screen %dx%d, maximized %dx%d, virtual screen %dx%d\n",
             GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), GetSystemMetrics(SM_CXFULLSCREEN),
             GetSystemMetrics(SM_CYFULLSCREEN), GetSystemMetrics(SM_CXMAXIMIZED), GetSystemMetrics(SM_CYMAXIMIZED),
             GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
    memset(&mode, 0, sizeof mode);
    mode.dmSize = sizeof mode;
    EnumDisplaySettingsW(0, ENUM_CURRENT_SETTINGS, &mode);
    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    GetMonitorInfoW(MonitorFromPoint(corner, MONITOR_DEFAULTTOPRIMARY), &info);
    GetWindowRect(GetDesktopWindow(), &desktop);
    DbgPrint("[display] current %lux%lu; monitor %ld %ld %ld %ld, work %ld %ld %ld %ld; desktop window %ld %ld %ld %ld\n",
             mode.dmPelsWidth, mode.dmPelsHeight, info.rcMonitor.left, info.rcMonitor.top, info.rcMonitor.right,
             info.rcMonitor.bottom, info.rcWork.left, info.rcWork.top, info.rcWork.right, info.rcWork.bottom,
             desktop.left, desktop.top, desktop.right, desktop.bottom);
    dc = CreateDCW(L"DISPLAY", 0, 0, 0);
    horz = GetDeviceCaps(dc, HORZRES);
    vert = GetDeviceCaps(dc, VERTRES);
    bits = GetDeviceCaps(dc, BITSPIXEL);
    DeleteDC(dc);
    GetCursorPos(&cursor);
    DbgPrint("[display] device caps %dx%d, %d bits; cursor %ld %ld\n", horz, vert, bits, cursor.x, cursor.y);
    memset(&mode, 0, sizeof mode);
    mode.dmSize = sizeof mode;
    registry = EnumDisplaySettingsW(0, ENUM_REGISTRY_SETTINGS, &mode);
    again = ChangeDisplaySettingsW(0, 0);
    DbgPrint("[display] the registry's %d: %lux%lu, %lu bits, %lu Hz; ChangeDisplaySettings(NULL) %ld, "
             "WM_DISPLAYCHANGE %d %d\n",
             registry, mode.dmPelsWidth, mode.dmPelsHeight, mode.dmBitsPerPel, mode.dmDisplayFrequency, again,
             heard[0].count, heard[1].count);
}

DWORD __stdcall GuiStartup(void)
{
    WNDCLASSEXW klass;
    POINT cursor;
    MSG message;
    int tries;

    if (!take_a_desktop())
        ExitProcess(1);
    green = CreateSolidBrush(GREEN);
    memset(&klass, 0, sizeof klass);
    klass.cbSize = sizeof klass;
    klass.lpfnWndProc = window_proc;
    klass.hInstance = GetModuleHandleW(0);
    klass.lpszClassName = L"MinoDisplay";
    RegisterClassExW(&klass);
    main_window = CreateWindowExW(0, L"MinoDisplay", L"display", WS_POPUP | WS_VISIBLE, 10, 10, 100, 100, 0, 0,
                                  GetModuleHandleW(0), 0);
    other_ready = CreateEventW(0, 1, 0, 0);
    CreateThread(0, 0, other_thread, 0, 0, 0);
    WaitForSingleObject(other_ready, INFINITE);
    pump();

    check_devices();
    check_modes();
    check_refusals();

    /* 4. The pointer to the bottom-right corner (QEMU moves the mouse). */
    DbgPrint("[display] waiting for the mouse\n");
    for (tries = 0; tries < 200; tries++) {
        GetCursorPos(&cursor);
        if (cursor.x == 1279 && cursor.y == 799)
            break;
        Sleep(50);
    }
    DbgPrint("[display] step 4: the pointer at %ld %ld\n", cursor.x, cursor.y);

    change_to_800();

    /* 6. The window in the corner of the new screen, green. */
    SetWindowPos(main_window, 0, 700, 500, 100, 100, SWP_NOZORDER | SWP_NOACTIVATE);
    UpdateWindow(main_window);
    pump();
    Sleep(500);
    pump();
    DbgPrint("[display] done\n");
    while (GetMessageW(&message, 0, 0, 0) > 0)
        DispatchMessageW(&message);
    ExitProcess(EXIT_STATUS);
    return 0;
}
