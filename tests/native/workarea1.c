/*
 * SystemParametersInfo(SPI_GETWORKAREA, SPI_SETWORKAREA): a Win32 program
 * (subsystem WINDOWS), compiled with MinGW and linked to ReactOS's user32,
 * which the scenario
 * `work-area` puts on the boot disk in the place of winlogon.exe. Apache
 * OpenOffice 4.1.17 started with no window: VCL centres its splash screen
 * and its first-start wizard in the work area that SPI_GETWORKAREA gives,
 * which Mino did not implement (FALSE). VCL used its RECT uninitialised and
 * put both windows at x = 0x4E4F43C0 and beyond; the wizard waited, unseen,
 * and every later launch waited on it. With SPI_GETWORKAREA alone,
 * explorer's taskbar disappeared: its desktop took the work area, the whole
 * screen, which explorer took for a full-screen application, and the taskbar
 * went to the bottom of the Z order; the taskbar sets the work area to keep
 * its room (SPI_SETWORKAREA). As ReactOS (sysparams.c,
 * UserSystemParametersInfo: the primary monitor's rcWork, SpiGet, SpiSet):
 * 1. SPI_GETWORKAREA gives TRUE and the whole RECT: the screen, with no
 *    taskbar to take room from it;
 * 2. the same rectangle as GetMonitorInfo's rcWork for the primary monitor;
 * 3. uiParam is ignored;
 * 4. a NULL pvParam gives FALSE;
 * 5. SPI_SETWORKAREA sets it: read back by SPI_GETWORKAREA and
 *    GetMonitorInfo;
 * 6. an empty rectangle, one beyond the screen, a NULL pvParam: FALSE, the
 *    work area kept;
 * 7. the whole screen again.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;

typedef struct {
    LONG left, top, right, bottom;
} RECT;

typedef struct {
    LONG x, y;
} POINT;

typedef struct {
    DWORD cbSize;
    RECT rcMonitor;
    RECT rcWork;
    DWORD dwFlags;
} MONITORINFO;

#define SPI_SETWORKAREA 0x002F
#define SPI_GETWORKAREA 0x0030
#define SM_CXSCREEN 0
#define SM_CYSCREEN 1
#define MONITOR_DEFAULTTOPRIMARY 1
#define SENTINEL 0x5A5A5A5A

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) BOOL __stdcall GetMonitorInfoW(HANDLE monitor, MONITORINFO *info);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) HANDLE __stdcall MonitorFromPoint(POINT point, DWORD flags);
__declspec(dllimport) BOOL __stdcall SystemParametersInfoW(UINT action, UINT param, void *pv, UINT win_ini);

static BOOL same(const RECT *a, const RECT *b)
{
    return a->left == b->left && a->top == b->top && a->right == b->right && a->bottom == b->bottom;
}

DWORD __stdcall GuiStartup(void)
{
    RECT work = {SENTINEL, SENTINEL, SENTINEL, SENTINEL}, again = {SENTINEL, SENTINEL, SENTINEL, SENTINEL};
    RECT screen = {0, 0, 0, 0};
    MONITORINFO info;
    POINT origin = {0, 0};
    BOOL got, got_monitor, got_again, got_null, set, empty, beyond, set_null, restored;
    RECT smaller, empty_rect, beyond_rect, now = {SENTINEL, SENTINEL, SENTINEL, SENTINEL};

    screen.right = GetSystemMetrics(SM_CXSCREEN);
    screen.bottom = GetSystemMetrics(SM_CYSCREEN);
    DbgPrint("[workarea] ready: a screen of %ldx%ld\n", screen.right, screen.bottom);

    /* 1. The work area: the whole screen. */
    got = SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    DbgPrint("[workarea] step 1: %d, (%ld,%ld)-(%ld,%ld), the screen %d\n", got, work.left, work.top, work.right,
             work.bottom, same(&work, &screen));

    /* 2. The primary monitor's rcWork. */
    info.cbSize = sizeof info;
    got_monitor = GetMonitorInfoW(MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY), &info);
    DbgPrint("[workarea] step 2: GetMonitorInfo %d, the same rcWork %d\n", got_monitor, same(&work, &info.rcWork));

    /* 3. uiParam does not count. */
    got_again = SystemParametersInfoW(SPI_GETWORKAREA, 123, &again, 0);
    DbgPrint("[workarea] step 3: uiParam 123: %d, the same %d\n", got_again, same(&again, &work));

    /* 4. Nowhere to write it. */
    got_null = SystemParametersInfoW(SPI_GETWORKAREA, 0, 0, 0);
    DbgPrint("[workarea] step 4: a NULL pvParam: %d\n", got_null);

    /* 5. A work area above a taskbar of 30 pixels. */
    smaller = screen;
    smaller.bottom -= 30;
    set = SystemParametersInfoW(SPI_SETWORKAREA, 0, &smaller, 0);
    got = SystemParametersInfoW(SPI_GETWORKAREA, 0, &now, 0);
    got_monitor = GetMonitorInfoW(MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY), &info);
    DbgPrint("[workarea] step 5: set %d, read back %d, the same %d, rcWork the same %d\n", set, got,
             same(&now, &smaller), got_monitor && same(&info.rcWork, &smaller));

    /* 6. Refused: nothing changes. */
    empty_rect = smaller;
    empty_rect.right = empty_rect.left;
    beyond_rect = screen;
    beyond_rect.bottom += 1;
    empty = SystemParametersInfoW(SPI_SETWORKAREA, 0, &empty_rect, 0);
    beyond = SystemParametersInfoW(SPI_SETWORKAREA, 0, &beyond_rect, 0);
    set_null = SystemParametersInfoW(SPI_SETWORKAREA, 0, 0, 0);
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &now, 0);
    DbgPrint("[workarea] step 6: empty %d, beyond the screen %d, NULL %d, kept %d\n", empty, beyond, set_null,
             same(&now, &smaller));

    /* 7. The whole screen again. */
    restored = SystemParametersInfoW(SPI_SETWORKAREA, 0, &screen, 0);
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &now, 0);
    DbgPrint("[workarea] step 7: %d, the screen %d\n", restored, same(&now, &screen));

    DbgPrint("[workarea] done\n");
    ExitProcess(0);
    return 0;
}
