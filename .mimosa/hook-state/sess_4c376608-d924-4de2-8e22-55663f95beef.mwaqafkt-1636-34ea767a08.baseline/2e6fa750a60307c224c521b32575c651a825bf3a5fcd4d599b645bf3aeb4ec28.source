/*
 * M5, console: a program of the CONSOLE subsystem, compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which CONSOLE1.EXE (console1.c)
 * starts after THREADS1.EXE, without waiting for it (scenario `console`).
 * consrv gives it a console, whose window its input thread creates and
 * shows; the program writes to it (WriteConsoleW), waits until the window
 * is visible (GetConsoleWindow, IsWindowVisible) and says where it is, then
 * stays: the scenario's screen capture shows its console.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point ConsoleStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef long LONG;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HWND;

typedef struct {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT;

#define INFINITE 0xFFFFFFFF
#define STD_OUTPUT_HANDLE ((DWORD)-11)
/* How long to wait for the console window: 10 ms at a time. */
#define TRIES 500

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD which);
__declspec(dllimport) HWND __stdcall GetConsoleWindow(void);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall WriteConsoleW(HANDLE console, const void *buffer, DWORD count, DWORD *written,
                                                   void *reserved);

__declspec(dllimport) BOOL __stdcall GetClientRect(HWND window, RECT *rect);
__declspec(dllimport) LONG __stdcall GetWindowLongW(HWND window, int index);
__declspec(dllimport) BOOL __stdcall GetWindowRect(HWND window, RECT *rect);
__declspec(dllimport) BOOL __stdcall IsWindowVisible(HWND window);

/* The console window, once visible; NULL if it never shows. */
static HWND visible_console_window(void)
{
    int tries;

    for (tries = 0; tries < TRIES; tries++) {
        HWND window = GetConsoleWindow();
        if (window && IsWindowVisible(window))
            return window;
        Sleep(10);
    }
    return 0;
}

DWORD __stdcall ConsoleStartup(void)
{
    static const WCHAR text[] = L"Mino console\r\n";
    DWORD written = 0;
    BOOL wrote;
    HWND window;
    RECT rect = {0, 0, 0, 0};
    RECT client = {0, 0, 0, 0};

    DbgPrint("[conshow] started\n");
    wrote = WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), text, sizeof text / sizeof text[0] - 1, &written, 0);
    DbgPrint("[conshow] WriteConsoleW: %d (%lu), %lu characters\n", wrote, wrote ? 0 : GetLastError(), written);
    window = visible_console_window();
    DbgPrint("[conshow] the console window: %s\n", window ? "visible" : "NOT VISIBLE");
    GetWindowRect(window, &rect);
    GetClientRect(window, &client);
    DbgPrint("[conshow] GetWindowRect: %ld %ld %ld %ld, GetClientRect: %ld %ld %ld %ld\n", rect.left, rect.top,
             rect.right, rect.bottom, client.left, client.top, client.right, client.bottom);
    /* consrv keeps the console's leader in the window's extra bytes
       (GWLP_CONSOLE_LEADER_PID, GWLP_CONSOLE_LEADER_TID): this process and
       its thread, which user32 reads in the window itself. */
    DbgPrint("[conshow] the leader in the window: %s, %s\n",
             (DWORD)GetWindowLongW(window, 0) == GetCurrentProcessId() ? "this process" : "WRONG",
             (DWORD)GetWindowLongW(window, 4) == GetCurrentThreadId() ? "this thread" : "WRONG");
    DbgPrint("[conshow] waiting\n");
    Sleep(INFINITE);
    return 0;
}
