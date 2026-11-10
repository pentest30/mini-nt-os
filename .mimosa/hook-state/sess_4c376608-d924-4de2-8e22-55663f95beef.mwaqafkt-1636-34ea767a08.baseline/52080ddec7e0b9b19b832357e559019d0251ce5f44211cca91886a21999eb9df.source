/*
 * M5, console: a program of the CONSOLE subsystem, compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which ReactOS's cmd.exe starts
 * in its console (`cmd /K C:\READ1.EXE`, scenario `cmd`, see concmd1.c):
 * consrv gave cmd a console, whose window its input thread shows, activated,
 * with the keyboard. The program writes a prompt, waits until the window is
 * visible and says it waits; the scenario then types a line in the window
 * (`keys =`), which consrv's window procedure puts in the console's input
 * buffer, echoes and gives to ReadConsoleW once Enter comes: then cmd reads
 * the next lines. Each result goes to the debug port (DbgPrint), where the
 * scenario looks for it; the program ends with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point ConsoleStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HWND;

#define STD_INPUT_HANDLE ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
/* How long to wait for the console window: 10 ms at a time. */
#define TRIES 500
#define LINE 64
#define EXIT_STATUS 0x600D

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) HWND __stdcall GetConsoleWindow(void);
__declspec(dllimport) BOOL __stdcall GetConsoleMode(HANDLE console, DWORD *mode);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD which);
__declspec(dllimport) BOOL __stdcall ReadConsoleW(HANDLE console, void *buffer, DWORD count, DWORD *read,
                                                  void *control);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall WriteConsoleW(HANDLE console, const void *buffer, DWORD count, DWORD *written,
                                                   void *reserved);

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

/* The characters read, in hexadecimal, as one line of the debug port. */
static void print_line(const WCHAR *line, DWORD count)
{
    char text[LINE * 5 + 1];
    static const char digits[] = "0123456789abcdef";
    DWORD i;
    char *at = text;

    for (i = 0; i < count && i < LINE; i++) {
        WCHAR c = line[i];
        if (c > 0xFF) {
            *at++ = digits[(c >> 12) & 0xF];
            *at++ = digits[(c >> 8) & 0xF];
        }
        *at++ = digits[(c >> 4) & 0xF];
        *at++ = digits[c & 0xF];
        *at++ = ' ';
    }
    if (at != text)
        at--;
    *at = 0;
    DbgPrint("[read] the line: %s\n", text);
}

DWORD __stdcall ConsoleStartup(void)
{
    static const WCHAR prompt[] = L"Name? ";
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    WCHAR line[LINE];
    DWORD written = 0;
    DWORD read = 0;
    DWORD mode = 0;
    BOOL ok;

    DbgPrint("[read] started\n");
    ok = GetConsoleMode(input, &mode);
    DbgPrint("[read] GetConsoleMode(input): %d, %lx\n", ok, mode);
    ok = WriteConsoleW(output, prompt, sizeof prompt / sizeof prompt[0] - 1, &written, 0);
    DbgPrint("[read] WriteConsoleW: %d (%lu), %lu characters\n", ok, ok ? 0 : GetLastError(), written);
    DbgPrint("[read] the console window: %s\n", visible_console_window() ? "visible" : "NOT VISIBLE");
    DbgPrint("[read] waiting\n");
    ok = ReadConsoleW(input, line, LINE, &read, 0);
    DbgPrint("[read] ReadConsoleW: %d (%lu), %lu characters\n", ok, ok ? 0 : GetLastError(), read);
    print_line(line, read);
    ExitProcess(EXIT_STATUS);
    return 0;
}
