/* The M7 bench (docs/compat/applications.md): runs silently the installer
   that C:\APPS\PROBE.TXT names, then the program it installed, and logs what
   it sees: the installer's exit code or how long it ran, the windows on the
   screen (a silent installer stuck on a message box shows it there), the
   installer's own log, what it put under its directory, then the program's
   first window and how it closes. It judges nothing: the kernel logs each
   service without a handler at its first call, and each exception that
   ends a process; the scenario's markers say how far an application goes.
   Taking WinSta0\Default, it replaces winlogon (initial-command). */
#include "app_probe.h"

#define TAG "[appbench] "
static char text[4096];
static WCHAR install[1024], visible[1024], log_path[MAX_PATH], program[MAX_PATH];
static char name[128];
static DWORD timeout_seconds = 300;

static unsigned int length(const char *s) { unsigned int n = 0; while (s[n]) ++n; return n; }
static unsigned int wlength(const WCHAR *s) { unsigned int n = 0; while (s[n]) ++n; return n; }
static BOOL prefix(const char *s, const char *p) { while (*p) if (*s++ != *p++) return FALSE; return TRUE; }

/* A wide string as ANSI for DbgPrint, cut to the buffer. */
static const char *narrow(const WCHAR *w, char *out, int size)
{
    if (!WideCharToMultiByte(CP_ACP, 0, w, -1, out, size, 0, 0)) out[0] = 0;
    out[size - 1] = 0;
    return out;
}

/* The value of `key` in the command file, as a wide string. */
static BOOL value_of(const char *key, WCHAR *out, int size)
{
    const char *line = text;
    unsigned int keylen = length(key);
    while (*line) {
        const char *end = line;
        while (*end && *end != '\r' && *end != '\n') ++end;
        if (prefix(line, key) && line[keylen] == '=') {
            int n = MultiByteToWideChar(CP_ACP, 0, line + keylen + 1, (int)(end - line - keylen - 1), out, size - 1);
            out[n > 0 ? n : 0] = 0;
            return TRUE;
        }
        line = end;
        while (*line == '\r' || *line == '\n') ++line;
    }
    return FALSE;
}

static void read_commands(void)
{
    HANDLE file = CreateFileW(L"C:\\APPS\\PROBE.TXT", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    app_check(file != INVALID_HANDLE_VALUE, "C:\\APPS\\PROBE.TXT");
    DWORD count = 0;
    app_check(ReadFile(file, text, sizeof(text) - 1, &count, 0), "read PROBE.TXT");
    CloseHandle(file);
    text[count] = 0;
    WCHAR value[128];
    app_check(value_of("name", value, 128) && value_of("install", install, 1024) && value_of("program", program, MAX_PATH),
              "PROBE.TXT: name, install, program");
    narrow(value, name, sizeof(name));
    if (!value_of("log", log_path, MAX_PATH)) log_path[0] = 0;
    if (!value_of("visible", visible, 1024)) visible[0] = 0;
    if (value_of("timeout", value, 128)) {
        timeout_seconds = 0;
        for (WCHAR *d = value; *d >= L'0' && *d <= L'9'; ++d) timeout_seconds = timeout_seconds * 10 + (*d - L'0');
    }
}

/* The visible top-level windows, and the texts of a dialog's controls: what
   a silent installer may be waiting on. Printed when they change. */
static DWORD windows_seen;
static BOOL CALLBACK print_child(HWND child, LPARAM count)
{
    WCHAR title[160]; char line[200];
    if (++*(int *)count > 12) return FALSE;
    if (GetWindowTextW(child, title, 160) > 0 && IsWindowVisible(child))
        DbgPrint(TAG "   control: %s\n", narrow(title, line, sizeof(line)));
    return TRUE;
}
static BOOL CALLBACK sum_window(HWND window, LPARAM sum)
{
    WCHAR title[64];
    if (!IsWindowVisible(window)) return TRUE;
    DWORD hash = (DWORD)(ULONG_PTR)window;
    int n = GetWindowTextW(window, title, 64);
    for (int i = 0; i < n; ++i) hash = hash * 31 + title[i];
    *(DWORD *)sum += hash;
    return TRUE;
}
static BOOL CALLBACK print_window(HWND window, LPARAM unused)
{
    WCHAR title[160], class_name[64]; char a[200], b[80];
    DWORD pid = 0;
    (void)unused;
    if (!IsWindowVisible(window)) return TRUE;
    GetWindowThreadProcessId(window, &pid);
    if (pid == GetCurrentProcessId()) return TRUE;
    title[0] = class_name[0] = 0;
    GetWindowTextW(window, title, 160);
    GetClassNameW(window, class_name, 64);
    DbgPrint(TAG "window: PID %lu, class %s, \"%s\"\n", pid, narrow(class_name, b, sizeof(b)), narrow(title, a, sizeof(a)));
    int children = 0;
    if (wlength(class_name) == 6 && class_name[0] == L'#' && class_name[1] == L'3')
        EnumChildWindows(window, print_child, (LPARAM)&children);
    return TRUE;
}
static void print_windows(BOOL always)
{
    DWORD sum = 0;
    EnumWindows(sum_window, (LPARAM)&sum);
    if (!always && sum == windows_seen) return;
    windows_seen = sum;
    EnumWindows(print_window, 0);
}

/* Prints the lines from `p`, `max` of them at most (0: all); returns where
   it stopped. */
static char *print_lines(char *p, unsigned int max)
{
    char line[220];
    for (unsigned int printed = 0; *p && (max == 0 || printed < max); ++printed) {
        unsigned int n = 0;
        while (p[n] && p[n] != '\n' && n < sizeof(line) - 1) { line[n] = p[n] == '\r' ? ' ' : p[n]; ++n; }
        line[n] = 0;
        if (n) DbgPrint(TAG "  log: %s\n", line);
        p += n;
        while (*p && *p != '\n') ++p;
        if (*p) ++p;
    }
    return p;
}

/* `word` is in the line from `p`, in any case. */
static BOOL line_has(const char *p, const char *word)
{
    for (; *p && *p != '\n'; ++p) {
        unsigned int i = 0;
        while (word[i] && (p[i] | 0x20) == word[i]) ++i;
        if (!word[i]) return TRUE;
    }
    return FALSE;
}

/* The lines from `p` to `end` that tell of a failure. */
static void print_failures(char *p, const char *end)
{
    static const char *const words[] = {"error", "fail", "exception", "rolling back", "abort"};
    while (p < end && *p) {
        BOOL failure = FALSE;
        for (unsigned int i = 0; i < sizeof(words) / sizeof(words[0]); ++i) failure |= line_has(p, words[i]);
        p = failure ? print_lines(p, 1) : p;
        if (!failure) {
            while (*p && *p != '\n') ++p;
            if (*p) ++p;
        }
    }
}

/* The first and the last lines of the installer's log (ANSI or UTF-16): the
   first ones say what the installer is and who runs it, those in between
   that tell of a failure why it stopped, the last ones where. */
static char log_bytes[65536];
static void print_log(void)
{
    char line[220];
    if (!log_path[0]) return;
    HANDLE file = CreateFileW(log_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if (file == INVALID_HANDLE_VALUE) {
        DbgPrint(TAG "no installer log: %s (error %lu)\n", narrow(log_path, line, sizeof(line)), GetLastError());
        return;
    }
    DWORD size = GetFileSize(file, 0), count = 0;
    if (size > sizeof(log_bytes) - 2) SetFilePointer(file, (LONG)(size - (sizeof(log_bytes) - 2)), 0, FILE_BEGIN);
    ReadFile(file, log_bytes, sizeof(log_bytes) - 2, &count, 0);
    CloseHandle(file);
    log_bytes[count] = log_bytes[count + 1] = 0;
    if (count >= 2 && log_bytes[1] == 0) {   /* UTF-16: as ANSI, in place */
        static char converted[sizeof(log_bytes)];
        WideCharToMultiByte(CP_ACP, 0, (WCHAR *)log_bytes, (int)(count / 2), converted, sizeof(converted) - 1, 0, 0);
        converted[sizeof(converted) - 1] = 0;
        for (unsigned int i = 0; i <= length(converted); ++i) log_bytes[i] = converted[i];
        count = length(log_bytes);
    }
    DbgPrint(TAG "installer log, %lu bytes, its first and last lines:\n", size);
    /* Back from the end: 40 lines. */
    unsigned int start = count, lines = 0;
    while (start > 0 && lines < 40) if (log_bytes[--start] == '\n') ++lines;
    char *p = log_bytes;
    if (size <= sizeof(log_bytes) - 2) {   /* the whole log: its first 12 lines too */
        p = print_lines(p, 12);
        if (p < log_bytes + start) {
            DbgPrint(TAG "  log: ...\n");
            print_failures(p, log_bytes + start);
            DbgPrint(TAG "  log: ...\n");
        }
    }
    if (p < log_bytes + start) p = log_bytes + start;
    print_lines(p, 0);
}

/* What a directory holds, two levels down, 80 entries at most. */
static unsigned int listed;
static void list_dir(const WCHAR *dir, unsigned int depth)
{
    WCHAR pattern[MAX_PATH], path[MAX_PATH]; char line[260];
    WIN32_FIND_DATAW found;
    unsigned int n = wlength(dir);
    if (n + 3 >= MAX_PATH) return;
    for (unsigned int i = 0; i < n; ++i) pattern[i] = dir[i];
    pattern[n] = L'\\'; pattern[n + 1] = L'*'; pattern[n + 2] = 0;
    HANDLE find = FindFirstFileW(pattern, &found);
    if (find == INVALID_HANDLE_VALUE) {
        if (depth == 0) DbgPrint(TAG "%s: nothing (error %lu)\n", narrow(dir, line, sizeof(line)), GetLastError());
        return;
    }
    do {
        if (found.cFileName[0] == L'.' && (!found.cFileName[1] || (found.cFileName[1] == L'.' && !found.cFileName[2])))
            continue;
        unsigned int m = wlength(found.cFileName);
        if (n + 1 + m >= MAX_PATH) continue;
        for (unsigned int i = 0; i < n; ++i) path[i] = dir[i];
        path[n] = L'\\';
        for (unsigned int i = 0; i <= m; ++i) path[n + 1 + i] = found.cFileName[i];
        if (++listed > 80) break;
        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DbgPrint(TAG "  dir  %s\n", narrow(path, line, sizeof(line)));
            if (depth < 2) list_dir(path, depth + 1);
        } else {
            DbgPrint(TAG "  file %s (%lu bytes)\n", narrow(path, line, sizeof(line)), found.nFileSizeLow);
        }
    } while (FindNextFileW(find, &found));
    FindClose(find);
}

static void print_free_room(void)
{
    ULARGE_INTEGER free_bytes, total, total_free;
    if (GetDiskFreeSpaceExW(L"C:\\", &free_bytes, &total, &total_free))
        DbgPrint(TAG "C: %lu MiB free of %lu MiB\n", (DWORD)(free_bytes.QuadPart >> 20), (DWORD)(total.QuadPart >> 20));
    else
        DbgPrint(TAG "GetDiskFreeSpaceEx failed (error %lu)\n", GetLastError());
}

/* A visible dialog (#32770: a message box, a wizard page) of `pid`. */
struct find_dialog { DWORD pid; HWND window; };
static BOOL CALLBACK find_dialog_window(HWND window, LPARAM argument)
{
    struct find_dialog *find = (struct find_dialog *)argument;
    WCHAR class_name[16];
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid == find->pid && IsWindowVisible(window) && GetClassNameW(window, class_name, 16) == 6 &&
        class_name[0] == L'#' && class_name[1] == L'3' && class_name[2] == L'2' && class_name[3] == L'7') {
        find->window = window;
        return FALSE;
    }
    return TRUE;
}

/* The default button of a dialog (DM_GETDEFID): Yes in a question box, OK,
   Next or I Agree elsewhere; IDOK without one, or when the dialog's thread
   does not answer within 2 s (a hung installer must not hang the bench). */
#define APPBENCH_DM_GETDEFID 0x0400
#define APPBENCH_DC_HASDEFID 0x534B
static WORD default_button(HWND dialog)
{
    DWORD_PTR id = 0;
    if (!SendMessageTimeoutW(dialog, APPBENCH_DM_GETDEFID, 0, 0, SMTO_ABORTIFHUNG, 2000, &id)) return IDOK;
    return HIWORD(id) == APPBENCH_DC_HASDEFID ? LOWORD(id) : IDOK;
}

/* Runs an installer's command line for `limit` seconds at most. A dialog
   on the screen that has not changed for 10 s is answered as a person
   would, by its default button (DM_GETDEFID: Yes, OK, Next, I Agree), 8
   times at most; its texts are printed first. Returns the exit code. */
static DWORD run_installer(WCHAR *command, DWORD limit)
{
    char line[400];
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup); startup.lpDesktop = L"WinSta0\\Default";
    DbgPrint(TAG "install: %s\n", narrow(command, line, sizeof(line)));
    DWORD started = GetTickCount();
    if (!CreateProcessW(0, command, 0, 0, FALSE, 0, 0, L"C:\\APPS", &startup, &process)) {
        DbgPrint(TAG "the installer did not start (error %lu)\n", GetLastError());
        return 0xFFFFFFFF;
    }
    DbgPrint(TAG "installer started: PID %lu\n", process.dwProcessId);
    DWORD seconds = 0, next_report = 30, last_change = 0, last_sum = 0, answers = 0;
    for (;;) {
        if (WaitForSingleObject(process.hProcess, 1000) == WAIT_OBJECT_0) break;
        seconds = (GetTickCount() - started) / 1000;
        DWORD sum = 0;
        EnumWindows(sum_window, (LPARAM)&sum);
        if (sum != last_sum) { last_sum = sum; last_change = seconds; }
        if (seconds >= next_report) {
            DbgPrint(TAG "still installing after %lu s\n", seconds);
            print_windows(FALSE);
            next_report = seconds + 30;
        }
        struct find_dialog dialog = {process.dwProcessId, 0};
        EnumWindows(find_dialog_window, (LPARAM)&dialog);
        if (dialog.window && seconds - last_change >= 10) {
            if (++answers > 8) {
                DbgPrint(TAG "8 dialogs answered already: the windows, then terminated\n");
                print_windows(TRUE);
                TerminateProcess(process.hProcess, 0xDEAD);
                WaitForSingleObject(process.hProcess, 10000);
                break;
            }
            DbgPrint(TAG "a dialog waits since %lu s: answered with its default button\n", last_change);
            print_windows(TRUE);
            WORD button = default_button(dialog.window);
            PostMessageW(dialog.window, WM_COMMAND, MAKEWPARAM(button, BN_CLICKED),
                         (LPARAM)GetDlgItem(dialog.window, button));
            last_change = seconds;
        }
        if (seconds >= limit) {
            DbgPrint(TAG "installer still running after %lu s: the windows, then terminated\n", seconds);
            print_windows(TRUE);
            TerminateProcess(process.hProcess, 0xDEAD);
            WaitForSingleObject(process.hProcess, 10000);
            break;
        }
    }
    DWORD code = 0;
    GetExitCodeProcess(process.hProcess, &code);
    DbgPrint(TAG "installer ended: exit code %lx after %lu s\n", code, (GetTickCount() - started) / 1000);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}

/* A visible top-level window of `pid` with a title. */
struct find_any { DWORD pid; HWND window; };
static BOOL CALLBACK find_titled(HWND window, LPARAM argument)
{
    struct find_any *find = (struct find_any *)argument;
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid == find->pid && IsWindowVisible(window) && GetWindowTextLengthW(window) > 0) {
        find->window = window;
        return FALSE;
    }
    return TRUE;
}
static BOOL CALLBACK close_window(HWND window, LPARAM pid)
{
    DWORD owner = 0;
    GetWindowThreadProcessId(window, &owner);
    if (owner == (DWORD)pid && IsWindowVisible(window)) PostMessageW(window, WM_CLOSE, 0, 0);
    return TRUE;
}

/* The installed program: its first window, then WM_CLOSE. */
static void run_program(void)
{
    char line[300];
    WCHAR dir[MAX_PATH], command[MAX_PATH + 2];
    unsigned int n = wlength(program), cut = 0;
    for (unsigned int i = 0; i <= n; ++i) {
        dir[i] = program[i];
        if (program[i] == L'\\') cut = i;
    }
    dir[cut] = 0;
    command[0] = L'"';
    for (unsigned int i = 0; i < n; ++i) command[i + 1] = program[i];
    command[n + 1] = L'"'; command[n + 2] = 0;
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup); startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(program, command, 0, 0, FALSE, 0, 0, dir, &startup, &process)) {
        DbgPrint(TAG "the program did not start (error %lu)\n", GetLastError());
        return;
    }
    DbgPrint(TAG "program started: PID %lu\n", process.dwProcessId);
    struct find_any find = {process.dwProcessId, 0};
    DWORD started = GetTickCount();
    while (!find.window && GetTickCount() - started < 90000) {
        if (WaitForSingleObject(process.hProcess, 500) == WAIT_OBJECT_0) break;
        EnumWindows(find_titled, (LPARAM)&find);
    }
    if (find.window) {
        WCHAR title[160], class_name[64]; char b[80];
        GetWindowTextW(find.window, title, 160);
        GetClassNameW(find.window, class_name, 64);
        DbgPrint(TAG "program window after %lu s: class %s, \"%s\"\n", (GetTickCount() - started) / 1000,
                 narrow(class_name, b, sizeof(b)), narrow(title, line, sizeof(line)));
        Sleep(5000);
        print_windows(TRUE);
    }
    DWORD code = 0;
    if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &code);
        DbgPrint(TAG "program ended by itself: exit code %lx\n", code);
    } else if (!find.window) {
        DbgPrint(TAG "program shows no window after 90 s: the windows, then terminated\n");
        print_windows(TRUE);
        TerminateProcess(process.hProcess, 0xDEAD);
    } else {
        EnumWindows(close_window, (LPARAM)process.dwProcessId);
        if (WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0) {
            GetExitCodeProcess(process.hProcess, &code);
            DbgPrint(TAG "program closed: exit code %lx\n", code);
        } else {
            DbgPrint(TAG "program still running 15 s after WM_CLOSE: the windows, then terminated\n");
            print_windows(TRUE);
            TerminateProcess(process.hProcess, 0xDEAD);
        }
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

DWORD WINAPI GuiStartup(void)
{
    char line[300];
    WCHAR temp[MAX_PATH];
    app_desktop();
    read_commands();
    DbgPrint(TAG "%s: the bench starts\n", name);
    /* The installers unpack in %TEMP%: the system's own, created. */
    CreateDirectoryW(L"C:\\WINDOWS\\TEMP", 0);
    if (!GetEnvironmentVariableW(L"TEMP", temp, MAX_PATH)) {
        SetEnvironmentVariableW(L"TEMP", L"C:\\WINDOWS\\TEMP");
        SetEnvironmentVariableW(L"TMP", L"C:\\WINDOWS\\TEMP");
        DbgPrint(TAG "TEMP was not set: C:\\WINDOWS\\TEMP\n");
    } else {
        DbgPrint(TAG "TEMP=%s\n", narrow(temp, line, sizeof(line)));
    }
    print_free_room();
    DWORD code = run_installer(install, timeout_seconds);
    /* A silent NSIS that fails says nothing (an integrity check that fails
       gives 2): its visible run shows why. Not one that ran out of time. */
    if (code != 0 && code != 0xDEAD && visible[0]) {
        DbgPrint(TAG "the silent installation failed: once more, visible\n");
        run_installer(visible, 180);
    }
    print_log();
    print_free_room();
    listed = 0;
    DbgPrint(TAG "C:\\Program Files after the installation:\n");
    list_dir(L"C:\\Program Files", 0);
    if (GetFileAttributesW(program) == INVALID_FILE_ATTRIBUTES) {
        DbgPrint(TAG "not installed: %s\n", narrow(program, line, sizeof(line)));
        if (!(program[0] == L'C' && program[3] == L'P')) {   /* outside Program Files: its parent */
            WCHAR dir[MAX_PATH]; unsigned int n = wlength(program), cut = 0;
            for (unsigned int i = 0; i <= n; ++i) { dir[i] = program[i]; if (program[i] == L'\\') cut = i; }
            dir[cut] = 0;
            listed = 0;
            list_dir(dir, 1);
        }
    } else {
        DbgPrint(TAG "installed: %s\n", narrow(program, line, sizeof(line)));
        run_program();
    }
    DbgPrint(TAG "%s: report done\n", name);
    ExitProcess(0);
    return 0;
}
