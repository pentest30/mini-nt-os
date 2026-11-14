/*
 * M5, console: a Win32 program (subsystem WINDOWS), compiled with MinGW and
 * linked to ReactOS's kernel32 and user32, which the scenario `cmd` puts on
 * the boot disk in the place of winlogon.exe (like `console`, see
 * console1.c). Like winlogon, it takes WinSta0\Default and loads the US
 * keyboard layout; then it starts ReactOS's cmd.exe by CreateProcessW, with
 * `/K C:\READ1.EXE`: cmd runs READ1.EXE (read1.c) in its console, which says
 * when the console window waits for keys, then reads the commands that the
 * scenario types (`keys =`), until `exit`. The commands write their results
 * to files of C:, which this program then reads, one line of the debug port
 * (DbgPrint) for each line, where the scenario looks for it; it ends with
 * EXIT_STATUS.
 *
 * What the root of C: holds changes with the test programs that xtask puts
 * there and with the files the kernel's self-tests write: the listings are
 * printed without line numbers (C:\LIST.TXT) or checked here (C:\DIR.TXT:
 * the summary of `dir` counts what it lists), so that the scenario looks
 * for no number that moves with them.
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
typedef void *HANDLE;
typedef void *HWINSTA;
typedef void *HDESK;
typedef void *HKL;

typedef struct {
    DWORD cb;
    WCHAR *lpReserved;
    WCHAR *lpDesktop;
    WCHAR *lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    BYTE *lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW;

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION;

#define MAXIMUM_ALLOWED 0x02000000
#define GENERIC_READ 0x80000000
#define FILE_WRITE_ATTRIBUTES 0x0100
#define FILE_BASIC_INFORMATION_CLASS 4
#define FILE_SHARE_READ 1
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x80
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define KLF_ACTIVATE 0x00000001
#define CMD_WAIT 100000
#define EXIT_STATUS 0x600D
/* The longest file read (a listing of the root, some 50 bytes for each of its
   files), and the longest line printed. */
#define FILE_BYTES 65536
#define LINE_BYTES 160

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
/* An IO_STATUS_BLOCK: the status, then the information. */
typedef struct {
    long Status;
    DWORD Information;
} IO_STATUS_BLOCK;
__declspec(dllimport) long __stdcall NtSetInformationFile(HANDLE file, IO_STATUS_BLOCK *status, void *information,
                                                          DWORD length, DWORD file_information_class);

__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *attributes,
                                                   DWORD disposition, DWORD flags, HANDLE template_file);
__declspec(dllimport) BOOL __stdcall CreateProcessW(const WCHAR *application, WCHAR *command_line, void *process_attributes,
                                                    void *thread_attributes, BOOL inherit_handles, DWORD flags,
                                                    void *environment, const WCHAR *directory,
                                                    STARTUPINFOW *startup_info, PROCESS_INFORMATION *information);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) BOOL __stdcall GetExitCodeProcess(HANDLE process, DWORD *code);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE file, void *buffer, DWORD count, DWORD *read, void *overlapped);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
__declspec(dllimport) HKL __stdcall LoadKeyboardLayoutW(const WCHAR *name, UINT flags);
__declspec(dllimport) BOOL __stdcall RegisterLogonProcess(DWORD process, BOOL logon);
__declspec(dllimport) BOOL __stdcall SetProcessWindowStation(HWINSTA station);
__declspec(dllimport) BOOL __stdcall SetThreadDesktop(HDESK desktop);
__declspec(dllimport) BOOL __stdcall SwitchDesktop(HDESK desktop);

void *memset(void *destination, int value, unsigned int count)
{
    unsigned char *bytes = destination;
    while (count--)
        *bytes++ = (unsigned char)value;
    return destination;
}

/* Like winlogon: the logon process, WinSta0, a desktop, on it, and the
   keyboard layout of the console's keys. */
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
    DbgPrint("[concmd] on WinSta0\\Default\n");
    if (!LoadKeyboardLayoutW(L"00000409", KLF_ACTIVATE))
        return 0;
    return 1;
}

/* The last file read, its `read` bytes. */
static char bytes[FILE_BYTES];
static DWORD read;

/* The file `name` in `bytes`, at most FILE_BYTES of it; whether it opened.
   `tag` names it on the debug port. */
static BOOL read_file(const WCHAR *name, const char *tag)
{
    HANDLE file = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    read = 0;
    if (file == INVALID_HANDLE_VALUE) {
        DbgPrint("[concmd] %s: CreateFileW: error %lu\n", tag, GetLastError());
        return 0;
    }
    if (!ReadFile(file, bytes, FILE_BYTES, &read, 0))
        DbgPrint("[concmd] %s: ReadFile: error %lu\n", tag, GetLastError());
    CloseHandle(file);
    DbgPrint("[concmd] %s: %lu bytes\n", tag, read);
    if (read == FILE_BYTES)
        DbgPrint("[concmd] %s: too long, cut at %lu bytes\n", tag, read);
    return 1;
}

/* The line of `bytes` at `*at` in `line`, without its end (CR, LF), cut at
   LINE_BYTES, and `*at` past it; 0 after the last line. */
static BOOL next_line(DWORD *at, char *line)
{
    DWORD length = 0;

    if (*at >= read)
        return 0;
    for (; *at < read && bytes[*at] != '\n'; ++*at)
        if (bytes[*at] != '\r' && length < LINE_BYTES)
            line[length++] = bytes[*at];
    if (*at < read)
        ++*at;
    line[length] = 0;
    return 1;
}

/* One line of the debug port for each line of `bytes`, after `tag` and, if
   `numbered`, the line's number (from 1). */
static void print_lines(const char *tag, BOOL numbered)
{
    char line[LINE_BYTES + 1];
    DWORD at = 0;
    DWORD number = 0;

    while (next_line(&at, line)) {
        if (numbered)
            DbgPrint("[concmd] %s %lu: %s\n", tag, ++number, line);
        else
            DbgPrint("[concmd] %s: %s\n", tag, line);
    }
}

/* Whether `text` holds `part`. */
static BOOL holds(const char *text, const char *part)
{
    const char *t;
    const char *p;

    for (; *text; text++) {
        for (t = text, p = part; *p && *t == *p; t++, p++)
            ;
        if (!*p)
            return 1;
    }
    return 0;
}

/* The number at the start of `line`, after its blanks. */
static DWORD leading_number(const char *line)
{
    DWORD number = 0;

    while (*line == ' ')
        line++;
    for (; *line >= '0' && *line <= '9'; line++)
        number = number * 10 + (DWORD)(*line - '0');
    return number;
}

/* Whether each line of `bytes`, a name, ends with `extension` (in capitals),
   whatever its case: a line of the debug port for each one that does not. */
static void check_extension(const char *tag, const char *extension)
{
    char line[LINE_BYTES + 1];
    DWORD at = 0;
    DWORD length;
    DWORD size;
    DWORD i;

    for (size = 0; extension[size]; size++)
        ;
    while (next_line(&at, line)) {
        for (length = 0; line[length]; length++)
            ;
        for (i = 0; i < size && length >= size; i++) {
            char c = line[length - size + i];
            if (c >= 'a' && c <= 'z')
                c = (char)(c - 'a' + 'A');
            if (c != extension[i])
                break;
        }
        if (length < size || i < size)
            DbgPrint("[concmd] %s: not a %s file: %s\n", tag, extension, line);
    }
}

/* Whether the summary of the listing of `dir` in `bytes` counts what it lists:
   its lines of files and directories begin with their date (a digit), and
   the directories show <DIR>; File(s) and Dir(s) begin with their number. */
static void check_summary(const char *tag)
{
    char line[LINE_BYTES + 1];
    DWORD at = 0;
    DWORD files = 0;
    DWORD dirs = 0;
    DWORD files_counted = 0;
    DWORD dirs_counted = 0;
    BOOL files_line = 0;
    BOOL dirs_line = 0;

    while (next_line(&at, line)) {
        if (line[0] >= '0' && line[0] <= '9') {
            if (holds(line, "<DIR>"))
                dirs++;
            else
                files++;
        } else if (holds(line, " File(s) ")) {
            files_counted = leading_number(line);
            files_line = 1;
        } else if (holds(line, " Dir(s) ")) {
            dirs_counted = leading_number(line);
            dirs_line = 1;
        }
    }
    if (!files_line || !dirs_line)
        DbgPrint("[concmd] %s: the summary does not count what is listed: no File(s) or Dir(s) line\n", tag);
    else if (files != files_counted || dirs != dirs_counted)
        DbgPrint("[concmd] %s: the summary does not count what is listed: %lu files and %lu directories listed, "
                 "%lu and %lu counted\n",
                 tag, files, dirs, files_counted, dirs_counted);
    else
        DbgPrint("[concmd] %s: the summary counts what is listed: %lu files, %lu directories\n", tag, files, dirs);
}

/* NtSetInformationFile(FileBasicInformation) with its FILE_BASIC_INFORMATION
 * on a 4-byte boundary that is not an 8-byte one, where x86 compilers may
 * leave a structure of LARGE_INTEGERs on the stack (kernel32's CopyFileW
 * does): the kernel takes it. All zero: nothing changes. */
static void check_basic_information_alignment(void)
{
    DWORD storage[16];
    unsigned char *at = (unsigned char *)storage;
    IO_STATUS_BLOCK status_block;
    HANDLE file = CreateFileW(L"C:\\WINDOWS\\SYSTEM32\\CMD.EXE", GENERIC_READ | FILE_WRITE_ATTRIBUTES,
                              FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    long status;

    if (((unsigned long)at & 7) == 0)
        at += 4;
    memset(at, 0, 40);
    if (file == INVALID_HANDLE_VALUE) {
        DbgPrint("[concmd] FILE_BASIC_INFORMATION on a 4-byte boundary: CreateFileW: error %lu\n", GetLastError());
        return;
    }
    status = NtSetInformationFile(file, &status_block, at, 40, FILE_BASIC_INFORMATION_CLASS);
    DbgPrint("[concmd] FILE_BASIC_INFORMATION on a 4-byte boundary: %lx\n", (DWORD)status);
    CloseHandle(file);
}

DWORD __stdcall GuiStartup(void)
{
    static WCHAR command_line[] = L"cmd /K C:\\READ1.EXE";
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD wait;
    DWORD code = 0;

    if (!take_a_desktop())
        ExitProcess(1);
    check_basic_information_alignment();
    memset(&startup, 0, sizeof startup);
    startup.cb = sizeof startup;
    startup.lpDesktop = L"WinSta0\\Default";
    if (!CreateProcessW(L"C:\\WINDOWS\\SYSTEM32\\CMD.EXE", command_line, 0, 0, 0, 0, 0, L"C:\\", &startup,
                        &process)) {
        DbgPrint("[concmd] CreateProcessW: error %lu\n", GetLastError());
        ExitProcess(2);
    }
    DbgPrint("[concmd] CMD.EXE started\n");
    wait = WaitForSingleObject(process.hProcess, CMD_WAIT);
    if (!GetExitCodeProcess(process.hProcess, &code))
        DbgPrint("[concmd] GetExitCodeProcess: error %lu\n", GetLastError());
    DbgPrint("[concmd] CMD.EXE: wait %lu, exit code %lx\n", wait, code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (read_file(L"C:\\OUT.TXT", "OUT.TXT"))
        print_lines("OUT.TXT", 1);
    if (read_file(L"C:\\LIST.TXT", "LIST.TXT")) {
        print_lines("LIST.TXT", 0);
        check_extension("LIST.TXT", ".TXT");
    }
    if (read_file(L"C:\\DIR.TXT", "DIR.TXT")) {
        print_lines("DIR.TXT", 1);
        check_summary("DIR.TXT");
    }
    ExitProcess(EXIT_STATUS);
    return 0;
}
