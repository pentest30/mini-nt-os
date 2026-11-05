/*
 * The installation wave, F1: a Win32 program (subsystem WINDOWS), compiled
 * with MinGW and linked to ReactOS's kernel32 and user32, which the
 * scenario `dir` puts on the boot disk in the place of winlogon.exe (like
 * GUI1.EXE and TEXT1.EXE). Like winlogon it registers as the logon process
 * and takes a desktop, then works with the directory enumeration
 * (NtQueryDirectoryFile, FileBothDirectoryInformation, as FindFirstFile of
 * kernel32 asks it):
 * - C:\* gives every entry but `.` and `..`, KERNEL.BIN, TEST.EXE,
 *   CMD.EXE and the WINDOWS directory among them;
 * - C:\*.EXE gives only the .EXE files;
 * - C:\KERNEL.BIN, an exact name, gives the file and its size;
 * - C:\WINDOWS\SYSTEM32\NT* gives at least NTDLL.DLL, whose 8.3 name and
 *   size an exact name gives back;
 * - a name nothing matches fails with ERROR_FILE_NOT_FOUND;
 * - the whole enumeration again, restarted, gives the same entries.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; the program ends with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int BOOL;
typedef long LONG;
typedef void *HANDLE;
typedef void *HWINSTA;
typedef void *HDESK;

typedef struct {
    DWORD low;
    DWORD high;
} FILETIME;

#define MAX_PATH 260
typedef struct {
    DWORD attributes;
    FILETIME creation;
    FILETIME access;
    FILETIME write;
    DWORD size_high;
    DWORD size_low;
    DWORD reserved0;
    DWORD reserved1;
    WCHAR file_name[MAX_PATH];
    WCHAR alternate_file_name[14];
} FIND_DATA;

#define MAXIMUM_ALLOWED 0x02000000
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define ERROR_FILE_NOT_FOUND 2
#define EXIT_STATUS 0x600D

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall FindClose(HANDLE find);
__declspec(dllimport) HANDLE __stdcall FindFirstFileW(const WCHAR *pattern, FIND_DATA *data);
__declspec(dllimport) BOOL __stdcall FindNextFileW(HANDLE find, FIND_DATA *data);

__declspec(dllimport) HDESK __stdcall CreateDesktopW(const WCHAR *name, const WCHAR *device, void *mode, DWORD flags,
                                                     DWORD access, void *attributes);
__declspec(dllimport) HWINSTA __stdcall CreateWindowStationW(const WCHAR *name, DWORD flags, DWORD access,
                                                             void *attributes);
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

void *memcpy(void *destination, const void *source, unsigned int count)
{
    unsigned char *to = destination;
    const unsigned char *from = source;
    while (count--)
        *to++ = *from++;
    return destination;
}

/* Are two wide strings the same, case aside? */
static BOOL same_name(const WCHAR *a, const WCHAR *b)
{
    unsigned int i;
    for (i = 0; a[i] && b[i]; i++) {
        WCHAR ca = a[i], cb = b[i];
        if (ca >= 'a' && ca <= 'z')
            ca -= 'a' - 'A';
        if (cb >= 'a' && cb <= 'z')
            cb -= 'a' - 'A';
        if (ca != cb)
            return 0;
    }
    return a[i] == b[i];
}

/* A wide name as ASCII, for the debug port (the names here are ASCII). */
static void ascii(const WCHAR *wide, char *out, unsigned int room)
{
    unsigned int i;
    for (i = 0; i + 1 < room && wide[i]; i++)
        out[i] = (char)(wide[i] <= 0x7F ? wide[i] : '?');
    out[i] = 0;
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
    DbgPrint("[dir] on WinSta0\\Default\n");
    return 1;
}

/* The name an enumeration looks for, printed when it comes. */
static const WCHAR *watched;

static BOOL watching(const WCHAR *name)
{
    return watched && same_name(name, watched);
}

/* Enumerates `pattern`, one entry at a time; `watch` names the entry whose
 * presence is printed. Returns how many entries it saw, or -1 if
 * FindFirstFileW itself failed. */
static int enumerate(const WCHAR *pattern, const WCHAR *watch)
{
    FIND_DATA data;
    HANDLE find;
    int count = 0;

    watched = watch;
    memset(&data, 0, sizeof data);
    find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return -1;
    do {
        char name[MAX_PATH];
        ascii(data.file_name, name, sizeof name);
        if (same_name(data.file_name, L".") || same_name(data.file_name, L"..")) {
            DbgPrint("[dir] a dot entry came back: %s\n", name);
        } else {
            if (watching(data.file_name))
                DbgPrint("[dir] %s: seen\n", name);
            count++;
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return count;
}

DWORD __stdcall GuiStartup(void)
{
    FIND_DATA data;
    char alternate[14];
    int count;

    if (!take_a_desktop())
        ExitProcess(1);

    /* Everything of the root, but never a dot entry. */
    count = enumerate(L"C:\\*", L"KERNEL.BIN");
    DbgPrint("[dir] C:\\*: %d entries\n", count);
    if (count < 4)
        ExitProcess(2);

    /* A pattern keeps only what it matches: the .EXE of the root, and only
     * them (the star of DOS, which FindFirstFile sends as `<`). */
    count = enumerate(L"C:\\*.EXE", L"TEST.EXE");
    DbgPrint("[dir] C:\\*.EXE: %d entries\n", count);
    if (count < 2)
        ExitProcess(3);

    /* An exact name gives the file, and its size. */
    memset(&data, 0, sizeof data);
    if (FindFirstFileW(L"C:\\KERNEL.BIN", &data) == INVALID_HANDLE_VALUE)
        ExitProcess(4);
    DbgPrint("[dir] KERNEL.BIN: %lu bytes\n", data.size_low);
    if (data.size_low != 4)
        ExitProcess(5);

    /* A directory of the system, and the 8.3 name of an entry. */
    count = enumerate(L"C:\\WINDOWS\\SYSTEM32\\NT*", L"NTDLL.DLL");
    DbgPrint("[dir] SYSTEM32\\NT*: %d entries\n", count);
    if (count < 1)
        ExitProcess(6);
    memset(&data, 0, sizeof data);
    if (FindFirstFileW(L"C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL", &data) == INVALID_HANDLE_VALUE)
        ExitProcess(7);
    ascii(data.alternate_file_name, alternate, sizeof alternate);
    DbgPrint("[dir] NTDLL.DLL: %lu bytes, alternate %s\n", data.size_low, alternate);
    if (!same_name(data.alternate_file_name, L"NTDLL.DLL") || data.size_low == 0)
        ExitProcess(8);

    /* A name nothing matches fails as the callers expect. */
    memset(&data, 0, sizeof data);
    if (FindFirstFileW(L"C:\\ZZ*", &data) != INVALID_HANDLE_VALUE)
        ExitProcess(9);
    DbgPrint("[dir] C:\\ZZ*: error %lu\n", GetLastError());
    if (GetLastError() != ERROR_FILE_NOT_FOUND)
        ExitProcess(10);

    /* The whole enumeration again: a new handle scans from the start, the
     * same entries. */
    count = enumerate(L"C:\\*", L"WINDOWS");
    DbgPrint("[dir] C:\\* again: %d entries\n", count);
    if (count < 4)
        ExitProcess(11);

    DbgPrint("[dir] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
