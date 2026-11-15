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
 * - C:\WINDOWS\SYSTEM32\NT* gives at least NTDLL.DLL; an exact name gives
 *   its size back, and its 8.3 name as the alternate name, as ReactOS's
 *   vfatfs gives it for every entry (it was empty for an 8.3 name);
 * - a file created as readme.txt and a directory created as Recent come
 *   back in their case: readme.txt by the NT case flags of its 8.3 entry,
 *   its alternate name readme.txt too; Recent by its long name, its
 *   alternate name RECENT;
 * - a name nothing matches fails with ERROR_FILE_NOT_FOUND;
 * - the whole enumeration again, restarted, gives the same entries;
 * - NtSetInformationFile(FileBasicInformation) takes a buffer aligned on 4
 *   bytes only, as an i386 stack gives kernel32's CopyFileW its local one
 *   (sizeof(ULONG), as ReactOS probes it): asking 8, Mino's kernel refused
 *   it with STATUS_DATATYPE_MISALIGNMENT, and CopyFileW failed.
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
#define FILE_WRITE_ATTRIBUTES 0x100
#define OPEN_EXISTING 3
#define CREATE_NEW 1
#define GENERIC_WRITE 0x40000000
#define FILE_ATTRIBUTE_NORMAL 0x80
#define FILE_BASIC_INFORMATION_CLASS 4
/* FILE_BASIC_INFORMATION: four times and the attributes, 40 bytes. */
#define FILE_BASIC_INFORMATION_SIZE 40

typedef struct {
    LONG status;
    DWORD information;
} IO_STATUS_BLOCK;

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall FindClose(HANDLE find);
__declspec(dllimport) HANDLE __stdcall FindFirstFileW(const WCHAR *pattern, FIND_DATA *data);
__declspec(dllimport) BOOL __stdcall FindNextFileW(HANDLE find, FIND_DATA *data);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *security,
                                                   DWORD disposition, DWORD flags, HANDLE template_file);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) BOOL __stdcall CreateDirectoryW(const WCHAR *name, void *security);
__declspec(dllimport) LONG __stdcall NtSetInformationFile(HANDLE file, IO_STATUS_BLOCK *status, void *information,
                                                          DWORD length, DWORD information_class);

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

/* Are two wide strings the same, case included? */
static BOOL exact_name(const WCHAR *a, const WCHAR *b)
{
    unsigned int i;
    for (i = 0; a[i] && a[i] == b[i]; i++)
        ;
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

/* NtSetInformationFile(FileBasicInformation) of KERNEL.BIN from a buffer at
 * 4 bytes past a multiple of 8, all zero: each time and the attributes as
 * they are. Its status. */
static LONG set_basic_information_aligned_on_four(void)
{
    unsigned char room[FILE_BASIC_INFORMATION_SIZE + 12];
    unsigned char *information = (unsigned char *)((((unsigned long)room + 7) & ~7ul) + 4);
    IO_STATUS_BLOCK status_block;
    HANDLE file = CreateFileW(L"C:\\KERNEL.BIN", FILE_WRITE_ATTRIBUTES, 7, 0, OPEN_EXISTING, 0, 0);
    LONG status;

    if (file == INVALID_HANDLE_VALUE)
        return -1;
    memset(information, 0, FILE_BASIC_INFORMATION_SIZE);
    status = NtSetInformationFile(file, &status_block, information, FILE_BASIC_INFORMATION_SIZE,
                                  FILE_BASIC_INFORMATION_CLASS);
    CloseHandle(file);
    return status;
}

/* Creates `path` (a directory with `directory`), finds it again by its
 * path, and reports the name and the alternate name it comes back with:
 * true if they are `name` and `alternate`, case included. */
static BOOL report_case(const WCHAR *path, BOOL directory, const WCHAR *name, const WCHAR *alternate)
{
    FIND_DATA data;
    HANDLE found;
    char shown[MAX_PATH], shown_alternate[14];

    if (directory) {
        if (!CreateDirectoryW(path, 0))
            return 0;
    } else {
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
        if (file == INVALID_HANDLE_VALUE)
            return 0;
        CloseHandle(file);
    }
    memset(&data, 0, sizeof data);
    found = FindFirstFileW(path, &data);
    if (found == INVALID_HANDLE_VALUE)
        return 0;
    FindClose(found);
    ascii(data.file_name, shown, sizeof shown);
    ascii(data.alternate_file_name, shown_alternate, sizeof shown_alternate);
    DbgPrint("[dir] created %s, alternate %s\n", shown, shown_alternate);
    return exact_name(data.file_name, name) && exact_name(data.alternate_file_name, alternate);
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

    /* A directory of the system. An entry already named in 8.3 form still
     * has its 8.3 name in FILE_BOTH_DIR_INFORMATION, as vfatfs gives it. */
    count = enumerate(L"C:\\WINDOWS\\SYSTEM32\\NT*", L"NTDLL.DLL");
    DbgPrint("[dir] SYSTEM32\\NT*: %d entries\n", count);
    if (count < 1)
        ExitProcess(6);
    memset(&data, 0, sizeof data);
    if (FindFirstFileW(L"C:\\WINDOWS\\SYSTEM32\\NTDLL.DLL", &data) == INVALID_HANDLE_VALUE)
        ExitProcess(7);
    ascii(data.alternate_file_name, alternate, sizeof alternate);
    DbgPrint("[dir] NTDLL.DLL: %lu bytes, alternate %s\n", data.size_low, alternate);
    if (!exact_name(data.alternate_file_name, L"NTDLL.DLL") || data.size_low == 0)
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

    DbgPrint("[dir] FileBasicInformation aligned on 4: %lx\n", (DWORD)set_basic_information_aligned_on_four());

    if (!report_case(L"C:\\readme.txt", 0, L"readme.txt", L"readme.txt"))
        ExitProcess(12);
    if (!report_case(L"C:\\Recent", 1, L"Recent", L"RECENT"))
        ExitProcess(13);

    DbgPrint("[dir] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
