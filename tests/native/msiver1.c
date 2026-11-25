/*
 * The Windows Installer version as the setup loader of Apache OpenOffice
 * 4.1 reads it (main/desktop/win32/source/setup/aoo_msi.cxx and setup.cpp,
 * Apache-licensed): the directory of msi.dll from
 * HKLM\Software\Microsoft\Windows\CurrentVersion\Installer, value
 * InstallerLocation (no other place is tried), LoadLibrary of
 * <InstallerLocation>\msi.dll, GetProcAddress of DllGetVersion, then
 * DllGetVersion on a DLLVERSIONINFO of which only cbSize is set, printed as
 * "%d.%d.%4d". Without the value, the loader returned
 * HRESULT_FROM_WIN32(GetLastError()), 0 when no error was pending, and
 * showed the uninitialised structure: "You have Windows Installer
 * '0.1244568.1244716' on your system!". syssetup.inf writes the value at
 * installation ([RegistrationPhase2] AddReg=Classes : %11%).
 * A Win32 program (subsystem WINDOWS) that the scenario `installer-location`
 * runs as the shell of the logged-on user (session), on the disk of an
 * application of the bench, which has msi.dll. Each result goes to the
 * debug port (DbgPrint), where the scenario looks for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef long NTSTATUS;
typedef long HRESULT;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HMODULE;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} UNICODE_STRING;

typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    ULONG Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    WCHAR Data[260];
} KEY_VALUE_PARTIAL_INFORMATION;

typedef struct {
    DWORD cbSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformID;
} DLLVERSIONINFO;

typedef HRESULT(__stdcall *DLLGETVERSIONPROC)(DLLVERSIONINFO *);

#define OBJ_CASE_INSENSITIVE 0x40
#define KEY_READ 0x20019
#define KeyValuePartialInformation 2
#define REG_SZ 1

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) NTSTATUS __stdcall NtOpenKey(HANDLE *key, ULONG access, OBJECT_ATTRIBUTES *attributes);
__declspec(dllimport) NTSTATUS __stdcall NtQueryValueKey(HANDLE key, UNICODE_STRING *name, ULONG kind, void *out,
                                                         ULONG length, ULONG *result);
__declspec(dllimport) NTSTATUS __stdcall NtClose(HANDLE handle);

__declspec(dllimport) void __stdcall ExitProcess(DWORD code);
__declspec(dllimport) HMODULE __stdcall LoadLibraryW(const WCHAR *name);
__declspec(dllimport) void *__stdcall GetProcAddress(HMODULE module, const char *name);

static USHORT length_of(const WCHAR *text)
{
    USHORT n = 0;
    while (text[n])
        n++;
    return n;
}

static void init_string(UNICODE_STRING *string, WCHAR *text)
{
    string->Buffer = text;
    string->Length = (USHORT)(length_of(text) * sizeof(WCHAR));
    string->MaximumLength = string->Length + sizeof(WCHAR);
}

/* The narrow copy of `text` (ASCII), for DbgPrint. */
static char *narrow(const WCHAR *text, char *out, int size)
{
    int i;
    for (i = 0; text[i] && i < size - 1; i++)
        out[i] = text[i] < 0x80 ? (char)text[i] : '?';
    out[i] = 0;
    return out;
}

/* getInstallerLocation: InstallerLocation, a REG_SZ, into `location`. */
static BOOL installer_location(WCHAR *location, int size)
{
    static WCHAR key_name[] = L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer";
    static WCHAR value_name[] = L"InstallerLocation";
    UNICODE_STRING name, value;
    OBJECT_ATTRIBUTES attributes = {sizeof attributes, 0, &name, OBJ_CASE_INSENSITIVE, 0, 0};
    KEY_VALUE_PARTIAL_INFORMATION info;
    HANDLE key;
    ULONG used = 0, i, count;
    NTSTATUS status;

    init_string(&name, key_name);
    status = NtOpenKey(&key, KEY_READ, &attributes);
    if (status < 0) {
        DbgPrint("[msiver] no key Installer (%lx)\n", status);
        return 0;
    }
    init_string(&value, value_name);
    status = NtQueryValueKey(key, &value, KeyValuePartialInformation, &info, sizeof info, &used);
    NtClose(key);
    if (status < 0 || info.Type != REG_SZ) {
        DbgPrint("[msiver] no value InstallerLocation (%lx)\n", status);
        return 0;
    }
    count = info.DataLength / sizeof(WCHAR);
    for (i = 0; i < count && i < (ULONG)size - 1 && info.Data[i]; i++)
        location[i] = info.Data[i];
    location[i] = 0;
    return 1;
}

DWORD __stdcall GuiStartup(void)
{
    static const WCHAR msi[] = L"\\msi.dll";
    WCHAR path[300];
    char line[300];
    DLLVERSIONINFO info;
    DLLGETVERSIONPROC get_version;
    HMODULE module;
    HRESULT result;
    int n, i;

    if (!installer_location(path, 260)) {
        DbgPrint("[msiver] done\n");
        ExitProcess(1);
    }
    DbgPrint("[msiver] InstallerLocation %s\n", narrow(path, line, sizeof line));
    n = length_of(path);
    for (i = 0; msi[i]; i++)
        path[n + i] = msi[i];
    path[n + i] = 0;
    module = LoadLibraryW(path);
    get_version = module ? (DLLGETVERSIONPROC)GetProcAddress(module, "DllGetVersion") : 0;
    if (!get_version) {
        DbgPrint("[msiver] no DllGetVersion in %s\n", narrow(path, line, sizeof line));
        DbgPrint("[msiver] done\n");
        ExitProcess(2);
    }
    /* setup.cpp's CheckVersion: only cbSize set. */
    info.dwMajorVersion = info.dwMinorVersion = info.dwBuildNumber = 0xDEAD;
    info.cbSize = sizeof info;
    result = get_version(&info);
    DbgPrint("[msiver] DllGetVersion %lx: %d.%d.%4d\n", result, (int)info.dwMajorVersion, (int)info.dwMinorVersion,
             (int)info.dwBuildNumber);
    DbgPrint("[msiver] done\n");
    ExitProcess(0);
    return 0;
}
