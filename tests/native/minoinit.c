/*
 * MINOINIT.EXE, the end of Mino's installation (ADR-023): winlogon starts it
 * in setup mode, on the first boot (SYSTEM\Setup: SetupType = 1, CmdLine =
 * %SystemRoot%\system32\minoinit.exe, from tools/mkhive/mino.inf). It does
 * the part of ReactOS's InstallReactOS (syssetup, as a specification) that
 * the logon needs, then reboots; on the next boot, winlogon goes to the
 * logon of Administrator:
 *
 * 1. samsrv made the accounts in setup mode (SampInitializeSAM): wait for
 *    the value Administrator of SAM\Domains\Account\Users\Names;
 * 2. the profiles: userenv's InitializeProfiles (ordinal 100), which
 *    creates the profiles directory, Default User and All Users, and writes
 *    ProfileList and the shell folders of HKU\.DEFAULT;
 * 3. the hive of Default User: HKU\.DEFAULT written back to its file
 *    (NtFlushKey), copied as NTUSER.DAT in the Default User profile
 *    (syssetup's SaveDefaultUserHive saves the key itself, RegSaveKeyEx);
 * 4. setup done: SetupType = 0, SystemSetupInProgress = 0, CmdLine empty;
 * 5. the hives written back to their files (NtFlushKey), then a reboot
 *    (NtShutdownSystem).
 *
 * Each step says how it went by DbgPrint ("[minoinit] ..."); a failed step
 * stops the program without the reboot.
 *
 * Built by `cargo xtask` without a C runtime: -nostdlib, entry point
 * GuiStartup; placed in WINDOWS\SYSTEM32 (xtask/src/native.rs).
 */

typedef unsigned long DWORD;
typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef long LONG;
typedef int BOOL;
typedef void *HANDLE;
typedef void *HMODULE;
typedef LONG NTSTATUS;

typedef struct {
    unsigned short Length;
    unsigned short MaximumLength;
    const WCHAR *Buffer;
} UNICODE_STRING;

typedef struct {
    DWORD Length;
    HANDLE RootDirectory;
    UNICODE_STRING *ObjectName;
    DWORD Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

/* KeyValuePartialInformation, with room for a REG_DWORD. */
typedef struct {
    DWORD TitleIndex;
    DWORD Type;
    DWORD DataLength;
    DWORD Data;
} KEY_VALUE_PARTIAL_INFORMATION;
#define KEY_VALUE_PARTIAL_INFORMATION_CLASS 2

#define OBJ_CASE_INSENSITIVE 0x40
#define MAXIMUM_ALLOWED 0x02000000
#define REG_SZ 1
#define REG_DWORD 4
#define SHUTDOWN_REBOOT 1
#define NT_SUCCESS(status) ((status) >= 0)

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) NTSTATUS __stdcall NtOpenKey(HANDLE *key, DWORD access, OBJECT_ATTRIBUTES *attributes);
__declspec(dllimport) NTSTATUS __stdcall NtSetValueKey(HANDLE key, UNICODE_STRING *name, DWORD title_index,
                                                       DWORD type, const void *data, DWORD size);
__declspec(dllimport) NTSTATUS __stdcall NtQueryValueKey(HANDLE key, UNICODE_STRING *name, DWORD information_class,
                                                         void *information, DWORD size, DWORD *result_size);
__declspec(dllimport) NTSTATUS __stdcall NtFlushKey(HANDLE key);
__declspec(dllimport) NTSTATUS __stdcall NtClose(HANDLE handle);
__declspec(dllimport) NTSTATUS __stdcall NtShutdownSystem(DWORD action);

__declspec(dllimport) HMODULE __stdcall LoadLibraryW(const WCHAR *name);
__declspec(dllimport) void *__stdcall GetProcAddress(HMODULE module, const char *name);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall CopyFileW(const WCHAR *from, const WCHAR *to, BOOL fail_if_exists);
__declspec(dllimport) DWORD __stdcall ExpandEnvironmentStringsW(const WCHAR *from, WCHAR *to, DWORD size);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);

typedef BOOL(__stdcall *InitializeProfilesFn)(void);
typedef BOOL(__stdcall *GetDefaultUserProfileDirectoryWFn)(WCHAR *path, DWORD *size);

/* How long samsrv may take to make the accounts. */
#define SAM_WAIT_MS 30000
#define SAM_POLL_MS 250

static DWORD length(const WCHAR *text)
{
    DWORD n = 0;
    while (text[n])
        ++n;
    return n;
}

static void append(WCHAR *to, DWORD size, const WCHAR *text)
{
    DWORD at = length(to);
    while (*text && at + 1 < size)
        to[at++] = *text++;
    to[at] = 0;
}

/* `text` as ASCII, for DbgPrint (the paths here are ASCII). */
static const char *ascii(const WCHAR *text)
{
    static char buffer[260];
    DWORD n = 0;
    while (text[n] && n + 1 < sizeof buffer) {
        buffer[n] = text[n] < 0x80 ? (char)text[n] : '?';
        ++n;
    }
    buffer[n] = 0;
    return buffer;
}

static NTSTATUS open_key(const WCHAR *path, HANDLE *key)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    name.Length = (unsigned short)(length(path) * 2);
    name.MaximumLength = name.Length + 2;
    name.Buffer = path;
    attributes.Length = sizeof attributes;
    attributes.RootDirectory = 0;
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.SecurityDescriptor = 0;
    attributes.SecurityQualityOfService = 0;
    return NtOpenKey(key, MAXIMUM_ALLOWED, &attributes);
}

static NTSTATUS set_value(HANDLE key, const WCHAR *value_name, DWORD type, const void *data, DWORD size)
{
    UNICODE_STRING name;
    name.Length = (unsigned short)(length(value_name) * 2);
    name.MaximumLength = name.Length + 2;
    name.Buffer = value_name;
    return NtSetValueKey(key, &name, 0, type, data, size);
}

/* Writes the hive of the key at `path` back to its file. */
static NTSTATUS flush(const WCHAR *path)
{
    HANDLE key;
    NTSTATUS status = open_key(path, &key);
    if (NT_SUCCESS(status)) {
        status = NtFlushKey(key);
        NtClose(key);
    }
    DbgPrint("[minoinit] NtFlushKey %s: %lx\n", ascii(path), (DWORD)status);
    return status;
}

static void stop(const char *why)
{
    DbgPrint("[minoinit] stopped: %s\n", why);
    ExitProcess(1);
}

/* How far samsrv went: which keys of its database exist. */
static void report_the_sam(void)
{
    static const WCHAR *const keys[] = {
        L"\\Registry\\Machine\\SAM\\SAM",
        L"\\Registry\\Machine\\SAM\\SAM\\Domains",
        L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Builtin",
        L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account",
        L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users",
        L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\Names",
        L"\\Registry\\Machine\\SECURITY\\Policy",
    };
    DWORD i;
    for (i = 0; i < sizeof keys / sizeof keys[0]; ++i) {
        HANDLE key;
        NTSTATUS status = open_key(keys[i], &key);
        if (NT_SUCCESS(status))
            NtClose(key);
        DbgPrint("[minoinit] %s: %lx\n", ascii(keys[i]), (DWORD)status);
    }
}

/* 1. The accounts samsrv makes in setup mode: their names are values of
 * Users\Names, each the RID of its account (SampSetupCreateUserAccount). */
static void wait_for_the_accounts(void)
{
    static const WCHAR names[] = L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\Names";
    DWORD waited;
    for (waited = 0; waited <= SAM_WAIT_MS; waited += SAM_POLL_MS) {
        HANDLE key;
        if (NT_SUCCESS(open_key(names, &key))) {
            UNICODE_STRING name;
            KEY_VALUE_PARTIAL_INFORMATION information;
            DWORD size = 0;
            NTSTATUS status;
            name.Length = sizeof L"Administrator" - 2;
            name.MaximumLength = sizeof L"Administrator";
            name.Buffer = L"Administrator";
            status = NtQueryValueKey(key, &name, KEY_VALUE_PARTIAL_INFORMATION_CLASS, &information,
                                     sizeof information, &size);
            NtClose(key);
            if (NT_SUCCESS(status) && information.Type == REG_DWORD) {
                DbgPrint("[minoinit] SAM: the account Administrator, RID %lx (after %lu ms)\n", information.Data,
                         waited);
                return;
            }
        }
        Sleep(SAM_POLL_MS);
    }
    report_the_sam();
    stop("no account Administrator in the SAM");
}

/* 2 and 3. The profiles, and the hive of Default User. */
static void make_the_profiles(void)
{
    WCHAR profile[260];
    WCHAR from[260];
    DWORD size = 260;
    HMODULE userenv = LoadLibraryW(L"userenv.dll");
    InitializeProfilesFn initialize_profiles;
    GetDefaultUserProfileDirectoryWFn default_user_profile;
    NTSTATUS status;

    if (!userenv)
        stop("userenv.dll does not load");
    initialize_profiles = (InitializeProfilesFn)GetProcAddress(userenv, (const char *)100);
    default_user_profile =
        (GetDefaultUserProfileDirectoryWFn)GetProcAddress(userenv, "GetDefaultUserProfileDirectoryW");
    if (!initialize_profiles || !default_user_profile)
        stop("userenv has no InitializeProfiles (ordinal 100) or GetDefaultUserProfileDirectoryW");
    if (!initialize_profiles()) {
        DbgPrint("[minoinit] InitializeProfiles: error %lu\n", GetLastError());
        stop("InitializeProfiles failed");
    }
    if (!default_user_profile(profile, &size)) {
        DbgPrint("[minoinit] GetDefaultUserProfileDirectoryW: error %lu\n", GetLastError());
        stop("no Default User profile");
    }
    DbgPrint("[minoinit] profiles: Default User in %s\n", ascii(profile));

    status = flush(L"\\Registry\\User\\.DEFAULT");
    if (!NT_SUCCESS(status))
        stop("HKU\\.DEFAULT not written back");
    if (!ExpandEnvironmentStringsW(L"%SystemRoot%\\system32\\config\\default", from, 260))
        stop("no %SystemRoot%");
    append(profile, 260, L"\\NTUSER.DAT");
    if (!CopyFileW(from, profile, 0)) {
        DbgPrint("[minoinit] CopyFileW %s: error %lu\n", ascii(profile), GetLastError());
        stop("no NTUSER.DAT for Default User");
    }
    DbgPrint("[minoinit] the hive of Default User: %s\n", ascii(profile));
}

/* 4 and 5. Setup done, the hives written back, the reboot. */
static void finish(void)
{
    static const DWORD zero = 0;
    static const WCHAR empty[] = L"";
    HANDLE setup;
    NTSTATUS status = open_key(L"\\Registry\\Machine\\SYSTEM\\Setup", &setup);
    if (!NT_SUCCESS(status))
        stop("no SYSTEM\\Setup");
    if (!NT_SUCCESS(set_value(setup, L"SetupType", REG_DWORD, &zero, sizeof zero))
        || !NT_SUCCESS(set_value(setup, L"SystemSetupInProgress", REG_DWORD, &zero, sizeof zero))
        || !NT_SUCCESS(set_value(setup, L"CmdLine", REG_SZ, empty, sizeof empty)))
        stop("SYSTEM\\Setup not changed");
    NtClose(setup);
    DbgPrint("[minoinit] setup done: SetupType = 0\n");

    if (!NT_SUCCESS(flush(L"\\Registry\\Machine\\SYSTEM")) || !NT_SUCCESS(flush(L"\\Registry\\Machine\\SOFTWARE"))
        || !NT_SUCCESS(flush(L"\\Registry\\Machine\\SAM")) || !NT_SUCCESS(flush(L"\\Registry\\Machine\\SECURITY")))
        stop("a hive not written back");
    DbgPrint("[minoinit] done; rebooting\n");
    status = NtShutdownSystem(SHUTDOWN_REBOOT);
    DbgPrint("[minoinit] NtShutdownSystem: %lx\n", (DWORD)status);
}

DWORD __stdcall GuiStartup(void)
{
    WCHAR environment[260];
    DbgPrint("[minoinit] started in setup mode\n");
    if (ExpandEnvironmentStringsW(L"SystemDrive=%SystemDrive% SystemRoot=%SystemRoot% windir=%windir%", environment,
                                  260))
        DbgPrint("[minoinit] environment: %s\n", ascii(environment));
    wait_for_the_accounts();
    make_the_profiles();
    finish();
    ExitProcess(0);
    return 0;
}
