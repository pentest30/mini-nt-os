/*
 * MINOINIT.EXE, the end of Mino's installation (ADR-023): winlogon starts it
 * in setup mode, on the first boot (SYSTEM\Setup: SetupType = 1, CmdLine =
 * %SystemRoot%\system32\minoinit.exe, from tools/mkhive/mino.inf). It does
 * the part of ReactOS's InstallReactOS (syssetup, as a specification) that
 * the logon needs, then reboots; on the next boot, winlogon goes to the
 * logon of Administrator:
 *
 * 1. samsrv made the accounts in setup mode (SampInitializeSAM): wait for
 *    the value Administrator of SAM\Domains\Account\Users\Names; then the
 *    rights of the accounts (syssetup's InstallSecurity, InstallPrivileges):
 *    each line of the [Privilege Rights] of %SystemRoot%\inf\defltwk.inf
 *    given to its SIDs and names by LsaAddAccountRights, in the LSA's
 *    database (the SECURITY hive), where lsasrv takes the privileges of a
 *    logon token from (LsapSetPrivileges) -- without them, Administrator's
 *    token has no SeShutdownPrivilege; a right not given is logged, not
 *    fatal, as in syssetup;
 * 2. the profiles: userenv's InitializeProfiles (ordinal 100), which
 *    creates the profiles directory, Default User and All Users, and writes
 *    ProfileList and the shell folders of HKU\.DEFAULT;
 * 3. the COM servers registered (syssetup.inf's OleControlDlls,
 *    RegistrationPhase2, which syssetup runs after the profiles): CoInitialize,
 *    then the DllRegisterServer of each one on the disk, which writes its
 *    classes under HKCR (browseui: the Start menu and the taskbar's band site,
 *    which explorer creates; shell32: the CLSIDs of the shell's folders and
 *    their icons, the user's shell folders); a failed registration is logged,
 *    not fatal, as in syssetup. One of them leaves the Finalize of syssetup in
 *    RunOnceEx (« rundll32 setupapi.dll,InstallHinfSection Finalize ») : a
 *    finished install has consumed it (iernonce runs it at the first logon),
 *    and it is deleted here — without iernonce.dll nor setupapi.dll on the
 *    disk, explorer's ProcessRunOnceEx would launch « rundll32 iernonce.dll
 *    RunOnceExProcess », whose rundll32 stops on its « LoadLibrary failed »
 *    MessageBox and never comes back;
 * 4. the hive of Default User: HKU\.DEFAULT written back to its file
 *    (NtFlushKey), copied as NTUSER.DAT in the Default User profile
 *    (syssetup's SaveDefaultUserHive saves the key itself, RegSaveKeyEx);
 * 5. setup done: SetupType = 0, SystemSetupInProgress = 0, CmdLine empty;
 * 6. the hives written back to their files (NtFlushKey), then a reboot
 *    (NtShutdownSystem, with SeShutdownPrivilege enabled, as winlogon
 *    enables it).
 *
 * Each step says how it went by DbgPrint ("[minoinit] ..."); a failed step
 * other than a registration stops the program without the reboot.
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
typedef unsigned char BOOLEAN;

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
#define GENERIC_READ 0x80000000
#define FILE_SHARE_READ 1
#define OPEN_EXISTING 3
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG)-1)
#define POLICY_CREATE_ACCOUNT 0x10
#define POLICY_LOOKUP_NAMES 0x800
#define SE_SHUTDOWN_PRIVILEGE 19
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
__declspec(dllimport) NTSTATUS __stdcall RtlAdjustPrivilege(DWORD privilege, BOOLEAN enable, BOOLEAN current_thread,
                                                            BOOLEAN *was_enabled);

__declspec(dllimport) HMODULE __stdcall LoadLibraryW(const WCHAR *name);
__declspec(dllimport) void *__stdcall GetProcAddress(HMODULE module, const char *name);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall CopyFileW(const WCHAR *from, const WCHAR *to, BOOL fail_if_exists);
__declspec(dllimport) DWORD __stdcall ExpandEnvironmentStringsW(const WCHAR *from, WCHAR *to, DWORD size);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *security,
                                                   DWORD disposition, DWORD flags, HANDLE template_file);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE file, void *buffer, DWORD size, DWORD *read, void *overlapped);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) void *__stdcall LocalFree(void *memory);

typedef BOOL(__stdcall *InitializeProfilesFn)(void);
typedef BOOL(__stdcall *GetDefaultUserProfileDirectoryWFn)(WCHAR *path, DWORD *size);
typedef LONG(__stdcall *CoInitializeFn)(void *reserved);
typedef LONG(__stdcall *DllRegisterServerFn)(void);
typedef LONG(__stdcall *SHDeleteKeyWFn)(void *key, const WCHAR *subkey);

/* LSA_TRANSLATED_SID2: what LsaLookupNames2 gives for a name. */
typedef struct {
    DWORD Use;
    void *Sid;
    LONG DomainIndex;
    DWORD Flags;
} LSA_TRANSLATED_SID2;

typedef NTSTATUS(__stdcall *LsaOpenPolicyFn)(UNICODE_STRING *system, OBJECT_ATTRIBUTES *attributes, DWORD access,
                                             HANDLE *policy);
typedef NTSTATUS(__stdcall *LsaAddAccountRightsFn)(HANDLE policy, void *sid, UNICODE_STRING *rights, DWORD count);
typedef NTSTATUS(__stdcall *LsaLookupNames2Fn)(HANDLE policy, DWORD flags, DWORD count, UNICODE_STRING *names,
                                               void **domains, LSA_TRANSLATED_SID2 **sids);
typedef NTSTATUS(__stdcall *LsaFreeMemoryFn)(void *memory);
typedef NTSTATUS(__stdcall *LsaCloseFn)(HANDLE handle);
typedef BOOL(__stdcall *ConvertStringSidToSidWFn)(const WCHAR *text, void **sid);

/* HKEY_LOCAL_MACHINE, as shlwapi takes it (a predefined handle, not a key of
 * the kernel's registry: shlwapi resolves it itself). */
#define HKEY_LOCAL_MACHINE_PREDEFINED ((void *)0x80000002)

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

/* The security defaults of a workstation, as ReactOS has them (ASCII). */
static char security_inf[8192];

/* A line of the INF file: its characters, its spaces trimmed. */
typedef struct {
    const char *text;
    DWORD length;
} LINE;

/* The next line of `text` from `*at`; 0 at its end. */
static BOOL next_line(const char *text, DWORD *at, LINE *line)
{
    DWORD start, end;
    if (!text[*at])
        return 0;
    start = *at;
    while (text[*at] && text[*at] != '\n')
        ++*at;
    end = *at;
    if (text[*at])
        ++*at;
    while (start < end && (text[start] == ' ' || text[start] == '\t'))
        ++start;
    while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r'))
        --end;
    line->text = text + start;
    line->length = end - start;
    return 1;
}

/* Whether `line` is the section header `header`, without case. */
static BOOL is_section(const LINE *line, const char *header)
{
    DWORD i;
    for (i = 0; i < line->length && header[i]; ++i) {
        char a = line->text[i], b = header[i];
        if (a >= 'a' && a <= 'z')
            a = (char)(a - 32);
        if (b >= 'a' && b <= 'z')
            b = (char)(b - 32);
        if (a != b)
            return 0;
    }
    return i == line->length && !header[i];
}

/* The value of the key `key` (its `n` characters) in the [Strings] of
 * `text`, its quotes taken off, into `value`; 0 without it. */
static BOOL inf_string(const char *text, const WCHAR *key, DWORD n, WCHAR *value, DWORD size)
{
    DWORD at = 0;
    LINE line;
    BOOL in_strings = 0;
    while (next_line(text, &at, &line)) {
        DWORD i, k;
        if (line.length && line.text[0] == '[') {
            in_strings = is_section(&line, "[Strings]");
            continue;
        }
        if (!in_strings || line.length <= n)
            continue;
        for (i = 0; i < n && (WCHAR)line.text[i] == key[i]; ++i)
            ;
        if (i < n)
            continue;
        while (i < line.length && line.text[i] == ' ')
            ++i;
        if (i >= line.length || line.text[i] != '=')
            continue;
        ++i;
        while (i < line.length && (line.text[i] == ' ' || line.text[i] == '"'))
            ++i;
        for (k = 0; i < line.length && line.text[i] != '"' && k + 1 < size; ++i, ++k)
            value[k] = (WCHAR)line.text[i];
        value[k] = 0;
        return 1;
    }
    return 0;
}

/* The LSA's functions of advapi32. */
typedef struct {
    LsaOpenPolicyFn open_policy;
    LsaAddAccountRightsFn add_rights;
    LsaLookupNames2Fn lookup_names;
    LsaFreeMemoryFn free_memory;
    LsaCloseFn close;
    ConvertStringSidToSidWFn string_to_sid;
} LSA;

/* Gives `right` (an UNICODE_STRING) to the account of the INF field `field`
 * (its `k` characters): a SID (`*S-1-5-32-544`), or an account name, given
 * or taken from [Strings] (`%SceInfGuest%`), which LsaLookupNames2 makes a
 * SID. 1 if given. */
static BOOL give_right(const LSA *lsa, HANDLE policy, UNICODE_STRING *right, WCHAR *field, DWORD k)
{
    void *sid = 0;
    LSA_TRANSLATED_SID2 *sids = 0;
    NTSTATUS status;
    if (field[0] == '*') {
        if (!lsa->string_to_sid(field + 1, &sid)) {
            DbgPrint("[minoinit] %s: not a SID (%lu)\n", ascii(field), GetLastError());
            return 0;
        }
    } else {
        WCHAR name[64];
        UNICODE_STRING account;
        void *domains = 0;
        if (field[0] == '%' && k > 2 && field[k - 1] == '%') {
            if (!inf_string(security_inf, field + 1, k - 2, name, 64)) {
                DbgPrint("[minoinit] %s: not in [Strings]\n", ascii(field));
                return 0;
            }
        } else {
            DWORD c;
            for (c = 0; c <= k && c < 64; ++c)
                name[c] = field[c];
            name[63] = 0;
        }
        account.Length = (unsigned short)(length(name) * 2);
        account.MaximumLength = account.Length + 2;
        account.Buffer = name;
        status = lsa->lookup_names(policy, 0, 1, &account, &domains, &sids);
        if (domains)
            lsa->free_memory(domains);
        if (!NT_SUCCESS(status) || !sids) {
            DbgPrint("[minoinit] LsaLookupNames2 %s: %lx\n", ascii(name), (DWORD)status);
            if (sids)
                lsa->free_memory(sids);
            return 0;
        }
    }
    status = lsa->add_rights(policy, sid ? sid : sids[0].Sid, right, 1);
    if (!NT_SUCCESS(status))
        DbgPrint("[minoinit] LsaAddAccountRights %s: %lx\n", ascii(right->Buffer), (DWORD)status);
    if (sids)
        lsa->free_memory(sids);
    if (sid)
        LocalFree(sid);
    return NT_SUCCESS(status);
}

/* 1, the end. The [Privilege Rights] of defltwk.inf given to the accounts,
 * as syssetup's InstallPrivileges does it: each field of a line is a SID or
 * an account name, which gets the right the line names. */
static void give_the_rights(void)
{
    HMODULE advapi32 = LoadLibraryW(L"advapi32.dll");
    LSA lsa = {0};
    WCHAR path[260];
    HANDLE file, policy = 0;
    DWORD read = 0, at = 0, given = 0, failed = 0;
    LINE line;
    BOOL in_rights = 0;
    OBJECT_ATTRIBUTES attributes = {0};
    NTSTATUS status;

    if (advapi32) {
        lsa.open_policy = (LsaOpenPolicyFn)GetProcAddress(advapi32, "LsaOpenPolicy");
        lsa.add_rights = (LsaAddAccountRightsFn)GetProcAddress(advapi32, "LsaAddAccountRights");
        lsa.lookup_names = (LsaLookupNames2Fn)GetProcAddress(advapi32, "LsaLookupNames2");
        lsa.free_memory = (LsaFreeMemoryFn)GetProcAddress(advapi32, "LsaFreeMemory");
        lsa.close = (LsaCloseFn)GetProcAddress(advapi32, "LsaClose");
        lsa.string_to_sid = (ConvertStringSidToSidWFn)GetProcAddress(advapi32, "ConvertStringSidToSidW");
    }
    if (!lsa.open_policy || !lsa.add_rights || !lsa.lookup_names || !lsa.free_memory || !lsa.close
        || !lsa.string_to_sid)
        stop("advapi32 has no LSA policy functions");
    if (!ExpandEnvironmentStringsW(L"%SystemRoot%\\inf\\defltwk.inf", path, 260))
        stop("no %SystemRoot%");
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (file == INVALID_HANDLE_VALUE) {
        DbgPrint("[minoinit] %s: error %lu\n", ascii(path), GetLastError());
        stop("no defltwk.inf");
    }
    if (!ReadFile(file, security_inf, sizeof security_inf - 1, &read, 0) || read == sizeof security_inf - 1)
        stop("defltwk.inf not read whole");
    CloseHandle(file);
    security_inf[read] = 0;

    attributes.Length = sizeof attributes;
    status = lsa.open_policy(0, &attributes, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &policy);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[minoinit] LsaOpenPolicy: %lx\n", (DWORD)status);
        stop("the LSA's policy does not open");
    }
    while (next_line(security_inf, &at, &line)) {
        DWORD i = 0, name_length;
        WCHAR right[64];
        UNICODE_STRING right_string;
        if (!line.length || line.text[0] == ';')
            continue;
        if (line.text[0] == '[') {
            in_rights = is_section(&line, "[Privilege Rights]");
            continue;
        }
        if (!in_rights)
            continue;
        /* The right's name, before `=`. */
        while (i < line.length && line.text[i] != '=' && line.text[i] != ' ' && i + 1 < 64) {
            right[i] = (WCHAR)line.text[i];
            ++i;
        }
        right[i] = 0;
        name_length = i;
        while (i < line.length && line.text[i] != '=')
            ++i;
        right_string.Length = (unsigned short)(name_length * 2);
        right_string.MaximumLength = right_string.Length + 2;
        right_string.Buffer = right;
        /* Its fields, separated by commas. */
        while (++i < line.length) {
            WCHAR field[128];
            DWORD k = 0;
            while (i < line.length && line.text[i] == ' ')
                ++i;
            while (i < line.length && line.text[i] != ',' && k + 1 < 128)
                field[k++] = (WCHAR)line.text[i++];
            while (k && field[k - 1] == ' ')
                --k;
            field[k] = 0;
            if (!k)
                continue;
            if (give_right(&lsa, policy, &right_string, field, k))
                ++given;
            else
                ++failed;
        }
    }
    lsa.close(policy);
    DbgPrint("[minoinit] rights of the accounts: %lu given, %lu not (defltwk.inf)\n", given, failed);
}

/* 2. The profiles; `profile` receives the directory of Default User. */
static void make_the_profiles(WCHAR *profile, DWORD size)
{
    HMODULE userenv = LoadLibraryW(L"userenv.dll");
    InitializeProfilesFn initialize_profiles;
    GetDefaultUserProfileDirectoryWFn default_user_profile;

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
}

/* 3. The COM servers of syssetup.inf's OleControlDlls (RegistrationPhase2)
 * that are on the disk, in its order, as syssetup's RegisterDlls does it:
 * CoInitialize, then each DLL's DllRegisterServer, which writes its classes
 * in HKCR (SOFTWARE\Classes), before the hive of Default User is saved
 * (shell32 also writes the user's shell folders). explorer needs them: the
 * Start menu and the taskbar's band site are browseui's, the desktop's
 * folders shell32's; Authenticode (WinVerifyTrust, CryptQueryObject) needs
 * the cryptographic providers (rsaenh), the trust providers and the SIPs
 * (wintrust, softpub, mscat32, msisip), which the pinned SOFTWARE hive does
 * not have; oleaut32's OleLoadPicture decodes every picture, BMP included,
 * through WIC (windowscodecs: CLSID_WICImagingFactory, the decoders), as
 * msi.dll loads the bitmaps of its dialogs. A DLL that does not load or fails is reported; it does
 * not stop the setup (as syssetup). */
static void register_the_dlls(void)
{
    static const WCHAR *const dlls[] = {
        L"browseui.dll", L"cryptnet.dll", L"mscat32.dll", L"msisip.dll", L"oleaut32.dll", L"rpcrt4.dll", L"rsabase.dll",
        L"rsaenh.dll", L"shdocvw.dll", L"shell32.dll", L"softpub.dll", L"urlmon.dll", L"windowscodecs.dll",
        L"wininet.dll", L"wintrust.dll",
    };
    HMODULE ole32 = LoadLibraryW(L"ole32.dll");
    CoInitializeFn co_initialize = ole32 ? (CoInitializeFn)GetProcAddress(ole32, "CoInitialize") : 0;
    DWORD i;

    if (!co_initialize)
        stop("ole32 has no CoInitialize");
    DbgPrint("[minoinit] CoInitialize: %lx\n", (DWORD)co_initialize(0));
    for (i = 0; i < sizeof dlls / sizeof dlls[0]; ++i) {
        HMODULE dll = LoadLibraryW(dlls[i]);
        DllRegisterServerFn register_server = dll ? (DllRegisterServerFn)GetProcAddress(dll, "DllRegisterServer") : 0;
        if (!register_server) {
            DbgPrint("[minoinit] DllRegisterServer %s: not found (%lu)\n", ascii(dlls[i]), GetLastError());
            continue;
        }
        DbgPrint("[minoinit] DllRegisterServer %s: %lx\n", ascii(dlls[i]), (DWORD)register_server());
    }
}

/* 3, the end. RunOnceEx, where a registration can leave syssetup's Finalize,
 * is consumed: a finished install has run it, and the logon of the next boot
 * has nothing to do there (explorer launches iernonce for it, which the disk
 * has not). SHDeleteKeyW of shlwapi takes the whole subtree down (ReactOS's
 * advapi32 has no RegDeleteTreeW). */
static void consume_the_run_once(void)
{
    HMODULE shlwapi = LoadLibraryW(L"shlwapi.dll");
    SHDeleteKeyWFn delete_key = shlwapi ? (SHDeleteKeyWFn)GetProcAddress(shlwapi, "SHDeleteKeyW") : 0;
    if (!delete_key) {
        DbgPrint("[minoinit] RunOnceEx: no SHDeleteKeyW (%lu)\n", GetLastError());
        return;
    }
    DbgPrint("[minoinit] RunOnceEx: %lx\n",
             (DWORD)delete_key(HKEY_LOCAL_MACHINE_PREDEFINED,
                               L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"));
}

/* 4. The hive of Default User, in its profile `profile`. */
static void save_the_default_user_hive(WCHAR *profile)
{
    WCHAR from[260];
    NTSTATUS status = flush(L"\\Registry\\User\\.DEFAULT");
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

/* 5 and 6. Setup done, the hives written back, the reboot. */
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
    /* NtShutdownSystem wants the caller's SeShutdownPrivilege enabled; the
     * token of System holds it disabled. */
    {
        BOOLEAN was_enabled;
        status = RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, 1, 0, &was_enabled);
        if (!NT_SUCCESS(status))
            DbgPrint("[minoinit] SeShutdownPrivilege not enabled: %lx\n", (DWORD)status);
    }
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
    WCHAR profile[260];
    wait_for_the_accounts();
    give_the_rights();
    make_the_profiles(profile, 260);
    register_the_dlls();
    consume_the_run_once();
    save_the_default_user_hive(profile);
    finish();
    ExitProcess(0);
    return 0;
}
