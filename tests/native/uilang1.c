/*
 * The language of the user interface: a Win32 program (subsystem WINDOWS),
 * compiled with MinGW and linked to ReactOS's ntdll and kernel32, which the
 * scenario `ui-language` puts on the boot disk in the place of winlogon.exe.
 * kernel32's GetUserDefaultUILanguage and GetSystemDefaultUILanguage call
 * NtQueryDefaultUILanguage and NtQueryInstallUILanguage and return the
 * LANGID they wrote, without looking at the status: without the services,
 * whatever was on the stack. Notepad++'s silent NSIS installer took its
 * language from it and came up in Dutch, or in English, from one run to
 * the next. As ReactOS (ex/locale.c, ExpGetCurrentUserUILanguage;
 * config/cmcontrl.c for PsInstallUILanguageId):
 * 1. NtQueryInstallUILanguage: the InstallLanguage of Nls\Language (0409);
 * 2. NtQueryDefaultUILanguage without MultiUILanguageId in the user's
 *    Control Panel\Desktop: the install language; the kernel32 functions
 *    return the same;
 * 3. MultiUILanguageId "0407" (REG_SZ): the user's language is 0407, the
 *    install language stays 0409;
 * 4. MultiUILanguageId as a REG_DWORD: not a string, the install language;
 * 5. MultiUILanguageId deleted: the install language again;
 * 6. a pointer outside the process, then a misaligned one: the probe's
 *    error, from both services.
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef unsigned short USHORT;
typedef unsigned short WCHAR;
typedef USHORT LANGID;
typedef void *HANDLE;
typedef long LONG;
typedef LONG NTSTATUS;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
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

#define OBJ_CASE_INSENSITIVE 0x40
#define KEY_ALL_ACCESS 0xF003F
#define REG_SZ 1
#define REG_DWORD 4

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) NTSTATUS __stdcall NtQueryDefaultUILanguage(LANGID *language);
__declspec(dllimport) NTSTATUS __stdcall NtQueryInstallUILanguage(LANGID *language);
__declspec(dllimport) NTSTATUS __stdcall RtlOpenCurrentUser(DWORD access, HANDLE *key);
__declspec(dllimport) NTSTATUS __stdcall NtCreateKey(HANDLE *key, DWORD access, OBJECT_ATTRIBUTES *attributes,
                                                     DWORD title_index, UNICODE_STRING *class_name, DWORD options,
                                                     DWORD *disposition);
__declspec(dllimport) NTSTATUS __stdcall NtSetValueKey(HANDLE key, UNICODE_STRING *name, DWORD title_index,
                                                       DWORD type, const void *data, DWORD size);
__declspec(dllimport) NTSTATUS __stdcall NtDeleteValueKey(HANDLE key, UNICODE_STRING *name);
__declspec(dllimport) NTSTATUS __stdcall NtClose(HANDLE handle);

__declspec(dllimport) LANGID __stdcall GetUserDefaultUILanguage(void);
__declspec(dllimport) LANGID __stdcall GetSystemDefaultUILanguage(void);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);

static const WCHAR desktop_name[] = L"Control Panel\\Desktop";
static const WCHAR value_name[] = L"MultiUILanguageId";
static UNICODE_STRING value = {sizeof(value_name) - 2, sizeof(value_name), value_name};

/* The user's language by the service, the LANGID 0xBEEF before. */
static LANGID user_language(NTSTATUS *status)
{
    LANGID language = 0xBEEF;
    *status = NtQueryDefaultUILanguage(&language);
    return language;
}

DWORD __stdcall GuiStartup(void)
{
    static const WCHAR german[] = L"0407";
    static const DWORD german_number = 0x0407;
    HANDLE user = 0, desktop = 0;
    UNICODE_STRING desktop_string = {sizeof(desktop_name) - 2, sizeof(desktop_name), desktop_name};
    OBJECT_ATTRIBUTES attributes = {sizeof(attributes), 0, &desktop_string, OBJ_CASE_INSENSITIVE, 0, 0};
    NTSTATUS status, opened;
    LANGID language, install = 0xBEEF, buffer[2];
    DWORD disposition = 0;

    /* 1. The install language. */
    status = NtQueryInstallUILanguage(&install);
    DbgPrint("[uilang] step 1: NtQueryInstallUILanguage %08lx, %04x\n", status, install);

    /* 2. No MultiUILanguageId: the install language, by kernel32 too. */
    opened = RtlOpenCurrentUser(KEY_ALL_ACCESS, &user);
    if (opened >= 0) {
        attributes.RootDirectory = user;
        opened = NtCreateKey(&desktop, KEY_ALL_ACCESS, &attributes, 0, 0, 0, &disposition);
    }
    DbgPrint("[uilang] the user's Control Panel\\Desktop: %08lx\n", opened);
    if (opened >= 0) NtDeleteValueKey(desktop, &value);
    language = user_language(&status);
    DbgPrint("[uilang] step 2: NtQueryDefaultUILanguage %08lx, %04x\n", status, language);
    language = GetUserDefaultUILanguage();
    install = GetSystemDefaultUILanguage();
    DbgPrint("[uilang] step 2: GetUserDefaultUILanguage %04x, GetSystemDefaultUILanguage %04x\n", language, install);

    if (opened >= 0) {
        /* 3. The user's own. */
        status = NtSetValueKey(desktop, &value, 0, REG_SZ, german, sizeof(german));
        language = user_language(&opened);
        install = GetSystemDefaultUILanguage();
        DbgPrint("[uilang] step 3: set %08lx; NtQueryDefaultUILanguage %08lx, %04x; GetUserDefaultUILanguage %04x, "
                 "GetSystemDefaultUILanguage %04x\n",
                 status, opened, language, GetUserDefaultUILanguage(), install);

        /* 4. Not a string. */
        status = NtSetValueKey(desktop, &value, 0, REG_DWORD, &german_number, sizeof(german_number));
        language = user_language(&opened);
        DbgPrint("[uilang] step 4: set %08lx; NtQueryDefaultUILanguage %08lx, %04x\n", status, opened, language);

        /* 5. Deleted. */
        status = NtDeleteValueKey(desktop, &value);
        language = user_language(&opened);
        DbgPrint("[uilang] step 5: deleted %08lx; NtQueryDefaultUILanguage %08lx, %04x\n", status, opened, language);
        NtClose(desktop);
        NtClose(user);
    }

    /* 6. Pointers that the probe refuses. */
    DbgPrint("[uilang] step 6: outside %08lx %08lx, misaligned %08lx %08lx\n",
             NtQueryDefaultUILanguage((LANGID *)0x10), NtQueryInstallUILanguage((LANGID *)0x10),
             NtQueryDefaultUILanguage((LANGID *)((char *)buffer + 1)),
             NtQueryInstallUILanguage((LANGID *)((char *)buffer + 1)));

    DbgPrint("[uilang] done\n");
    ExitProcess(0);
    return 0;
}
