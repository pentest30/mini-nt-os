/* Byte-range locks (NtLockFile, NtUnlockFile; ReactOS 0.4.16 iofunc.c and
 * fsrtl/filelock.c as the specification): kernel32's LockFile, LockFileEx
 * and UnlockFile, the native services with their I/O status block and
 * event, reads and writes stopped by a lock, the locks of a handle gone with
 * it; then ole32's structured storage, which msiexec opens its package with
 * and which locks byte ranges far past the end of the file. No C runtime,
 * entry GuiStartup. */
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long NTSTATUS;
typedef long HRESULT;
typedef int BOOL;
typedef unsigned short WCHAR;
typedef void *HANDLE;
typedef unsigned long long ULONGLONG;
typedef struct { NTSTATUS status; ULONG information; } IO_STATUS_BLOCK;
typedef struct { DWORD internal, internal_high, offset, offset_high; HANDLE event; } OVERLAPPED;

#define GENERIC_READ 0x80000000UL
#define GENERIC_WRITE 0x40000000UL
#define FILE_SHARE_RW 3
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define LOCKFILE_FAIL_IMMEDIATELY 1
#define LOCKFILE_EXCLUSIVE_LOCK 2
#define ERROR_LOCK_VIOLATION 33
#define ERROR_NOT_LOCKED 158
#define ERROR_INVALID_NAME 123
#define SUCCESS 0
#define CONFLICT ((NTSTATUS)0xc0000054)
#define NOT_LOCKED ((NTSTATUS)0xc000007e)
#define INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define WAIT_OBJECT_0 0
#define POISON 0xdeadbeefUL

#define STGM_READ 0x0
#define STGM_READWRITE 0x2
#define STGM_SHARE_EXCLUSIVE 0x10
#define STGM_SHARE_DENY_WRITE 0x20
#define STGM_CREATE 0x1000
#define STG_E_SHAREVIOLATION ((HRESULT)0x80030020)

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *, ...);
__declspec(dllimport) NTSTATUS __stdcall NtLockFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, ULONGLONG *,
                                                     ULONGLONG *, ULONG, unsigned char, unsigned char);
__declspec(dllimport) NTSTATUS __stdcall NtUnlockFile(HANDLE, IO_STATUS_BLOCK *, ULONGLONG *, ULONGLONG *, ULONG);
__declspec(dllimport) NTSTATUS __stdcall NtReadFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, void *, ULONG,
                                                     ULONGLONG *, ULONG *);
__declspec(dllimport) NTSTATUS __stdcall NtWriteFile(HANDLE, HANDLE, void *, void *, IO_STATUS_BLOCK *, const void *,
                                                      ULONG, ULONGLONG *, ULONG *);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
__declspec(dllimport) DWORD __stdcall SetFilePointer(HANDLE, long, long *, DWORD);
__declspec(dllimport) BOOL __stdcall LockFile(HANDLE, DWORD, DWORD, DWORD, DWORD);
__declspec(dllimport) BOOL __stdcall LockFileEx(HANDLE, DWORD, DWORD, DWORD, DWORD, OVERLAPPED *);
__declspec(dllimport) BOOL __stdcall UnlockFile(HANDLE, DWORD, DWORD, DWORD, DWORD);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *, BOOL, BOOL, const void *);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE, DWORD);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);
__declspec(dllimport) void *__stdcall LoadLibraryW(const WCHAR *);
__declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
__declspec(dllimport) void __stdcall ExitProcess(DWORD);
__declspec(dllimport) BOOL __stdcall CreateDirectoryW(const WCHAR *, void *);
__declspec(dllimport) DWORD __stdcall GetFileAttributesW(const WCHAR *);


/* IStorage and IStream through their vtables: Release is the third entry,
 * IStorage::CreateStream the fourth and Commit the tenth, IStream::Write
 * the fifth. */
typedef struct { void **vtbl; } COM;
typedef HRESULT(__stdcall *Release)(COM *);
typedef HRESULT(__stdcall *CreateStream)(COM *, const WCHAR *, DWORD, DWORD, DWORD, COM **);
typedef HRESULT(__stdcall *Commit)(COM *, DWORD);
typedef HRESULT(__stdcall *StreamWrite)(COM *, const void *, ULONG, ULONG *);
typedef HRESULT(__stdcall *StgCreateDocfile)(const WCHAR *, DWORD, DWORD, COM **);
typedef HRESULT(__stdcall *StgOpenStorage)(const WCHAR *, COM *, DWORD, void *, DWORD, COM **);

static void check(int ok, const char *what)
{
    if (!ok) {
        DbgPrint("[lock] FAIL %s (last error %lu)\n", what, GetLastError());
        ExitProcess(1);
    }
}

static HANDLE open_file_named(const WCHAR *name, DWORD disposition)
{
    return CreateFileW(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW, 0, disposition, 0, 0);
}

static HANDLE open_file(DWORD disposition)
{
    return open_file_named(L"C:\\LOCK1.TMP", disposition);
}

static void kernel32_and_native(void)
{
    static char data[1024];
    char byte = 0;
    DWORD done, n;
    IO_STATUS_BLOCK iosb;
    ULONGLONG at, length;
    ULONG key;
    OVERLAPPED ol = {0};
    HANDLE first = open_file(CREATE_ALWAYS), second, event;
    check(first != (HANDLE)-1, "create C:\\LOCK1.TMP");
    for (n = 0; n < sizeof(data); ++n)
        data[n] = (char)n;
    check(WriteFile(first, data, sizeof(data), &done, 0) && done == sizeof(data), "write the file");
    second = open_file(OPEN_EXISTING);
    check(second != (HANDLE)-1, "a second open");

    /* An exclusive lock overlaps nothing, whoever asks. */
    check(LockFile(first, 100, 0, 100, 0), "LockFile");
    check(!LockFile(second, 150, 0, 1, 0) && GetLastError() == ERROR_LOCK_VIOLATION, "overlap refused");
    check(!LockFile(first, 199, 0, 10, 0) && GetLastError() == ERROR_LOCK_VIOLATION, "even by its owner");
    check(LockFile(second, 200, 0, 10, 0), "adjacent range");
    check(LockFile(second, 150, 0, 0, 0), "an empty range overlaps nothing");
    DbgPrint("[lock] LockFile: an exclusive lock overlaps nothing\n");

    /* Shared locks share; a write stops at them, even its owner's. */
    ol.offset = 300;
    check(LockFileEx(first, LOCKFILE_FAIL_IMMEDIATELY, 0, 50, 0, &ol), "shared lock");
    check(LockFileEx(second, LOCKFILE_FAIL_IMMEDIATELY, 0, 10, 0, &ol), "shared with another");
    check(!LockFileEx(second, LOCKFILE_FAIL_IMMEDIATELY | LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol) &&
              GetLastError() == ERROR_LOCK_VIOLATION,
          "no exclusive lock over a shared one");
    SetFilePointer(first, 310, 0, 0);
    check(!WriteFile(first, "x", 1, &done, 0) && GetLastError() == ERROR_LOCK_VIOLATION, "write in a shared range");
    SetFilePointer(first, 310, 0, 0);
    check(ReadFile(first, &byte, 1, &done, 0) && done == 1 && byte == (char)310, "read in a shared range");
    DbgPrint("[lock] LockFileEx: shared locks share, writes stop at them\n");

    /* The I/O of another key stops at an exclusive lock; the owner's goes. */
    at = 120;
    key = 7;
    check(NtReadFile(first, 0, 0, 0, &iosb, &byte, 1, &at, &key) == CONFLICT, "read with another key");
    check(NtWriteFile(first, 0, 0, 0, &iosb, "y", 1, &at, &key) == CONFLICT, "write with another key");
    check(NtReadFile(first, 0, 0, 0, &iosb, &byte, 1, &at, 0) == SUCCESS && byte == 120, "owner reads");
    check(NtWriteFile(first, 0, 0, 0, &iosb, "z", 1, &at, 0) == SUCCESS, "owner writes");
    /* Key is a PULONG for the I/O, a ULONG for NtLockFile: a lock taken with
     * key 7 lets the I/O that points at 7 through, not the one without key
     * (0) nor the one that points at 8. */
    at = 400;
    length = 10;
    check(NtLockFile(first, 0, 0, 0, &iosb, &at, &length, 7, 1, 1) == SUCCESS, "a lock with key 7");
    at = 405;
    key = 7;
    check(NtReadFile(second, 0, 0, 0, &iosb, &byte, 1, &at, &key) == SUCCESS, "read through a pointer to its key");
    check(NtWriteFile(second, 0, 0, 0, &iosb, "k", 1, &at, &key) == SUCCESS, "write through a pointer to its key");
    check(NtReadFile(second, 0, 0, 0, &iosb, &byte, 1, &at, 0) == CONFLICT, "read without key");
    key = 8;
    check(NtReadFile(second, 0, 0, 0, &iosb, &byte, 1, &at, &key) == CONFLICT, "read through a pointer to 8");
    at = 400;
    check(NtUnlockFile(first, &iosb, &at, &length, 7) == SUCCESS, "unlock key 7");
    DbgPrint("[lock] NtReadFile, NtWriteFile: an exclusive lock of another key stops them\n");

    /* The native services: the I/O status block, the event, the key. */
    event = CreateEventW(0, 1, 0, 0);
    at = 0x7fffff92;
    length = 1;
    iosb.status = (NTSTATUS)POISON;
    check(NtLockFile(first, event, 0, 0, &iosb, &at, &length, 5, 1, 1) == SUCCESS && iosb.status == SUCCESS &&
              WaitForSingleObject(event, 0) == WAIT_OBJECT_0,
          "NtLockFile far past the end, with an event");
    check(NtLockFile(second, event, 0, 0, &iosb, &at, &length, 5, 1, 0) == CONFLICT && iosb.status == CONFLICT,
          "the conflict in the status block");
    at = ~0ULL;
    length = 2;
    check(NtLockFile(first, 0, 0, 0, &iosb, &at, &length, 0, 1, 1) == INVALID_PARAMETER, "a range past 2^64");
    at = 0x7fffff92;
    length = 1;
    check(NtUnlockFile(first, &iosb, &at, &length, 0) == NOT_LOCKED && iosb.status == NOT_LOCKED,
          "unlock with another key");
    check(NtUnlockFile(first, &iosb, &at, &length, 5) == SUCCESS, "unlock with its key");
    DbgPrint("[lock] NtLockFile, NtUnlockFile: status block, event, key\n");

    /* UnlockFile names the exact range. */
    check(!UnlockFile(first, 100, 0, 50, 0) && GetLastError() == ERROR_NOT_LOCKED, "a part of a range");
    check(UnlockFile(first, 100, 0, 100, 0), "UnlockFile");
    check(LockFile(second, 150, 0, 1, 0), "the range is free");
    DbgPrint("[lock] UnlockFile: the exact range\n");

    /* The locks of a handle go with it. */
    check(!LockFile(first, 205, 0, 1, 0), "the second handle's lock");
    CloseHandle(second);
    check(LockFile(first, 205, 0, 1, 0), "gone with its handle");
    CloseHandle(first);
    CloseHandle(event);
    DbgPrint("[lock] the locks of a handle go with it\n");
}

static void structured_storage(void)
{
    static const WCHAR path[] = L"C:\\LOCK1.STG";
    void *ole32 = LoadLibraryW(L"ole32.dll");
    StgCreateDocfile create = ole32 ? (StgCreateDocfile)GetProcAddress(ole32, "StgCreateDocfile") : 0;
    StgOpenStorage open = ole32 ? (StgOpenStorage)GetProcAddress(ole32, "StgOpenStorage") : 0;
    COM *storage = 0, *stream = 0, *reader = 0, *other = 0, *writer = 0;
    HRESULT hr;
    ULONG written;
    check(create && open, "ole32's StgCreateDocfile and StgOpenStorage");

    hr = create(path, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &storage);
    check(hr == 0, "StgCreateDocfile");
    hr = ((CreateStream)storage->vtbl[3])(storage, L"Data", STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &stream);
    check(hr == 0, "IStorage::CreateStream");
    check(((StreamWrite)stream->vtbl[4])(stream, "mino", 4, &written) == 0 && written == 4, "IStream::Write");
    ((Release)stream->vtbl[2])(stream);
    check(((Commit)storage->vtbl[9])(storage, 0) == 0, "IStorage::Commit");
    ((Release)storage->vtbl[2])(storage);
    DbgPrint("[lock] ole32: StgCreateDocfile\n");

    /* What msiexec does to read its package. */
    hr = open(path, 0, STGM_READ | STGM_SHARE_DENY_WRITE, 0, 0, &reader);
    DbgPrint("[lock] ole32: StgOpenStorage(read, deny write) = %08lx\n", (DWORD)hr);
    check(hr == 0, "StgOpenStorage for reading");
    /* A reader that denies writes takes no lock: ole32 leaves that to the
     * share mode of CreateFile, which Mino does not check yet. A reader
     * that denies everything locks the deny ranges, and a writer finds
     * them locked. */
    hr = open(path, 0, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, 0, &other);
    check(hr == 0, "a reader that denies everything");
    hr = open(path, 0, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &writer);
    DbgPrint("[lock] ole32: a writer while it reads = %08lx\n", (DWORD)hr);
    check(hr == STG_E_SHAREVIOLATION, "a writer refused while it reads");
    ((Release)other->vtbl[2])(other);
    ((Release)reader->vtbl[2])(reader);
    hr = open(path, 0, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0, &writer);
    check(hr == 0, "a writer once they are gone");
    ((Release)writer->vtbl[2])(writer);
    DbgPrint("[lock] ole32: StgOpenStorage shares and refuses by its locks\n");
}

/* msi makes `C:\WINDOWS\Installer\` so before it copies its package there:
 * a trailing backslash names a directory to create; a file cannot be
 * created so. */
static void trailing_backslash(void)
{
    check(CreateDirectoryW(L"C:\\LOCKDIR\\", 0), "CreateDirectoryW with a trailing backslash");
    check(GetFileAttributesW(L"C:\\LOCKDIR") == 0x10, "the directory made");
    check(open_file_named(L"C:\\LOCKDIR\\INSIDE.TMP", CREATE_ALWAYS) != (HANDLE)-1, "a file in it");
    check(open_file_named(L"C:\\LOCKDIR\\FILE.TMP\\", CREATE_ALWAYS) == (HANDLE)-1 &&
              GetLastError() == ERROR_INVALID_NAME,
          "no file named with a trailing backslash");
    check(open_file_named(L"C:\\LOCKDIR\\INSIDE.TMP\\", OPEN_EXISTING) == (HANDLE)-1 &&
              GetLastError() == ERROR_INVALID_NAME,
          "no file opened with a trailing backslash");
    DbgPrint("[lock] CreateDirectoryW: a trailing backslash names a directory\n");
}

void __stdcall GuiStartup(void)
{
    trailing_backslash();
    kernel32_and_native();
    structured_storage();
    DbgPrint("[lock] PASS\n");
    ExitProcess(0);
}
