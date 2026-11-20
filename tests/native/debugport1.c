/* ProcessDebugPort (ReactOS 0.4.16 query.c and internal/probe.h as the
 * specification): exercise the real syscall from i386, including precedence
 * and output preservation on errors. No C runtime, entry GuiStartup. */
typedef unsigned long DWORD;
typedef long NTSTATUS;
typedef int BOOL;
typedef void *HANDLE;
#define SELF ((HANDLE)-1)
#define POISON 0xdeadbeefUL
#define QUERY 0x0400
#define SUCCESS 0
#define LENGTH ((NTSTATUS)0xc0000004)
#define ACCESS ((NTSTATUS)0xc0000005)
#define ALIGNMENT ((NTSTATUS)0x80000002)
#define INVALID_HANDLE ((NTSTATUS)0xc0000008)
#define TYPE ((NTSTATUS)0xc0000024)
#define DENIED ((NTSTATUS)0xc0000022)
__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *, ...);
__declspec(dllimport) NTSTATUS __stdcall NtQueryInformationProcess(HANDLE, DWORD, void *, DWORD, DWORD *);
__declspec(dllimport) HANDLE __stdcall OpenProcess(DWORD, BOOL, DWORD);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *, BOOL, BOOL, const void *);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);
__declspec(dllimport) BOOL __stdcall CheckRemoteDebuggerPresent(HANDLE, BOOL *);
__declspec(dllimport) void __stdcall ExitProcess(DWORD);

static void check(int ok, const char *what)
{
    if (!ok) {
        DbgPrint("[debug-port] FAIL %s\n", what);
        ExitProcess(1);
    }
}

static NTSTATUS query(HANDLE h, void *out, DWORD bytes, DWORD *used)
{
    return NtQueryInformationProcess(h, 7, out, bytes, used);
}

void __stdcall GuiStartup(void)
{
    DWORD out[3] = {POISON, POISON, POISON}, used, n;
    DWORD sizes[] = {0, 1, 3, 5, 8, 0xffffffffUL};
    HANDLE real = OpenProcess(QUERY, 0, GetCurrentProcessId());
    HANDLE limited = OpenProcess(0x100000, 0, GetCurrentProcessId());
    HANDLE event = CreateEventW(0, 0, 0, 0);
    BOOL debugged = 1;
    check(real && limited && event, "create test handles");
    used = POISON;
    check(query(SELF, &out[1], 4, &used) == SUCCESS && out[1] == 0 && used == 4,
          "current process");
    check(out[0] == POISON && out[2] == POISON, "i386 output width");
    out[1] = POISON;
    check(query(real, &out[1], 4, 0) == SUCCESS && out[1] == 0, "real handle, optional length");
    DbgPrint("[debug-port] current and real process handles: zero, four bytes\n");

    for (n = 0; n < sizeof(sizes) / sizeof(sizes[0]); ++n) {
        out[1] = used = POISON;
        check(query(SELF, &out[1], sizes[n], &used) == LENGTH && out[1] == POISON && used == POISON,
              "exact length, outputs unchanged");
    }
    check(query(0, (void *)1, 0, (DWORD *)1) == LENGTH, "length checked first");
    used = POISON;
    check(query(SELF, (char *)out + 1, 4, &used) == ALIGNMENT && used == POISON,
          "unaligned buffer");
    check(query(SELF, (void *)0x80000000, 4, &used) == ACCESS && used == POISON,
          "kernel buffer");
    check(query(SELF, 0, 4, &used) == ACCESS && used == 4, "null buffer, length returned");
    out[1] = POISON;
    check(query(SELF, &out[1], 4, (DWORD *)0x80000000) == ACCESS && out[1] == POISON,
          "bad return length before output");
    check(query(SELF, &out[1], 4, (DWORD *)0x7ffe0000) == ACCESS && out[1] == POISON,
          "read-only return length before output");
    /* ProbeForWriteUlong permits an unaligned ReturnLength. */
    out[0] = out[1] = out[2] = POISON;
    check(query(SELF, &out[2], 4, (DWORD *)((char *)out + 1)) == SUCCESS && out[2] == 0,
          "unaligned return length accepted");
    check(((unsigned char *)out)[1] == 4 && ((unsigned char *)out)[2] == 0 &&
          ((unsigned char *)out)[3] == 0 && ((unsigned char *)out)[4] == 0,
          "unaligned return length bytes");
    used = POISON;
    check(query(SELF, (void *)0x7ffe0000, 4, &used) == ACCESS && used == 4, "read-only output");
    DbgPrint("[debug-port] lengths and user pointers checked\n");

    out[1] = used = POISON;
    check(query(0, &out[1], 4, &used) == INVALID_HANDLE && out[1] == POISON && used == 4,
          "null process handle");
    used = POISON;
    check(query(event, &out[1], 4, &used) == TYPE && out[1] == POISON && used == 4, "event handle");
    check(query(limited, &out[1], 4, &used) == DENIED && out[1] == POISON, "query access required");
    check(CloseHandle(real), "close query handle");
    check(query(real, &out[1], 4, &used) == INVALID_HANDLE, "closed handle");
    DbgPrint("[debug-port] handle type and query access checked\n");
    check(CheckRemoteDebuggerPresent(SELF, &debugged) && !debugged, "kernel32 wrapper");
    DbgPrint("[debug-port] kernel32 CheckRemoteDebuggerPresent: false\n");
    check(CloseHandle(limited) && CloseHandle(event), "close remaining handles");
    DbgPrint("[debug-port] PASS\n");
    ExitProcess(0);
}
