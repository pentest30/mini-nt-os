/* A whole session (M7, the second criterion: opening, work, shutdown, with
   no fatal error nor measurable pool leak). Started by userinit as the shell
   of the logged-on user (a scenario's `session`), it does the same work
   several times, and reads the kernel's pools after each round
   (NtQuerySystemInformation, SystemPoolTagInformation: the bytes each tag
   holds in the paged and non-paged pools):
   1. writes C:\WORK.TXT;
   2. has cmd.exe copy it (`cmd /c copy`): a console process, made and ended;
   3. opens it in notepad.exe, waits for its window, closes it (WM_CLOSE)
      and waits for its end.
   The first round warms the caches (fonts, sections, the console's); a
   leak is what the pools grow by from the second round to the last, read
   once they hold still after each round (three readings 500 ms apart that
   agree: what is finished after a process ends — the reaper's stacks,
   csrss's clean-up of a dead client, the image contents its section held —
   is done by then).
   The program prints the totals of each round, the growth and the tags that
   grew, says PASS if it is at most LEAK_LIMIT bytes and FAIL otherwise, then
   ends the session as shutdn1.c does: its window, then
   ExitWindowsEx(EWX_SHUTDOWN | EWX_POWEROFF). */
#include "app_probe.h"

#define TAG "[work] "
#define ROUNDS 4
/* What the pools may grow by from round 2 to the last: none was measured; a
   leaked block, a section's page table (a client's view at csrss) or a VAD
   node per round (a thread's stack), goes past it. */
#define LEAK_LIMIT 256

__declspec(dllimport) LONG NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
__declspec(dllimport) LONG NTAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

/* SystemPoolTagInformation and its SYSTEM_POOLTAG entries. */
#define SYSTEM_POOL_TAG_INFORMATION 22
#define SHUTDOWN_PRIVILEGE 19
#define MAX_TAGS 160

typedef struct {
    DWORD tag;
    DWORD paged_allocs, paged_frees, paged_used;
    DWORD non_paged_allocs, non_paged_frees, non_paged_used;
} POOL_TAG;

typedef struct {
    DWORD count;
    POOL_TAG tags[MAX_TAGS];
} POOL;

static POOL rounds[ROUNDS + 1];

/* The pools now, into `pool`; FALSE if the query fails. */
static BOOL read_pools(POOL *pool)
{
    ULONG size = 0;
    LONG status = NtQuerySystemInformation(SYSTEM_POOL_TAG_INFORMATION, pool, sizeof(*pool), &size);
    if (status < 0) {
        DbgPrint(TAG "FAIL SystemPoolTagInformation: %08lx (%lu bytes)\n", status, size);
        return FALSE;
    }
    return TRUE;
}

static DWORD total(const POOL *pool);

/* Reads the pools into `pool` once they hold still: three readings 500 ms
   apart with the same total, 20 s at most. */
static BOOL settled_pools(POOL *pool)
{
    DWORD last = 0, same = 0;
    for (int tries = 0; tries < 40; ++tries) {
        Sleep(500);
        if (!read_pools(pool)) return FALSE;
        DWORD now = total(pool);
        same = now == last ? same + 1 : 0;
        last = now;
        if (same == 2) return TRUE;
    }
    DbgPrint(TAG "the pools did not hold still in 20 s\n");
    return TRUE;
}

static DWORD total(const POOL *pool)
{
    DWORD bytes = 0;
    for (DWORD i = 0; i < pool->count && i < MAX_TAGS; ++i) bytes += pool->tags[i].paged_used + pool->tags[i].non_paged_used;
    return bytes;
}

static const POOL_TAG *find(const POOL *pool, DWORD tag)
{
    for (DWORD i = 0; i < pool->count && i < MAX_TAGS; ++i)
        if (pool->tags[i].tag == tag) return &pool->tags[i];
    return 0;
}

static const char *tag_name(DWORD tag)
{
    static char name[5];
    for (int i = 0; i < 4; ++i) {
        char c = (char)(tag >> (8 * i));
        name[i] = c >= 0x20 && c < 0x7F ? c : '.';
    }
    name[4] = 0;
    return name;
}

/* The first visible top-level window of the process `pid`. */
struct first_window { DWORD pid; HWND window; };
static BOOL CALLBACK first_window_of(HWND window, LPARAM argument)
{
    struct first_window *find = (struct first_window *)argument;
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid != find->pid || !IsWindowVisible(window)) return TRUE;
    find->window = window;
    return FALSE;
}

/* Runs `command` and waits for its end, `seconds` at most; its exit code, or
   0xDEAD if it had to be ended. */
static DWORD run(WCHAR *command, DWORD seconds)
{
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD code = 0xDEAD;
    startup.cb = sizeof(startup);
    if (!CreateProcessW(0, command, 0, 0, FALSE, 0, 0, L"C:\\", &startup, &process)) {
        DbgPrint(TAG "FAIL CreateProcessW (%lu)\n", GetLastError());
        return code;
    }
    if (WaitForSingleObject(process.hProcess, seconds * 1000) == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &code);
    } else {
        TerminateProcess(process.hProcess, 0xDEAD);
        WaitForSingleObject(process.hProcess, 5000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}

/* One round of work; TRUE if every step went as it should. */
static BOOL work(int round)
{
    static const char text[] = "Mino: a round of work in the session.\r\n";
    DWORD written = 0;
    HANDLE file = CreateFileW(L"C:\\WORK.TXT", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    BOOL ok = file != INVALID_HANDLE_VALUE && WriteFile(file, text, sizeof(text) - 1, &written, 0);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (!ok) {
        DbgPrint(TAG "FAIL round %d: C:\\WORK.TXT not written (%lu)\n", round, GetLastError());
        return FALSE;
    }
    WCHAR copy[] = L"C:\\WINDOWS\\system32\\cmd.exe /c copy C:\\WORK.TXT C:\\COPY.TXT";
    DWORD copied = run(copy, 60);
    WIN32_FILE_ATTRIBUTE_DATA data = {0};
    BOOL there = GetFileAttributesExW(L"C:\\COPY.TXT", GetFileExInfoStandard, &data);
    if (copied != 0 || !there || data.nFileSizeLow != sizeof(text) - 1) {
        DbgPrint(TAG "FAIL round %d: cmd copy gave %lx, the copy %d (%lu bytes)\n", round, copied, there,
                 data.nFileSizeLow);
        return FALSE;
    }

    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    WCHAR notepad[] = L"C:\\WINDOWS\\system32\\notepad.exe C:\\WORK.TXT";
    startup.cb = sizeof(startup);
    if (!CreateProcessW(0, notepad, 0, 0, FALSE, 0, 0, L"C:\\", &startup, &process)) {
        DbgPrint(TAG "FAIL round %d: notepad does not start (%lu)\n", round, GetLastError());
        return FALSE;
    }
    struct first_window find = {process.dwProcessId, 0};
    for (int tries = 0; tries < 300 && !find.window; ++tries) {
        Sleep(100);
        EnumWindows(first_window_of, (LPARAM)&find);
    }
    DWORD code = 0xDEAD;
    if (find.window) {
        PostMessageW(find.window, WM_CLOSE, 0, 0);
        if (WaitForSingleObject(process.hProcess, 30000) == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &code);
    }
    if (code == 0xDEAD) {
        TerminateProcess(process.hProcess, 0xDEAD);
        WaitForSingleObject(process.hProcess, 5000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    DeleteFileW(L"C:\\COPY.TXT");
    DeleteFileW(L"C:\\WORK.TXT");
    if (!find.window || code != 0) {
        DbgPrint(TAG "FAIL round %d: notepad's window %d, its exit code %lx\n", round, find.window != 0, code);
        return FALSE;
    }
    return TRUE;
}

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_QUERYENDSESSION:
        DbgPrint(TAG "WM_QUERYENDSESSION\n");
        return TRUE;
    case WM_ENDSESSION:
        DbgPrint(TAG "WM_ENDSESSION %u\n", (unsigned)wparam);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

DWORD WINAPI GuiStartup(void)
{
    DbgPrint(TAG "in the session\n");
    if (!read_pools(&rounds[0])) ExitProcess(1);
    DbgPrint(TAG "pools after the logon: %lu bytes in %lu tags\n", total(&rounds[0]), rounds[0].count);
    for (int round = 1; round <= ROUNDS; ++round) {
        if (!work(round) || !settled_pools(&rounds[round])) ExitProcess(1);
        const POOL_TAG *rust = find(&rounds[round], 0x74737552); /* "Rust" */
        DbgPrint(TAG "round %d done: pools %lu bytes in %lu tags (Rust %lu)\n", round, total(&rounds[round]),
                 rounds[round].count, rust ? rust->non_paged_used : 0);
    }
    const POOL *from = &rounds[2], *to = &rounds[ROUNDS];
    LONG growth = (LONG)(total(to) - total(from));
    DbgPrint(TAG "growth from round 2 to round %d: %ld bytes\n", ROUNDS, growth);
    for (DWORD i = 0; i < to->count && i < MAX_TAGS; ++i) {
        const POOL_TAG *now = &to->tags[i], *before = find(from, now->tag);
        LONG paged = (LONG)(now->paged_used - (before ? before->paged_used : 0));
        LONG non_paged = (LONG)(now->non_paged_used - (before ? before->non_paged_used : 0));
        if (paged || non_paged)
            DbgPrint(TAG "  %s: paged %+ld, non-paged %+ld (allocations %lu, frees %lu)\n", tag_name(now->tag), paged,
                     non_paged, now->non_paged_allocs + now->paged_allocs, now->non_paged_frees + now->paged_frees);
    }
    if (growth <= LEAK_LIMIT)
        DbgPrint(TAG "PASS: the pools grew by %ld bytes from round 2 to round %d (at most %d)\n", growth, ROUNDS,
                 LEAK_LIMIT);
    else
        DbgPrint(TAG "FAIL: the pools grew by %ld bytes from round 2 to round %d (at most %d)\n", growth, ROUNDS,
                 LEAK_LIMIT);
    DbgPrint(TAG "work done\n");

    WNDCLASSW class = {0};
    class.lpfnWndProc = procedure;
    class.hInstance = GetModuleHandleW(0);
    class.lpszClassName = L"WorkProbe";
    RegisterClassW(&class);
    CreateWindowExW(0, L"WorkProbe", L"Work probe", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, 320, 200, 0, 0,
                    class.hInstance, 0);
    BOOLEAN was = FALSE;
    RtlAdjustPrivilege(SHUTDOWN_PRIVILEGE, TRUE, FALSE, &was);
    BOOL asked = ExitWindowsEx(EWX_SHUTDOWN | EWX_POWEROFF, 0);
    DbgPrint(TAG "ExitWindowsEx: %d\n", asked);
    MSG message;
    while (GetMessageW(&message, 0, 0, 0) > 0) DispatchMessageW(&message);
    ExitProcess(0);
    return 0;
}
