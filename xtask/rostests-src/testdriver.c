/* Le pilote des apitests : chaque test dans son processus fils
 * (NTAPIRUN.EXE <nom> — le main de wine/test.h, argv[1] = le test, son
 * code de sortie = ses échecs), attendu avec un délai — un test qui pend
 * coûte son délai, pas le banc. Le bilan par DbgPrint, où le scénario le
 * lit : un test passe si son fils rend 0. La liste des tests
 * (winetest_testlist, struct test) est posée par le testlist généré,
 * compilé dans le même fichier.
 *
 * Le pilote tient la place de winlogon (la commande initiale de smss) :
 * comme lui, il s'inscrit comme processus de logon, crée WinSta0 et son
 * bureau Default, et y lance ses fils. Chaque fils part détaché
 * (DETACHED_PROCESS : sans console, pas de fenêtre de consrv par test), sa
 * sortie standard et d'erreur dans C:\APITEST.OUT, que le pilote relaie
 * ensuite par DbgPrint (« [apitest] | … ») : les échecs de chaque test sont
 * dans le journal série. */

#include <windows.h>

__declspec(dllimport) int __cdecl DbgPrint(const char *format, ...);
/* user32, non déclarée par MinGW. */
__declspec(dllimport) BOOL WINAPI RegisterLogonProcess(DWORD process_id, BOOL secure);

/* Le temps d'un test avant d'être tué (ms). */
#define TEST_TIMEOUT_MS 20000
/* Ce que l'on relaie de la sortie d'un test. */
#define OUTPUT_PATH "C:\\APITEST.OUT"
#define OUTPUT_MAX_BYTES 32768
#define OUTPUT_MAX_LINES 60

static char output[OUTPUT_MAX_BYTES + 1];

/* Comme winlogon : le processus de logon, WinSta0, son bureau Default. */
static void take_a_desktop(void)
{
    HWINSTA station;
    HDESK desktop;

    if (!RegisterLogonProcess(GetCurrentProcessId(), TRUE)) {
        DbgPrint("[apitest] RegisterLogonProcess: error %lu\n", GetLastError());
        return;
    }
    station = CreateWindowStationW(L"WinSta0", 0, MAXIMUM_ALLOWED, NULL);
    if (!station || !SetProcessWindowStation(station)) {
        DbgPrint("[apitest] WinSta0: error %lu\n", GetLastError());
        return;
    }
    desktop = CreateDesktopW(L"Default", NULL, NULL, 0, MAXIMUM_ALLOWED, NULL);
    if (!desktop || !SetThreadDesktop(desktop) || !SwitchDesktop(desktop)) {
        DbgPrint("[apitest] WinSta0\\Default: error %lu\n", GetLastError());
        return;
    }
    DbgPrint("[apitest] on WinSta0\\Default\n");
}

/* La sortie du dernier test, ligne par ligne, bornée. */
static void relay_output(void)
{
    HANDLE file;
    DWORD length = 0;
    DWORD lines = 0, skipped = 0;
    char *line, *end;

    file = CreateFileA(OUTPUT_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DbgPrint("[apitest] | (no output: error %lu)\n", GetLastError());
        return;
    }
    if (!ReadFile(file, output, OUTPUT_MAX_BYTES, &length, NULL))
        length = 0;
    CloseHandle(file);
    output[length] = 0;
    for (line = output; *line; line = end) {
        end = line;
        while (*end && *end != '\n')
            ++end;
        if (*end)
            *end++ = 0;
        if (end - line > 1 && end[-1] == 0 && end[-2] == '\r')
            end[-2] = 0;
        if (!*line)
            continue;
        if (lines < OUTPUT_MAX_LINES) {
            DbgPrint("[apitest] | %.200s\n", line);
            ++lines;
        } else {
            ++skipped;
        }
    }
    if (skipped)
        DbgPrint("[apitest] | ... %lu more lines\n", skipped);
}

static int run_one(const char *name)
{
    SECURITY_ATTRIBUTES inherit;
    STARTUPINFOA startup;
    PROCESS_INFORMATION info;
    char command[256];
    DWORD exit_code;
    HANDLE out;

    inherit.nLength = sizeof(inherit);
    inherit.lpSecurityDescriptor = NULL;
    inherit.bInheritHandle = TRUE;
    out = CreateFileA(OUTPUT_PATH, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        DbgPrint("[apitest] %s: no-output-file=%lu\n", name, GetLastError());
        return 0;
    }

    wsprintfA(command, "C:\\NTAPIRUN.EXE %s", name);
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    startup.lpDesktop = "WinSta0\\Default";
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = NULL;
    startup.hStdOutput = out;
    startup.hStdError = out;
    ZeroMemory(&info, sizeof(info));
    if (!CreateProcessA(NULL, command, NULL, NULL, TRUE, DETACHED_PROCESS, NULL, NULL, &startup, &info)) {
        DbgPrint("[apitest] %s: no-process=%lu\n", name, GetLastError());
        CloseHandle(out);
        return 0;
    }
    /* Le fils tient sa copie du handle. */
    CloseHandle(out);
    if (WaitForSingleObject(info.hProcess, TEST_TIMEOUT_MS) != WAIT_OBJECT_0) {
        TerminateProcess(info.hProcess, 0xFFFF);
        WaitForSingleObject(info.hProcess, TEST_TIMEOUT_MS);
        relay_output();
        DbgPrint("[apitest] %s: FAIL (timeout)\n", name);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        return 0;
    }
    if (!GetExitCodeProcess(info.hProcess, &exit_code)) {
        exit_code = 0xFFFF;
    }
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    relay_output();
    if (exit_code == 0) {
        DbgPrint("[apitest] %s: pass\n", name);
    } else {
        DbgPrint("[apitest] %s: FAIL (exit %lx)\n", name, exit_code);
    }
    return exit_code == 0;
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE prev, LPSTR line, int show)
{
    int total = 0, passed = 0;
    const struct test *test;
    (void)instance; (void)prev; (void)line; (void)show;
    take_a_desktop();
    DbgPrint("[apitest] begin\n");
    for (test = winetest_testlist; test->name != 0; ++test) {
        total += 1;
        passed += run_one(test->name);
    }
    DbgPrint("[apitest] TOTALS: tests=%d failures=%d skipped=0\n", total, total - passed);
    /* WinMain@16 est le point d'entrée même (-nostartfiles) : kernel32
     * l'appelle sans ses quatre arguments, il ne doit pas revenir. */
    ExitProcess(0);
    return 0;
}
