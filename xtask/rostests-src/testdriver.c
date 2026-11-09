/* Le pilote des apitests : chaque test dans son processus fils
 * (NTAPIRUN.EXE <nom> — le main de wine/test.h, argv[1] = le test, son
 * code de sortie = ses échecs), attendu avec un délai — un test qui pend
 * coûte son délai, pas le banc. Le bilan par DbgPrint, où le scénario le
 * lit : un test passe si son fils rend 0. La liste des tests
 * (winetest_testlist, struct test) est posée par le testlist généré,
 * compilé dans le même fichier. */

#include <windows.h>

__declspec(dllimport) int __cdecl DbgPrint(const char *format, ...);

/* Le temps d'un test avant d'être tué (ms). */
#define TEST_TIMEOUT_MS 20000

static int run_one(const char *name)
{
    STARTUPINFOA startup;
    PROCESS_INFORMATION info;
    char command[256];
    DWORD exit_code;

    wsprintfA(command, "C:\\NTAPIRUN.EXE %s", name);
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&info, sizeof(info));
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info)) {
        DbgPrint("[apitest] %s: no-process=%lu\n", name, GetLastError());
        return 0;
    }
    if (WaitForSingleObject(info.hProcess, TEST_TIMEOUT_MS) != WAIT_OBJECT_0) {
        TerminateProcess(info.hProcess, 0xFFFF);
        DbgPrint("[apitest] %s: timeout\n", name);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        return 0;
    }
    if (!GetExitCodeProcess(info.hProcess, &exit_code)) {
        exit_code = 0xFFFF;
    }
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    return exit_code == 0;
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE prev, LPSTR line, int show)
{
    int total = 0, passed = 0;
    const struct test *test;
    (void)instance; (void)prev; (void)line; (void)show;
    DbgPrint("[apitest] begin\n");
    for (test = winetest_testlist; test->name != 0; ++test) {
        int ok = run_one(test->name);
        total += 1;
        passed += ok;
        DbgPrint("[apitest] %s: %s\n", test->name, ok ? "pass" : "FAIL");
    }
    DbgPrint("[apitest] TOTALS: tests=%d failures=%d skipped=0\n", total, total - passed);
    return 0;
}
