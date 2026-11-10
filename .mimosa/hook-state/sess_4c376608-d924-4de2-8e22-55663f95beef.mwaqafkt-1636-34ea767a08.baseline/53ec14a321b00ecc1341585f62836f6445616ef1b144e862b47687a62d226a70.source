/* Le main de lot des apitests : itère la liste des tests
 * (winetest_testlist, posée par testlist.c), rend le résumé de chacun par
 * DbgPrint — le port série, où le scénario le lit — et un bilan final. Le
 * main d'un seul test de wine/test.h est écarté (testlist.c est compilé
 * avec -Dmain=apitest_wine_main). Chaque test tourne sous __try (PSEH) :
 * celui qui plante ne tue pas le banc — il compte pour un échec. */

#include <windows.h>
#include <pseh/pseh2.h>

__declspec(dllimport) int __cdecl DbgPrint(const char *format, ...);

/* Layout-compatible avec struct test de wine/test.h (STANDALONE). */
struct apitest {
    const char *name;
    void (*func)(void);
};
extern const struct apitest winetest_testlist[];

/* Les compteurs de wine/test.h (définis dans testlist.o, STANDALONE). */
extern LONG winetest_successes, winetest_failures, winetest_skipped;
extern LONG winetest_todo_successes, winetest_todo_failures;

/* La cible de saut de NtContinue.c, que son fichier ne définit que sous
 * MSVC (asm inline) — un point de retour sans effet sous MinGW. */
void continuePoint(void);

void continuePoint(void)
{
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE prev, LPSTR line, int show)
{
    int total = 0, failed = 0, skipped = 0;
    const struct apitest *test;
    (void)instance; (void)prev; (void)line; (void)show;
    DbgPrint("[apitest] begin\n");
    for (test = winetest_testlist; test->name != 0; ++test) {
        int ok, todo, fails, skip, crashed;
        winetest_successes = winetest_failures = 0;
        winetest_todo_successes = winetest_todo_failures = 0;
        winetest_skipped = 0;
        crashed = 0;
        _SEH2_TRY
        {
            test->func();
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            crashed = 1;
        }
        _SEH2_END;
        ok = winetest_successes;
        todo = winetest_todo_successes;
        fails = winetest_failures + winetest_todo_failures + crashed;
        skip = winetest_skipped;
        skipped += skip;
        total += ok + todo + fails;
        failed += fails;
        DbgPrint("[apitest] %s: ok=%d todo=%d fail=%d skip=%d%s\n",
                 test->name, ok, todo, fails, skip, crashed ? " (AV)" : "");
    }
    DbgPrint("[apitest] TOTALS: tests=%d failures=%d skipped=%d\n", total, failed, skipped);
    return 0;
}
