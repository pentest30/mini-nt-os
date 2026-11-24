/* The stack of a finished thread is given back: a Win32 program (subsystem
   WINDOWS), compiled with MinGW and linked to ReactOS's kernel32, which the
   scenario `thread-stack` puts on the boot disk in the place of
   winlogon.exe. A thread that ends by ExitThread (or by returning, which
   kernel32's BaseThreadStartup turns into ExitThread) asks the kernel to
   free its stack (TEB.FreeStackOnTermination), which PspExitThread does
   before it deletes the TEB; one ended by TerminateThread does not ask, and
   keeps it, as on XP. Before, Mino gave the TEB back but never the stack:
   every thread that ended in a process that lives on left its reservation,
   its committed pages and a VAD node (csrss: one per console).
   1. a thread that returns: its stack, then MEM_FREE;
   2. a thread that calls ExitThread: the same;
   3. a thread ended by TerminateThread: its stack still reserved;
   4. 20 threads that return, one after the other: their stacks all free.
   Each step goes to the debug port (DbgPrint); the program ends with 0. */
#include "app_probe.h"

#define TAG "[thrstk] "

static volatile ULONG_PTR stack_of_thread;

static DWORD WINAPI returns(LPVOID parameter)
{
    volatile int local = 0;
    stack_of_thread = (ULONG_PTR)&local;
    return (DWORD)(ULONG_PTR)parameter;
}

static DWORD WINAPI exits(LPVOID parameter)
{
    volatile int local = 0;
    stack_of_thread = (ULONG_PTR)&local;
    ExitThread((DWORD)(ULONG_PTR)parameter);
}

static DWORD WINAPI waits(LPVOID parameter)
{
    volatile int local = 0;
    (void)parameter;
    stack_of_thread = (ULONG_PTR)&local;
    while (local == 0) Sleep(1000);
    return 0;
}

/* The state of the memory at the thread's stack (MEM_FREE, MEM_RESERVE,
   MEM_COMMIT). */
static DWORD state_of_stack(void)
{
    MEMORY_BASIC_INFORMATION info = {0};
    if (!VirtualQuery((void *)stack_of_thread, &info, sizeof(info))) return 0;
    return info.State;
}

/* Runs `start` in a thread to its end (or ends it after 1 s); its exit
   code. */
static DWORD run(LPTHREAD_START_ROUTINE start, DWORD code, BOOL terminate)
{
    stack_of_thread = 0;
    HANDLE thread = CreateThread(0, 0, start, (LPVOID)(ULONG_PTR)code, 0, 0);
    if (!thread) {
        DbgPrint(TAG "FAIL CreateThread (%lu)\n", GetLastError());
        ExitProcess(1);
    }
    if (terminate) {
        while (!stack_of_thread) Sleep(10);
        TerminateThread(thread, code);
    }
    WaitForSingleObject(thread, 10000);
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);
    return exit_code;
}

DWORD WINAPI GuiStartup(void)
{
    DbgPrint(TAG "started\n");
    DWORD code = run(returns, 7, FALSE);
    DbgPrint(TAG "step 1: a thread that returns %lu: its stack %lx\n", code, state_of_stack());
    code = run(exits, 8, FALSE);
    DbgPrint(TAG "step 2: a thread that calls ExitThread(%lu): its stack %lx\n", code, state_of_stack());
    code = run(waits, 9, TRUE);
    DbgPrint(TAG "step 3: a thread ended by TerminateThread(%lu): its stack %lx\n", code, state_of_stack());
    int freed = 0;
    for (int i = 0; i < 20; ++i) {
        run(returns, i, FALSE);
        if (state_of_stack() == MEM_FREE) ++freed;
    }
    DbgPrint(TAG "step 4: 20 threads that return: %d stacks free\n", freed);
    DbgPrint(TAG "done\n");
    ExitProcess(0);
    return 0;
}
