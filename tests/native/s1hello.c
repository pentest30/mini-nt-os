/*
 * Spike S1 (docs/05-feuille-de-route.md, M3): a native program (subsystem
 * NATIVE), compiled with MinGW and linked to ReactOS's ntdll only. ntdll's
 * LdrInitializeThunk initializes the process, binds these imports, then
 * enters NtProcessStartup with the PEB as its argument. The program writes
 * to the debug port with DbgPrint, then ends with its own status, which the
 * kernel checks (ntoskrnl::userland::run_boot_programs).
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point NtProcessStartup.
 */

typedef long NTSTATUS;
typedef void *HANDLE;

#define NtCurrentProcess() ((HANDLE)-1)

/* What the kernel expects when the program runs to its end. */
#define EXIT_STATUS ((NTSTATUS)0x5152)

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) NTSTATUS __stdcall NtTerminateProcess(HANDLE process, NTSTATUS status);

void __stdcall NtProcessStartup(void *peb)
{
    DbgPrint("[s1] hello from a MinGW native program, PEB %p\n", peb);
    NtTerminateProcess(NtCurrentProcess(), EXIT_STATUS);
}
