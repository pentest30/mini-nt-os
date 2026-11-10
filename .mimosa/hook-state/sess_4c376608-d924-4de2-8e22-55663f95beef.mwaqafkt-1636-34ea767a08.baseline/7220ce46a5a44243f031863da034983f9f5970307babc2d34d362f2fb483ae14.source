/*
 * A program that runs longer than 10 s without a key, then says so: the
 * `interactive` scenario puts it in place of winlogon.exe. With the kernel's
 * `interactive` feature, the native-program probe waits for it without a
 * deadline (a person drives the system, as on VirtualBox); without it, the
 * probe ends it 10 s after its start, which killed the installer mid-copy.
 *
 * Built by `cargo xtask` without a C runtime: -nostdlib, entry point
 * GuiStartup.
 */

typedef unsigned long DWORD;
typedef unsigned int UINT;

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);

DWORD __stdcall GuiStartup(void)
{
    DbgPrint("[wait] started; no key for 12 s\n");
    Sleep(12000);
    DbgPrint("[wait] still running 12 s after its start\n");
    ExitProcess(0);
    return 0;
}
