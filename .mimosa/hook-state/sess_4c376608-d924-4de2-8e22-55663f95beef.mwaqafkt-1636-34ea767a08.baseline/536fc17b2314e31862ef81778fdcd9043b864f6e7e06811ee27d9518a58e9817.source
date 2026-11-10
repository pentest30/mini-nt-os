/*
 * taskl.c — la liste des processus, la première sonde de la vague
 * applications (M7) : NtQuerySystemInformation(SystemProcessInformation),
 * le syscall que taskmgr de ReactOS relit à chaque rafraîchissement. La
 * sonde marche le buffer que le noyau rend — les entêtes
 * SYSTEM_PROCESS_INFORMATION, leurs threads, leurs noms d'image pointés
 * dans le buffer même — et le journalise, un DbgPrint par processus, où
 * le scénario `tasklist` vérifie.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup. Subsystem WINDOWS: smss refuses to
 * launch the initial command of a CUI subsystem before its subsystem
 * process registers, and csrss does not live long enough to register the
 * console one — the WINDOWS one is ready, as for SETUP1.EXE.
 */

typedef unsigned short WCHAR;
typedef unsigned short USHORT;
typedef unsigned char BYTE;
typedef unsigned int ULONG;
typedef long LONG;
typedef long NTSTATUS;
typedef void *HANDLE;
typedef void *PVOID;

/* The SYSTEM_THREAD_INFORMATION of ReactOS 0.4.16 (ndk extypes.h), i386,
 * packed to 4: 0x40 bytes. */
#pragma pack(push, 4)
typedef struct {
    long long KernelTime;
    long long UserTime;
    long long CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    ULONG ClientIdUniqueProcess;
    ULONG ClientIdUniqueThread;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
    ULONG Pad;
} SYSTEM_THREAD_INFORMATION;

/* The SYSTEM_PROCESS_INFORMATION of ReactOS 0.4.16: 0xB8 bytes of header,
 * then the threads, then the image name the buffer pointer reaches. */
typedef struct {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    long long WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    long long CycleTime;
    long long CreateTime;
    long long UserTime;
    long long KernelTime;
    USHORT ImageNameLength;
    USHORT ImageNameMaximumLength;
    WCHAR *ImageNameBuffer;
    LONG BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG PageDirectoryBase;
    ULONG PeakVirtualSize;
    ULONG VirtualSize;
    ULONG PageFaultCount;
    ULONG PeakWorkingSetSize;
    ULONG WorkingSetSize;
    ULONG QuotaPeakPagedPoolUsage;
    ULONG QuotaPagedPoolUsage;
    ULONG QuotaPeakNonPagedPoolUsage;
    ULONG QuotaNonPagedPoolUsage;
    ULONG PagefileUsage;
    ULONG PeakPagefileUsage;
    ULONG PrivatePageCount;
    long long ReadOperationCount;
    long long WriteOperationCount;
    long long OtherOperationCount;
    long long ReadTransferCount;
    long long WriteTransferCount;
    long long OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION;
#pragma pack(pop)

/* The layouts the noyau emits, checked here where the compiler can see them. */
typedef char THREAD_INFORMATION_IS_0X40[(sizeof(SYSTEM_THREAD_INFORMATION) == 0x40) ? 1 : -1];
typedef char PROCESS_INFORMATION_IS_0XB8[(sizeof(SYSTEM_PROCESS_INFORMATION) == 0xB8) ? 1 : -1];

/* Class 5 of NtQuerySystemInformation. */
#define SYSTEM_PROCESS_INFORMATION_CLASS 5
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0x80000004)

#define CURRENT_PROCESS ((HANDLE)-1)

static BYTE Buffer[0x10000];

__declspec(dllimport) ULONG __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) NTSTATUS __stdcall NtQuerySystemInformation(ULONG information_class, PVOID information,
                                                                  ULONG length, ULONG *needed);
__declspec(dllimport) NTSTATUS __stdcall NtTerminateProcess(HANDLE process, NTSTATUS status);

void __stdcall GuiStartup(void)
{
    ULONG needed = 0;
    NTSTATUS status = NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION_CLASS, Buffer, sizeof Buffer, &needed);
    DbgPrint("[apps] status %08lx, needed %lu\n", status, needed);
    if (status < 0) {
        NtTerminateProcess(CURRENT_PROCESS, status);
    }

    SYSTEM_PROCESS_INFORMATION *entry = (SYSTEM_PROCESS_INFORMATION *)Buffer;
    ULONG count = 0;
    for (;;) {
        char name[16];
        ULONG i = 0;
        for (; i < entry->ImageNameLength / 2 && i < 15; ++i) {
            name[i] = (char)entry->ImageNameBuffer[i];
        }
        name[i] = 0;
        DbgPrint("[apps] process %lu \"%s\" threads=%lu\n", entry->UniqueProcessId, name,
                 entry->NumberOfThreads);
        count = count + 1;
        if (entry->NextEntryOffset == 0) {
            break;
        }
        entry = (SYSTEM_PROCESS_INFORMATION *)((BYTE *)entry + entry->NextEntryOffset);
    }
    DbgPrint("[apps] %lu processes listed\n", count);
    NtTerminateProcess(CURRENT_PROCESS, 0);
}
