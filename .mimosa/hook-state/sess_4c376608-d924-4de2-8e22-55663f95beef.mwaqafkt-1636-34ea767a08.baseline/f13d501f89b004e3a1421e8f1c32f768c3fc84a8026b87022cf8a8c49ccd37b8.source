/*
 * M5, named pipes (NPFS): a Win32 program (subsystem WINDOWS), compiled with
 * MinGW and linked to ReactOS's kernel32, which the scenario `pipes` puts on
 * the boot disk in the place of winlogon.exe. It exercises the named pipe
 * file system through kernel32, as rpcrt4 and cmd.exe will:
 *
 * - a message pipe, \\.\pipe\mino\test, whose server is overlapped like
 *   rpcrt4's (CreateNamedPipeW with FILE_FLAG_OVERLAPPED, ConnectNamedPipe
 *   with an event: FSCTL_PIPE_LISTEN pending), and a client thread that
 *   waits for an instance (WaitNamedPipeW), opens it (CreateFileW), reads in
 *   message mode (SetNamedPipeHandleState), writes two messages and waits
 *   for a reply; the server peeks (PeekNamedPipe), reads part of a message
 *   (ERROR_MORE_DATA), then the rest, replies, and its pending read ends
 *   with the client's close (ERROR_BROKEN_PIPE); then a disconnect, a
 *   cancelled listen (CancelIo), the instance limit, a busy pipe and a
 *   timed-out wait, and the pipe gone with its last instance;
 * - an anonymous pipe (CreatePipe: byte mode, synchronous), with a 16-byte
 *   quota: reads across writes, a write past the quota that waits for
 *   reads, a read that waits for a write, and a broken pipe.
 *
 * Each result goes to the debug port (DbgPrint), where the scenario looks
 * for it; the program ends with EXIT_STATUS.
 *
 * Built by `cargo xtask` (xtask/src/native.rs) without a C runtime:
 * -nostdlib, entry point GuiStartup.
 */

typedef unsigned short WCHAR;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef unsigned long ULONG_PTR;
typedef int BOOL;
typedef void *HANDLE;

typedef struct {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    DWORD Offset;
    DWORD OffsetHigh;
    HANDLE hEvent;
} OVERLAPPED;

typedef DWORD(__stdcall *THREAD_START)(void *parameter);

#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define OPEN_EXISTING 3
#define PIPE_ACCESS_DUPLEX 0x00000003
#define FILE_FLAG_OVERLAPPED 0x40000000
#define PIPE_TYPE_MESSAGE 0x00000004
#define PIPE_READMODE_MESSAGE 0x00000002
#define PIPE_WAIT 0x00000000
#define NMPWAIT_WAIT_FOREVER 0xFFFFFFFF
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define INFINITE 0xFFFFFFFF
#define ERROR_IO_PENDING 997
#define EXIT_STATUS 0x600D
#define QUOTA 16

__declspec(dllimport) unsigned long __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) void __stdcall ExitProcess(UINT code);
__declspec(dllimport) void __stdcall Sleep(DWORD milliseconds);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE handle);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);
__declspec(dllimport) HANDLE __stdcall CreateEventW(void *attributes, BOOL manual, BOOL initial, const WCHAR *name);
__declspec(dllimport) BOOL __stdcall SetEvent(HANDLE event);
__declspec(dllimport) HANDLE __stdcall CreateThread(void *attributes, DWORD stack, THREAD_START start,
                                                    void *parameter, DWORD flags, DWORD *id);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access, DWORD share, void *attributes,
                                                   DWORD disposition, DWORD flags, HANDLE template_file);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE file, void *buffer, DWORD size, DWORD *read,
                                              OVERLAPPED *overlapped);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE file, const void *buffer, DWORD size, DWORD *written,
                                               OVERLAPPED *overlapped);
__declspec(dllimport) BOOL __stdcall GetOverlappedResult(HANDLE file, OVERLAPPED *overlapped, DWORD *transferred,
                                                         BOOL wait);
__declspec(dllimport) BOOL __stdcall CancelIo(HANDLE file);
__declspec(dllimport) DWORD __stdcall GetFileType(HANDLE file);
__declspec(dllimport) HANDLE __stdcall CreateNamedPipeW(const WCHAR *name, DWORD open_mode, DWORD pipe_mode,
                                                        DWORD instances, DWORD out_size, DWORD in_size,
                                                        DWORD timeout, void *attributes);
__declspec(dllimport) BOOL __stdcall ConnectNamedPipe(HANDLE pipe, OVERLAPPED *overlapped);
__declspec(dllimport) BOOL __stdcall DisconnectNamedPipe(HANDLE pipe);
__declspec(dllimport) BOOL __stdcall WaitNamedPipeW(const WCHAR *name, DWORD timeout);
__declspec(dllimport) BOOL __stdcall PeekNamedPipe(HANDLE pipe, void *buffer, DWORD size, DWORD *read,
                                                   DWORD *available, DWORD *left);
__declspec(dllimport) BOOL __stdcall SetNamedPipeHandleState(HANDLE pipe, DWORD *mode, DWORD *count,
                                                             DWORD *timeout);
__declspec(dllimport) BOOL __stdcall GetNamedPipeInfo(HANDLE pipe, DWORD *flags, DWORD *out_size, DWORD *in_size,
                                                      DWORD *instances);
__declspec(dllimport) BOOL __stdcall CreatePipe(HANDLE *read, HANDLE *write, void *attributes, DWORD size);

static const WCHAR NAME[] = L"\\\\.\\pipe\\mino\\test";
static const WCHAR MISSING[] = L"\\\\.\\pipe\\nothing";

/* The client of the message pipe tells the server it wrote its messages. */
static HANDLE written_event;

static void zero(void *memory, DWORD size)
{
    volatile char *bytes = memory;
    while (size--)
        *bytes++ = 0;
}

/* `size` bytes of `data` as a string, in `out` (at least 65 bytes). */
static const char *text(const char *data, DWORD size, char *out)
{
    DWORD i;
    for (i = 0; i < size && i < 64; i++)
        out[i] = data[i];
    out[i] = 0;
    return out;
}

static HANDLE open_client(void)
{
    return CreateFileW(NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
}

static DWORD __stdcall message_client(void *parameter)
{
    char buffer[64], shown[65];
    DWORD mode = PIPE_READMODE_MESSAGE, done = 0;
    HANDLE client;
    BOOL ok;
    (void)parameter;
    ok = WaitNamedPipeW(NAME, NMPWAIT_WAIT_FOREVER);
    DbgPrint("[pipe-client] WaitNamedPipeW: %d\n", ok);
    client = open_client();
    if (client == INVALID_HANDLE_VALUE) {
        DbgPrint("[pipe-client] CreateFileW failed: %lu\n", GetLastError());
        return 1;
    }
    ok = SetNamedPipeHandleState(client, &mode, 0, 0);
    DbgPrint("[pipe-client] SetNamedPipeHandleState(message): %d\n", ok);
    ok = WriteFile(client, "hello", 5, &done, 0);
    DbgPrint("[pipe-client] WriteFile: %d, %lu bytes\n", ok, done);
    ok = WriteFile(client, "world!!", 7, &done, 0);
    DbgPrint("[pipe-client] WriteFile: %d, %lu bytes\n", ok, done);
    SetEvent(written_event);
    /* Waits for the server's reply. */
    ok = ReadFile(client, buffer, sizeof(buffer), &done, 0);
    DbgPrint("[pipe-client] ReadFile: %d, %lu bytes, %s\n", ok, done, text(buffer, done, shown));
    CloseHandle(client);
    return 0;
}

/* An overlapped read of `size` bytes from `pipe`, ended or waited for. */
static void overlapped_read(HANDLE pipe, DWORD size, const char *what)
{
    char buffer[64], shown[65];
    OVERLAPPED overlapped;
    DWORD done = 0, error = 0;
    BOOL ok;
    zero(&overlapped, sizeof(overlapped));
    overlapped.hEvent = CreateEventW(0, 1, 0, 0);
    ok = ReadFile(pipe, buffer, size, &done, &overlapped);
    if (!ok) {
        error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            ok = GetOverlappedResult(pipe, &overlapped, &done, 1);
            error = ok ? 0 : GetLastError();
        } else {
            done = overlapped.InternalHigh;
        }
    }
    DbgPrint("[pipe] ReadFile %s: %d, error %lu, %lu bytes, %s\n", what, ok, error, done,
             text(buffer, done, shown));
    CloseHandle(overlapped.hEvent);
}

static void message_pipe(void)
{
    OVERLAPPED listen, pending;
    char buffer[64];
    DWORD done = 0, available = 0, left = 0, flags = 0, out_size = 0, in_size = 0, instances = 0;
    HANDLE server, second, third, client, busy, thread;
    BOOL ok;

    busy = CreateFileW(MISSING, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    DbgPrint("[pipe] CreateFileW of a missing pipe: %d, error %lu\n", busy != INVALID_HANDLE_VALUE, GetLastError());
    ok = WaitNamedPipeW(MISSING, 10);
    DbgPrint("[pipe] WaitNamedPipeW of a missing pipe: %d, error %lu\n", ok, GetLastError());

    server = CreateNamedPipeW(NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                              PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 2, 256, 256, 0, 0);
    if (server == INVALID_HANDLE_VALUE) {
        DbgPrint("[pipe] CreateNamedPipeW failed: %lu\n", GetLastError());
        ExitProcess(1);
    }
    DbgPrint("[pipe] CreateNamedPipeW: a server, type %lu\n", GetFileType(server));
    zero(&listen, sizeof(listen));
    listen.hEvent = CreateEventW(0, 1, 0, 0);
    ok = ConnectNamedPipe(server, &listen);
    DbgPrint("[pipe] ConnectNamedPipe: %d, error %lu\n", ok, GetLastError());

    written_event = CreateEventW(0, 1, 0, 0);
    thread = CreateThread(0, 0, message_client, 0, 0, 0);
    /* Read once the wait is over: arguments have no order of evaluation. */
    done = WaitForSingleObject(listen.hEvent, 5000);
    DbgPrint("[pipe] the listen ended: wait %lu, status %lx\n", done, listen.Internal);
    WaitForSingleObject(written_event, 5000);
    ok = PeekNamedPipe(server, 0, 0, 0, &available, &left);
    DbgPrint("[pipe] PeekNamedPipe: %d, %lu bytes, %lu left in this message\n", ok, available, left);
    overlapped_read(server, 3, "of 3 bytes");
    overlapped_read(server, 64, "of the rest");
    overlapped_read(server, 64, "of the second message");

    /* A read that waits, then ends with the client's close. */
    zero(&pending, sizeof(pending));
    pending.hEvent = CreateEventW(0, 1, 0, 0);
    ok = ReadFile(server, buffer, sizeof(buffer), &done, &pending);
    DbgPrint("[pipe] ReadFile with nothing to read: %d, error %lu\n", ok, GetLastError());
    zero(&listen.Internal, sizeof(listen.Internal));
    ok = WriteFile(server, "ok", 2, &done, &listen);
    DbgPrint("[pipe] WriteFile of the reply: %d, %lu bytes\n", ok, done);
    ok = GetOverlappedResult(server, &pending, &done, 1);
    DbgPrint("[pipe] the waiting read: %d, error %lu\n", ok, ok ? 0 : GetLastError());
    done = WaitForSingleObject(thread, 5000);
    DbgPrint("[pipe] the client thread: wait %lu\n", done);

    ok = GetNamedPipeInfo(server, &flags, &out_size, &in_size, &instances);
    DbgPrint("[pipe] GetNamedPipeInfo: %d, flags %lu, out %lu, in %lu, instances %lu\n", ok, flags, out_size,
             in_size, instances);
    ok = DisconnectNamedPipe(server);
    DbgPrint("[pipe] DisconnectNamedPipe: %d\n", ok);

    /* A listen, cancelled. */
    ok = ConnectNamedPipe(server, &listen);
    ok = CancelIo(server);
    ok = GetOverlappedResult(server, &listen, &done, 1);
    DbgPrint("[pipe] a cancelled listen: %d, error %lu\n", ok, GetLastError());

    /* Two instances at most. */
    second = CreateNamedPipeW(NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 2, 256, 256, 0, 0);
    third = CreateNamedPipeW(NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 2, 256, 256, 0, 0);
    DbgPrint("[pipe] a second instance: %d; a third: %d, error %lu\n", second != INVALID_HANDLE_VALUE,
             third != INVALID_HANDLE_VALUE, GetLastError());
    DisconnectNamedPipe(server);
    client = open_client();
    busy = open_client();
    DbgPrint("[pipe] a client of the second instance: %d; another: %d, error %lu\n", client != INVALID_HANDLE_VALUE,
             busy != INVALID_HANDLE_VALUE, GetLastError());
    ok = WaitNamedPipeW(NAME, 50);
    DbgPrint("[pipe] WaitNamedPipeW of a busy pipe: %d, error %lu\n", ok, GetLastError());
    WriteFile(client, "x", 1, &done, 0);
    ok = ReadFile(second, buffer, sizeof(buffer), &done, 0);
    DbgPrint("[pipe] the second instance reads: %d, %lu bytes\n", ok, done);
    CloseHandle(client);
    CloseHandle(second);
    CloseHandle(server);
    busy = open_client();
    DbgPrint("[pipe] the pipe after its last instance: %d, error %lu\n", busy != INVALID_HANDLE_VALUE,
             GetLastError());
}

static HANDLE anonymous_read, anonymous_write;

static DWORD __stdcall stalled_writer(void *parameter)
{
    char data[40];
    DWORD i, done = 0;
    BOOL ok;
    (void)parameter;
    for (i = 0; i < sizeof(data); i++)
        data[i] = (char)('A' + i % 26);
    ok = WriteFile(anonymous_write, data, sizeof(data), &done, 0);
    DbgPrint("[pipe-writer] WriteFile past the quota: %d, %lu bytes\n", ok, done);
    return 0;
}

static DWORD __stdcall waiting_reader(void *parameter)
{
    char buffer[64], shown[65];
    DWORD done = 0;
    BOOL ok;
    (void)parameter;
    ok = ReadFile(anonymous_read, buffer, sizeof(buffer), &done, 0);
    DbgPrint("[pipe-reader] ReadFile: %d, %lu bytes, %s\n", ok, done, text(buffer, done, shown));
    return 0;
}

static void anonymous_pipe(void)
{
    char buffer[64], shown[65];
    DWORD done = 0, available = 0, total = 0, wait;
    HANDLE thread;
    BOOL ok;

    ok = CreatePipe(&anonymous_read, &anonymous_write, 0, QUOTA);
    DbgPrint("[pipe] CreatePipe: %d, types %lu %lu\n", ok, GetFileType(anonymous_read),
             GetFileType(anonymous_write));
    WriteFile(anonymous_write, "abc", 3, &done, 0);
    WriteFile(anonymous_write, "defgh", 5, &done, 0);
    ok = PeekNamedPipe(anonymous_read, 0, 0, 0, &available, 0);
    DbgPrint("[pipe] PeekNamedPipe: %d, %lu bytes\n", ok, available);
    ok = ReadFile(anonymous_read, buffer, 6, &done, 0);
    DbgPrint("[pipe] ReadFile of 6 bytes: %d, %s\n", ok, text(buffer, done, shown));
    ok = ReadFile(anonymous_read, buffer, sizeof(buffer), &done, 0);
    DbgPrint("[pipe] ReadFile of the rest: %d, %s\n", ok, text(buffer, done, shown));

    /* 40 bytes for a quota of 16: the writer waits for reads. */
    thread = CreateThread(0, 0, stalled_writer, 0, 0, 0);
    Sleep(200);
    wait = WaitForSingleObject(thread, 0);
    ok = ReadFile(anonymous_read, buffer, 10, &done, 0);
    total += done;
    ok = ReadFile(anonymous_read, buffer, 14, &done, 0);
    total += done;
    done = WaitForSingleObject(thread, 5000);
    DbgPrint("[pipe] the writer past the quota, before reads: wait %lu; after: wait %lu\n", wait, done);
    ok = ReadFile(anonymous_read, buffer, sizeof(buffer), &done, 0);
    total += done;
    DbgPrint("[pipe] read in three: %lu bytes, the last %s\n", total, text(buffer, done, shown));
    CloseHandle(thread);

    /* A read that waits for a write. */
    thread = CreateThread(0, 0, waiting_reader, 0, 0, 0);
    Sleep(200);
    wait = WaitForSingleObject(thread, 0);
    WriteFile(anonymous_write, "late", 4, &done, 0);
    done = WaitForSingleObject(thread, 5000);
    DbgPrint("[pipe] the reader, before the write: wait %lu; after: wait %lu\n", wait, done);
    CloseHandle(thread);

    CloseHandle(anonymous_write);
    ok = ReadFile(anonymous_read, buffer, sizeof(buffer), &done, 0);
    DbgPrint("[pipe] ReadFile once the writer is closed: %d, error %lu\n", ok, GetLastError());
    CloseHandle(anonymous_read);
}

DWORD __stdcall GuiStartup(void)
{
    DbgPrint("[pipe] started\n");
    message_pipe();
    anonymous_pipe();
    DbgPrint("[pipe] done\n");
    ExitProcess(EXIT_STATUS);
    return 0;
}
