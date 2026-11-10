/*
 * The frame-based SEH handler that clang's i386 code calls for
 * __try/__except/__finally (`--target=i686-pc-windows-msvc`), written for
 * Mino's native test programs: ReactOS's ntdll does not export it (it comes
 * with a C runtime, which these programs do not have).
 *
 * Written from the frame layout that clang generates (checked by
 * disassembly), in the scheme that the public descriptions of i386 SEH give:
 * each function with __try blocks registers, at EBP - 0x10, a record
 *
 *     EBP - 0x18   ESP saved after the prologue (reloaded by __except blocks)
 *     EBP - 0x14   EXCEPTION_POINTERS * of the exception being filtered
 *     EBP - 0x10   next record in the FS:[0] chain
 *     EBP - 0x0C   this handler
 *     EBP - 0x08   the function's scope table
 *     EBP - 0x04   the current try level, -1 outside every __try
 *
 * and a scope table of { previous level, filter, handler } per __try, the
 * filter being NULL for a __finally. Filters, __finally blocks and __except
 * blocks are entered with EBP set to the function's frame.
 */

typedef struct EXCEPTION_RECORD {
    unsigned long code;
    unsigned long flags;
    struct EXCEPTION_RECORD *record;
    void *address;
    unsigned long parameters_count;
    unsigned long parameters[15];
} EXCEPTION_RECORD;

typedef struct {
    EXCEPTION_RECORD *record;
    void *context;
} EXCEPTION_POINTERS;

typedef struct {
    long previous;
    void *filter;
    void *handler;
} SCOPE;

typedef struct REGISTRATION {
    struct REGISTRATION *next;
    void *handler;
    const SCOPE *scopes;
    long level;
} REGISTRATION;

/* EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND */
#define UNWINDING 0x6
/* EXCEPTION_DISPOSITION */
#define CONTINUE_EXECUTION 0
#define CONTINUE_SEARCH 1
/* Filter results. */
#define EXECUTE_HANDLER 1
#define NO_LEVEL (-1)

/* The frame of the function that registered `r`. */
#define FRAME(r) ((char *)(r) + 0x10)
#define POINTERS(r) (*(EXCEPTION_POINTERS **)((char *)(r) - 4))

/* Calls `function` (a filter or a __finally block) with EBP = `frame`;
 * returns its EAX. EBX, ESI, EDI and EBP are kept. */
__attribute__((naked)) static long call_with_frame(void *function, void *frame)
{
    __asm__ volatile(
        "pushl %ebp\n\t"
        "pushl %ebx\n\t"
        "pushl %esi\n\t"
        "pushl %edi\n\t"
        "movl 20(%esp), %eax\n\t"
        "movl 24(%esp), %ebp\n\t"
        "calll *%eax\n\t"
        "popl %edi\n\t"
        "popl %esi\n\t"
        "popl %ebx\n\t"
        "popl %ebp\n\t"
        "retl\n\t");
}

/* Enters the __except block `target` with EBP = `frame`; it reloads ESP. */
__attribute__((naked, noreturn)) static void jump_with_frame(void *target, void *frame)
{
    __asm__ volatile(
        "movl 4(%esp), %eax\n\t"
        "movl 8(%esp), %ebp\n\t"
        "jmpl *%eax\n\t");
}

/* RtlUnwind(registration, back here, record, 0): the handlers of the frames
 * above `registration` run their __finally blocks, and those frames leave
 * the chain. RtlUnwind resumes at the return point it is given. */
__attribute__((naked)) static void global_unwind(REGISTRATION *registration, EXCEPTION_RECORD *record)
{
    __asm__ volatile(
        "pushl %ebp\n\t"
        "pushl %ebx\n\t"
        "pushl %esi\n\t"
        "pushl %edi\n\t"
        "pushl $0\n\t"
        "pushl 28(%esp)\n\t"
        "pushl $1f\n\t"
        "pushl 32(%esp)\n\t"
        "calll *__imp__RtlUnwind@16\n"
        "1:\n\t"
        "popl %edi\n\t"
        "popl %esi\n\t"
        "popl %ebx\n\t"
        "popl %ebp\n\t"
        "retl\n\t");
}

/* Runs the __finally blocks of `registration` from its current level down to
 * `stop`, leaving each level before running its block. */
static void local_unwind(REGISTRATION *registration, long stop)
{
    while (registration->level != NO_LEVEL && registration->level != stop) {
        const SCOPE *scope = &registration->scopes[registration->level];
        registration->level = scope->previous;
        if (!scope->filter)
            call_with_frame(scope->handler, FRAME(registration));
    }
}

int _except_handler3(EXCEPTION_RECORD *record, REGISTRATION *registration, void *context, void *dispatcher)
{
    (void)dispatcher;
    if (record->flags & UNWINDING) {
        local_unwind(registration, NO_LEVEL);
        return CONTINUE_SEARCH;
    }
    EXCEPTION_POINTERS pointers = { record, context };
    POINTERS(registration) = &pointers;
    for (long level = registration->level; level != NO_LEVEL; level = registration->scopes[level].previous) {
        const SCOPE *scope = &registration->scopes[level];
        if (!scope->filter)
            continue;
        long verdict = call_with_frame(scope->filter, FRAME(registration));
        if (verdict < 0)
            return CONTINUE_EXECUTION;
        if (verdict > 0) {
            global_unwind(registration, record);
            local_unwind(registration, level);
            registration->level = scope->previous;
            jump_with_frame(scope->handler, FRAME(registration));
        }
    }
    return CONTINUE_SEARCH;
}
