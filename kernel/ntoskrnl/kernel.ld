/* kernel/ntoskrnl/kernel.ld — Linker script for the Mino kernel (ELF64, ADR-014).
 *
 * The kernel is linked in the top 2 GiB of the address space, as
 * `code-model=kernel` expects. The bootloader loads each PT_LOAD segment into
 * one physically contiguous block and maps it at its virtual address with the
 * segment's rights, so the image is W^X:
 *
 *   text    .text                 R X
 *   rodata  .rodata .got          R
 *   data    .data .bss            R W  (no execute)
 *
 * Every output section starts on a page boundary, so no page mixes rights.
 * The __*_start / __*_end symbols let the kernel check those rights at boot.
 */

ENTRY(kernel_main)

KERNEL_VMA = 0xFFFFFFFF80000000;

PHDRS {
    text   PT_LOAD FLAGS(5);   /* R X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* R W */
}

SECTIONS {
    . = KERNEL_VMA;
    __kernel_start = .;

    .text : ALIGN(4096) {
        __text_start = .;
        KEEP(*(.text.entry))
        *(.text .text.*)
        . = ALIGN(4096);
        __text_end = .;
    } :text

    .rodata : ALIGN(4096) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        /* Static linking: GOT entries are final at link time, never written. */
        *(.got .got.*)
        *(.data.rel.ro .data.rel.ro.*)
        . = ALIGN(4096);
        __rodata_end = .;
    } :rodata

    .data : ALIGN(4096) {
        __data_start = .;
        *(.data .data.*)
    } :data

    .bss : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
        . = ALIGN(4096);
        __data_end = .;
    } :data

    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.note.GNU-stack)
    }
}
