/* kernel/kernel.ld — Linker script for the Mino kernel flat binary.
 *
 * Physical load address: 0x0010_0000 (1 MiB mark).
 * The bootloader allocates pages there and loads kernel.bin verbatim.
 * The flat binary is produced with:  objcopy -O binary kernel kernel.bin
 *
 * kernel_main MUST be at the very first byte of the binary (byte 0 = 0x10_0000).
 * We achieve this by placing kernel_main in ".text.entry" and listing that
 * section first in the .text output group.
 */

ENTRY(kernel_main)

SECTIONS {
    /* Start at 1 MiB — matches KERNEL_PHYS_BASE in the bootloader. */
    . = 0x00100000;

    .text : {
        /* kernel_main is tagged #[link_section = ".text.entry"]; place it first
         * so it sits at physical 0x00100000 = first byte of kernel.bin. */
        KEEP(*(.text.entry))
        *(.text .text.*)
    }

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096) {
        *(.data .data.*)
        /* Rust global statics that have non-zero initializers end up here. */
    }

    .bss : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* objcopy -O binary writes zeros for the BSS range automatically. */

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.note.GNU-stack)
    }
}
