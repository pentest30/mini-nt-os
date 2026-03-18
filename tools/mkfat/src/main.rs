//! mkfat — build the FAT32 ramdisk image for micro-nt-os QEMU tests.
//!
//! Outputs a raw FAT32 image containing:
//!   KERNEL.BIN  — 4-byte sentinel "ABCD" for the in-kernel FAT smoke probe
//!   TEST.EXE    — hand-crafted PE32 that exercises all smoke-test syscalls
//!   CMD.EXE     — hand-crafted PE32 that exercises the Win32 message pump
//!   + any extra files supplied on the command line
//!
//! Usage:  mkfat <output.img> [HOST_PATH:FAT_NAME ...]
//!   e.g.: mkfat fat.img /path/to/hello.exe:HELLO.EXE
//!
//! FAT names must be plain 8.3 (no subdirectory path).
//! The tool is invoked by tools/qemu-run.sh before assembling the ESP.

use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let out = args.get(1).cloned().unwrap_or_else(|| "fat.img".to_string());

    let pe32 = build_test_pe32(0x0200_0000, 0x1000);
    let cmd  = build_cmd_pe32(0x0210_0000, 0x1000);

    // Standard files always present.
    let mut files: Vec<([u8; 11], Vec<u8>)> = vec![
        (*b"KERNEL  BIN", b"ABCD".to_vec()),
        (*b"TEST    EXE", pe32),
        (*b"CMD     EXE", cmd),
    ];

    // Extra files from HOST_PATH:FAT_NAME pairs.
    // We split on the LAST ':' so Windows drive letters (C:\...) are handled correctly.
    for arg in args.iter().skip(2) {
        if let Some((host, fat_name)) = arg.rsplit_once(':') {
            match fat_short_name(fat_name) {
                Ok(name) => match fs::read(host) {
                    Ok(data) => files.push((name, data)),
                    Err(e)   => eprintln!("[mkfat] skipping {arg}: {e}"),
                },
                Err(e) => eprintln!("[mkfat] skipping {arg}: bad FAT name: {e}"),
            }
        } else {
            eprintln!("[mkfat] skipping {arg}: expected HOST:FATNAME format");
        }
    }

    let img = build_fat_image(&files);
    fs::write(&out, &img).unwrap_or_else(|e| panic!("mkfat: write {out}: {e}"));

    eprint!("[mkfat] {} bytes → {out} ", img.len());
    for (name, data) in &files {
        eprint!(" {}={}", fat_name_display(name), data.len());
    }
    eprintln!();
}

// ── FAT name helpers ──────────────────────────────────────────────────────────

/// Convert "FOO.BAR" or "FOOBAR" to an 11-byte space-padded FAT 8.3 name.
fn fat_short_name(s: &str) -> Result<[u8; 11], &'static str> {
    let mut out = [b' '; 11];
    let upper = s.to_ascii_uppercase();
    let (base, ext) = if let Some(dot) = upper.rfind('.') {
        (&upper[..dot], Some(&upper[dot + 1..]))
    } else {
        (upper.as_str(), None)
    };
    if base.is_empty() || base.len() > 8 { return Err("base name must be 1–8 chars"); }
    if ext.map_or(false, |e| e.len() > 3) { return Err("extension must be ≤3 chars"); }
    out[..base.len()].copy_from_slice(base.as_bytes());
    if let Some(e) = ext {
        out[8..8 + e.len()].copy_from_slice(e.as_bytes());
    }
    Ok(out)
}

fn fat_name_display(name: &[u8; 11]) -> String {
    let base: String = name[..8].iter().copied().filter(|&b| b != b' ').map(|b| b as char).collect();
    let ext:  String = name[8..].iter().copied().filter(|&b| b != b' ').map(|b| b as char).collect();
    if ext.is_empty() { base } else { format!("{base}.{ext}") }
}

// ── FAT32 image builder ───────────────────────────────────────────────────────
//
// Generic builder: accepts any list of (fat_8.3_name, data) pairs.
//
// Geometry:
//   BytesPerSector   = 512
//   SectorsPerClust  = 1
//   ReservedSectors  = 1   (sector 0 = BPB/boot sector)
//   NumberOfFATs     = 1
//   FAT sectors      = ceil((total_clusters * 4) / 512)   — computed dynamically
//   RootCluster      = 2   (first data cluster = root directory, 1 sector)
//   DataStartLBA     = ReservedSectors + FAT sectors
//
// Cluster → LBA:
//   lba = data_start_lba + (cluster − 2)
//
// Root directory is 1 cluster (= 1 sector = 16 entries max).
// Each file occupies ceil(size / 512) contiguous clusters starting at cluster 3.
//
// FAT32 dir entry layout (32 bytes):
//   [0..11]  Name  [11] Attr  [20..22] FstClusHI  [26..28] FstClusLO  [28..32] FileSize

fn build_fat_image(files: &[([u8; 11], Vec<u8>)]) -> Vec<u8> {
    const SECTOR: usize = 512;

    // ── Compute cluster layout ────────────────────────────────────────────────
    // cluster 0, 1 = reserved in FAT
    // cluster 2    = root directory (1 sector)
    // cluster 3+   = file data, packed sequentially

    let mut next_cluster: u32 = 3;
    let mut first_clusters: Vec<u32> = Vec::with_capacity(files.len());
    let mut cluster_counts: Vec<u32> = Vec::with_capacity(files.len());

    for (_, data) in files {
        let n = ((data.len() + SECTOR - 1) / SECTOR).max(1) as u32;
        first_clusters.push(next_cluster);
        cluster_counts.push(n);
        next_cluster += n;
    }

    // Total FAT entries needed: 0..next_cluster
    let fat_sectors = ((next_cluster as usize * 4) + SECTOR - 1) / SECTOR;
    let fat_sectors = fat_sectors.max(1) as u32;

    let reserved_sectors: u32 = 1;
    let data_start_lba = reserved_sectors + fat_sectors;
    // root dir at cluster 2 → lba = data_start_lba + (2 − 2) = data_start_lba
    let total_sectors = data_start_lba + (next_cluster - 2); // data clusters

    let mut img = vec![0u8; total_sectors as usize * SECTOR];

    // ── Sector 0: BPB ────────────────────────────────────────────────────────
    {
        let b = &mut img[..SECTOR];
        b[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes()); // BytesPerSector
        b[13] = 1;                                                   // SectorsPerCluster
        b[14..16].copy_from_slice(&(reserved_sectors as u16).to_le_bytes()); // ReservedSectors
        b[16] = 1;                                                   // NumberOfFATs
        // RootEntryCount=0, TotalSectors16=0 → FAT32 variant
        b[32..36].copy_from_slice(&total_sectors.to_le_bytes());     // TotalSectors32
        b[36..40].copy_from_slice(&fat_sectors.to_le_bytes());       // FATsize32
        b[44..48].copy_from_slice(&2u32.to_le_bytes());              // RootCluster
    }

    // ── FAT (reserved_sectors .. reserved_sectors + fat_sectors) ─────────────
    {
        let fat_off = reserved_sectors as usize * SECTOR;
        let f = &mut img[fat_off..fat_off + fat_sectors as usize * SECTOR];

        f[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes()); // entry 0: media descriptor
        f[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // entry 1: reserved
        f[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // entry 2: root dir EOF

        for i in 0..files.len() {
            let first = first_clusters[i];
            let count = cluster_counts[i];
            // Link all but the last cluster to the next.
            for c in first..first + count - 1 {
                let off = (c as usize) * 4;
                f[off..off + 4].copy_from_slice(&(c + 1).to_le_bytes());
            }
            // Mark last cluster as EOF.
            let last_off = ((first + count - 1) as usize) * 4;
            f[last_off..last_off + 4].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        }
    }

    // ── Root directory cluster (cluster 2 → lba = data_start_lba) ────────────
    {
        let root_lba = data_start_lba as usize;
        let d = &mut img[root_lba * SECTOR..(root_lba + 1) * SECTOR];

        for (i, (name, data)) in files.iter().enumerate() {
            let off = i * 32;
            if off + 32 > d.len() {
                eprintln!("[mkfat] warning: root dir full (max 16 entries); truncating");
                break;
            }
            let fc = first_clusters[i];
            d[off..off + 11].copy_from_slice(name);
            d[off + 11] = 0x20; // archive attribute
            d[off + 20..off + 22].copy_from_slice(&((fc >> 16) as u16).to_le_bytes()); // FstClusHI
            d[off + 26..off + 28].copy_from_slice(&(fc as u16).to_le_bytes());         // FstClusLO
            d[off + 28..off + 32].copy_from_slice(&(data.len() as u32).to_le_bytes()); // FileSize
        }
    }

    // ── File data ─────────────────────────────────────────────────────────────
    // lba(cluster) = data_start_lba + (cluster − 2)
    for (i, (_, data)) in files.iter().enumerate() {
        let lba = data_start_lba + (first_clusters[i] - 2);
        let start = lba as usize * SECTOR;
        img[start..start + data.len()].copy_from_slice(data);
    }

    img
}

// ── PE32 builder ──────────────────────────────────────────────────────────────
//
// Generates the same binary as kernel/src/main.rs::build_test_pe32.
// Preferred base: 0x0200_0000  Entry RVA: 0x1000
//
// The ring-3 code exercises the full syscall path:
//   NtWriteFile  (0x0112) → "[smoke] int2e write path hit"
//   NtCreateProcess (0x001B) → "[smoke] NtCreateProcess ok"
//   NtCreateThread  (0x0035) → "[smoke] NtCreateThread ok"
//   NtWriteFile via IAT      → "[smoke] IAT NtWriteFile path hit"
//   NtAllocateVirtualMemory (0x0011)
//   NtTerminateProcess (0x00C2) then JMP$

fn build_test_pe32(image_base: u32, entry_rva: u32) -> Vec<u8> {
    use pe32::*;

    let mut buf = vec![0u8; 0x3000];

    // ── DOS header ────────────────────────────────────────────────────────────
    buf[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
    let nt_off: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&nt_off.to_le_bytes());

    // ── NT signature ──────────────────────────────────────────────────────────
    buf[0x40..0x44].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

    let fh_off  = 0x44usize;
    let opt_sz  = std::mem::size_of::<ImageOptionalHeader32>() as u16;
    let nsec: u16 = 2;

    // ── FILE_HEADER ───────────────────────────────────────────────────────────
    buf[fh_off..fh_off + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
    buf[fh_off + 2..fh_off + 4].copy_from_slice(&nsec.to_le_bytes());
    buf[fh_off + 16..fh_off + 18].copy_from_slice(&opt_sz.to_le_bytes());

    // ── OPTIONAL_HEADER32 ─────────────────────────────────────────────────────
    let opt_off = fh_off + std::mem::size_of::<ImageFileHeader>();
    buf[opt_off..opt_off + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
    buf[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
    let size_of_image: u32 = 0x3000;
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());
    let size_of_headers: u32 = 0x400;
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&size_of_headers.to_le_bytes());
    let n_dirs: u32 = 16;
    buf[opt_off + 92..opt_off + 96].copy_from_slice(&n_dirs.to_le_bytes());

    // ── Section headers (.text, .data) ───────────────────────────────────────
    let sh_off   = opt_off + opt_sz as usize;
    let text_rva: u32 = 0x1000;
    let text_raw: u32 = 0x600;
    let text_off = size_of_headers as usize;
    buf[sh_off..sh_off + 5].copy_from_slice(b".text");
    buf[sh_off + 8..sh_off + 12].copy_from_slice(&text_raw.to_le_bytes());
    buf[sh_off + 12..sh_off + 16].copy_from_slice(&text_rva.to_le_bytes());
    buf[sh_off + 16..sh_off + 20].copy_from_slice(&text_raw.to_le_bytes());
    buf[sh_off + 20..sh_off + 24].copy_from_slice(&size_of_headers.to_le_bytes());
    let text_chars: u32 = SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_CNT_CODE;
    buf[sh_off + 36..sh_off + 40].copy_from_slice(&text_chars.to_le_bytes());

    let sh2      = sh_off + 40;
    let data_rva: u32 = 0x2000;
    let data_raw: u32 = 0x600;
    let data_off = (size_of_headers + text_raw) as usize;
    buf[sh2..sh2 + 5].copy_from_slice(b".data");
    buf[sh2 + 8..sh2 + 12].copy_from_slice(&data_raw.to_le_bytes());
    buf[sh2 + 12..sh2 + 16].copy_from_slice(&data_rva.to_le_bytes());
    buf[sh2 + 16..sh2 + 20].copy_from_slice(&data_raw.to_le_bytes());
    buf[sh2 + 20..sh2 + 24].copy_from_slice(&(size_of_headers + text_raw).to_le_bytes());
    let data_chars: u32 = SCN_MEM_READ | SCN_MEM_WRITE | SCN_CNT_INITIALIZED_DATA;
    buf[sh2 + 36..sh2 + 40].copy_from_slice(&data_chars.to_le_bytes());

    // ── Compute key virtual addresses ─────────────────────────────────────────
    let args_write_va       = image_base.wrapping_add(data_rva + 0x00);
    let args_alloc_va       = image_base.wrapping_add(data_rva + 0x20);
    let iat_iosb_va         = image_base.wrapping_add(data_rva + 0x130);
    let iat_msg_va          = image_base.wrapping_add(data_rva + 0x138);
    let args_iat_proof_va   = image_base.wrapping_add(data_rva + 0x148);
    let iat_proof_msg_va    = image_base.wrapping_add(data_rva + 0x160);
    let import_desc_rva: u32 = data_rva + 0x1A0;
    let import_int_rva:  u32 = data_rva + 0x1C0;
    let import_iat_rva:  u32 = data_rva + 0x1D0;
    let import_ibn_rva:  u32 = data_rva + 0x1E0;
    let import_dll_rva:  u32 = data_rva + 0x1F0;
    let import_iat_va        = image_base.wrapping_add(import_iat_rva);
    let sysenter_iosb_va     = image_base.wrapping_add(data_rva + 0xD0);
    let sysenter_msg_va      = image_base.wrapping_add(data_rva + 0xD8);
    let args_create_proc_va  = image_base.wrapping_add(data_rva + 0x80);
    let out_proc_handle_va   = image_base.wrapping_add(data_rva + 0x90);
    let args_create_thread_va= image_base.wrapping_add(data_rva + 0xA0);
    let out_thread_handle_va = image_base.wrapping_add(data_rva + 0xB8);
    let out_client_id_va     = image_base.wrapping_add(data_rva + 0xC0);
    let out_base_va          = image_base.wrapping_add(data_rva + 0x40);
    let out_size_va          = image_base.wrapping_add(data_rva + 0x44);
    let args_term_va         = image_base.wrapping_add(data_rva + 0x48);
    let msg_va               = image_base.wrapping_add(data_rva + 0x60);

    // ── Win32 test VAs (data_rva + 0x200 onward, after the import table) ─────
    let wc_ptr_va      = image_base.wrapping_add(data_rva + 0x200); // WNDCLASSA (40 bytes)
    let class_name_va  = image_base.wrapping_add(data_rva + 0x228); // "TestWnd\0" (8 bytes)
    let w32_msg_va     = image_base.wrapping_add(data_rva + 0x230); // MSG struct (28 bytes)
    let args_rc_va     = image_base.wrapping_add(data_rva + 0x24C); // RegisterClassA args (4 bytes)
    let args_cw_va     = image_base.wrapping_add(data_rva + 0x250); // CreateWindowExA args (48 bytes)
    let args_gm_va     = image_base.wrapping_add(data_rva + 0x280); // GetMessageA args (16 bytes)
    let wp_marker_va   = image_base.wrapping_add(data_rva + 0x298); // "[smoke] WndProc called\n"
    let wp_iosb_va     = image_base.wrapping_add(data_rva + 0x2B0); // WndProc IOSB (8 bytes)
    let args_wp_va     = image_base.wrapping_add(data_rva + 0x2B8); // NtWriteFile args for WndProc

    let msg           = b"[smoke] int2e write+alloc+term\n";
    let iat_msg       = b"[iat] NtWriteFile via IAT\n";
    let iat_proof_msg = b"IATOK";
    let sysenter_msg  = b"[smoke] SYSENTER path hit\n";
    let wp_marker     = b"[smoke] WndProc called\n";

    // ── Ring-3 machine code (.text section) ──────────────────────────────────
    let mut code = Vec::<u8>::new();

    // Set DS/ES to user data selector (0x23)
    code.extend_from_slice(&[0x66, 0xB8, 0x23, 0x00]); // MOV AX, 0x23
    code.extend_from_slice(&[0x8E, 0xD8]);              // MOV DS, AX
    code.extend_from_slice(&[0x8E, 0xC0]);              // MOV ES, AX

    // NtWriteFile (0x112) with args_write_va
    code.push(0xBA); eu32(&mut code, args_write_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]); // MOV EAX, 0x112
    code.extend_from_slice(&[0xCD, 0x2E]);              // INT 0x2E

    // Win32 draw demo frame (0x2050) — user-mode initiated framebuffer output
    code.push(0xBA); eu32(&mut code, 0);
    code.extend_from_slice(&[0xB8, 0x50, 0x20, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);

    // NtCreateProcess (0x001B)
    code.push(0xBA); eu32(&mut code, args_create_proc_va);
    code.extend_from_slice(&[0xB8, 0x1B, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);

    // Copy process handle to thread args
    code.extend_from_slice(&[0xA1]); eu32(&mut code, out_proc_handle_va);
    code.extend_from_slice(&[0xA3]); eu32(&mut code, args_create_thread_va + 12);

    // NtCreateThread (0x0035)
    code.push(0xBA); eu32(&mut code, args_create_thread_va);
    code.extend_from_slice(&[0xB8, 0x35, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);

    // Call NtWriteFile via IAT (CALL DWORD PTR [import_iat_va])
    epush(&mut code, 0);
    epush(&mut code, 0);
    epush(&mut code, iat_msg.len() as u32);
    epush(&mut code, iat_msg_va);
    epush(&mut code, iat_iosb_va);
    epush(&mut code, 0);
    epush(&mut code, 0);
    epush(&mut code, 0);
    epush(&mut code, 0);
    code.extend_from_slice(&[0xFF, 0x15]); eu32(&mut code, import_iat_va);

    // NtWriteFile (0x112) with args_iat_proof_va — writes "IATOK"
    code.push(0xBA); eu32(&mut code, args_iat_proof_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);

    // NtAllocateVirtualMemory (0x0011) with args_alloc_va
    code.push(0xBA); eu32(&mut code, args_alloc_va);
    code.extend_from_slice(&[0xB8, 0x11, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);

    // Write 4 bytes to allocated page (sanity write)
    code.extend_from_slice(&[0x8B, 0x1D]); eu32(&mut code, out_base_va);
    code.extend_from_slice(&[0xC7, 0x03]); eu32(&mut code, 0x1234_5678);

    // NtWriteFile via SYSENTER (XP SP2 ABI).
    // Stack layout at SYSENTER: [EDX+0]=ret_addr [EDX+4..]=args[0..8].
    // Push in reverse: Key → ... → FileHandle → ret_addr (topmost).
    code.extend_from_slice(&[0x6A, 0x00]);              // push 0  (Key)
    code.extend_from_slice(&[0x6A, 0x00]);              // push 0  (ByteOffset)
    epush(&mut code, sysenter_msg.len() as u32);        // push Length
    epush(&mut code, sysenter_msg_va);                  // push Buffer
    epush(&mut code, sysenter_iosb_va);                 // push IoStatusBlock
    code.extend_from_slice(&[0x6A, 0x00]);              // push 0  (ApcContext)
    code.extend_from_slice(&[0x6A, 0x00]);              // push 0  (ApcRoutine)
    code.extend_from_slice(&[0x6A, 0x00]);              // push 0  (Event)
    code.extend_from_slice(&[0x6A, 0xFF]);              // push -1 (FileHandle = serial)
    // call/pop trick: get VA of the pop-eax instruction, add delta → .after_sysenter.
    // delta = 1(pop) + 5(add) + 1(push) + 2(mov edx,esp) + 5(mov eax,imm) + 2(sysenter) = 16
    code.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call .se_eip
    code.push(0x58);                                    // pop eax  (.se_eip)
    code.extend_from_slice(&[0x05, 16, 0, 0, 0]);      // add eax, 16
    code.push(0x50);                                    // push eax (ret addr)
    code.extend_from_slice(&[0x89, 0xE2]);              // mov edx, esp
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]); // mov eax, 0x112
    code.extend_from_slice(&[0x0F, 0x34]);              // sysenter
    // .after_sysenter: ret at SharedUserData+0x300 popped ret_addr; 9 args remain.
    code.extend_from_slice(&[0x83, 0xC4, 0x24]);        // add esp, 36

    // Win32 draw demo frame (0x2050) — user-mode initiated framebuffer output
    code.push(0xBA); eu32(&mut code, 0);
    code.extend_from_slice(&[0xB8, 0x50, 0x20, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);

    // ── Win32 message pump test ───────────────────────────────────────────────
    //
    // Must run BEFORE NtTerminateProcess because that syscall actually terminates
    // the current thread — execution never returns to user mode after it.
    //
    // 1. RegisterClassA(wc_ptr_va) → EAX = atom
    // 2. Store atom into CreateWindowExA args[1] (lpClassName) at runtime
    // 3. CreateWindowExA → EAX = hwnd; kernel pushes WM_CREATE to the queue
    // 4. Message loop:
    //    a. GetMessageA → EAX=0 (WM_QUIT) exits loop, EAX≠0 continues
    //    b. DispatchMessageA via user32 stub (0x7100_1030):
    //       stub calls WIN32_LOOKUP_WNDPROC (0x2019) → gets wndproc VA
    //       then CALLs wndproc(hwnd, msg, wparam, lparam) in ring-3
    //    c. PostQuitMessage(0) → next GetMessage returns WM_QUIT (loop ends)

    // RegisterClassA via direct INT 0x2E (kernel stores class→wndproc mapping)
    code.push(0xBA); eu32(&mut code, args_rc_va);
    code.extend_from_slice(&[0xB8, 0x17, 0x20, 0x00, 0x00]); // MOV EAX, 0x2017
    code.extend_from_slice(&[0xCD, 0x2E]);
    // EAX = atom; store to CreateWindowExA args[1] (lpClassName)
    // A3 imm32 = MOV [abs32], EAX (32-bit mode)
    code.push(0xA3); eu32(&mut code, args_cw_va.wrapping_add(4));

    // CreateWindowExA via INT 0x2E → EAX = hwnd; WM_CREATE queued by kernel
    code.push(0xBA); eu32(&mut code, args_cw_va);
    code.extend_from_slice(&[0xB8, 0x10, 0x20, 0x00, 0x00]); // MOV EAX, 0x2010
    code.extend_from_slice(&[0xCD, 0x2E]);

    // msg_loop:
    let msg_loop_off = code.len();
    // GetMessageA(w32_msg_va, 0, 0, 0) via INT 0x2E
    code.push(0xBA); eu32(&mut code, args_gm_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x20, 0x00, 0x00]); // MOV EAX, 0x2012
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0x85, 0xC0]); // TEST EAX, EAX
    code.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]); let j_msg_done = code.len() - 4; // JZ rel32

    // DispatchMessageA via user32 stub (ring-3 WndProc dispatch)
    // user32 base = 0x7100_0000, DispatchMessageA stub at 0x7100_1030
    epush(&mut code, w32_msg_va);                                    // PUSH lpMsg
    code.extend_from_slice(&[0xB8, 0x30, 0x10, 0x00, 0x71]);        // MOV EAX, 0x7100_1030
    code.extend_from_slice(&[0xFF, 0xD0]);                           // CALL EAX (stub RET 4 cleans lpMsg)

    // PostQuitMessage(0) via user32 stub at 0x7100_1060
    code.extend_from_slice(&[0x6A, 0x00]);                           // PUSH 0 (exit code)
    code.extend_from_slice(&[0xB8, 0x60, 0x10, 0x00, 0x71]);        // MOV EAX, 0x7100_1060
    code.extend_from_slice(&[0xFF, 0xD0]);                           // CALL EAX (stub RET 4)

    // JMP back to msg_loop (EB rel8)
    // Displacement = msg_loop_off - (code.len() + 2);  must fit in i8.
    {
        let disp = msg_loop_off.wrapping_sub(code.len() + 2) as u8;
        code.extend_from_slice(&[0xEB, disp]);
    }

    // msg_done: (patch JZ above)
    let msg_done_off = code.len();
    patch_rel32(&mut code, j_msg_done, msg_done_off);

    // NtTerminateProcess (0x00C2) — terminates thread after Win32 pump completes
    code.push(0xBA); eu32(&mut code, args_term_va);
    code.extend_from_slice(&[0xB8, 0xC2, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);

    // ── Final JMP $ (safety in case NtTerminateProcess returns) ─────────────
    code.extend_from_slice(&[0xEB, 0xFE]); // JMP $

    // ── WndProc body (17 bytes) ──────────────────────────────────────────────
    // stdcall: (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) → LRESULT
    // Only reachable via CALL from DispatchMessageA stub (0x7100_1030).
    // Action: write "[smoke] WndProc called\n" to serial via NtWriteFile.
    let wndproc_off = code.len(); // record for patching WNDCLASSA.lpfnWndProc
    code.push(0xBA); eu32(&mut code, args_wp_va);                    // MOV EDX, args_wp_va (5 bytes)
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);        // MOV EAX, 0x112    (5 bytes)
    code.extend_from_slice(&[0xCD, 0x2E]);                           // INT 0x2E          (2 bytes)
    code.extend_from_slice(&[0x33, 0xC0]);                           // XOR EAX, EAX      (2 bytes)
    code.extend_from_slice(&[0xC2, 0x10, 0x00]);                     // RET 16            (3 bytes)
    // Total WndProc = 5+5+2+2+3 = 17 bytes ✓

    let code_end = text_off + code.len();
    assert!(code.len() <= text_raw as usize,
        "Win32 test: code too large ({} > {})", code.len(), text_raw);
    buf[text_off..code_end].copy_from_slice(&code);

    // Patch WndProc VA into WNDCLASSA.lpfnWndProc (+4)
    let wndproc_va = image_base.wrapping_add(text_rva).wrapping_add(wndproc_off as u32);
    let wc_off = data_off + 0x200;
    buf[wc_off + 4..wc_off + 8].copy_from_slice(&wndproc_va.to_le_bytes());

    // ── Data section ─────────────────────────────────────────────────────────
    let args_write_off       = data_off;
    let args_alloc_off       = data_off + 0x20;
    let iat_iosb_off         = data_off + 0x130;
    let iat_msg_off          = data_off + 0x138;
    let args_iat_proof_off   = data_off + 0x148;
    let iat_proof_msg_off    = data_off + 0x160;
    let import_desc_off      = data_off + 0x1A0;
    let import_int_off       = data_off + 0x1C0;
    let import_iat_off       = data_off + 0x1D0;
    let import_ibn_off       = data_off + 0x1E0;
    let import_dll_off       = data_off + 0x1F0;
    let sysenter_iosb_off    = data_off + 0xD0;
    let sysenter_msg_off     = data_off + 0xD8;
    let args_create_proc_off = data_off + 0x80;
    let out_proc_handle_off  = data_off + 0x90;
    let args_create_thread_off = data_off + 0xA0;
    let out_thread_handle_off= data_off + 0xB8;
    let out_client_id_off    = data_off + 0xC0;
    let out_base_off         = data_off + 0x40;
    let out_size_off         = data_off + 0x44;
    let args_term_off        = data_off + 0x48;
    let msg_off              = data_off + 0x60;

    // NtWriteFile args: buf_ptr=msg_va, len=msg.len()
    buf[args_write_off + 16..args_write_off + 20].copy_from_slice(&0u32.to_le_bytes());
    buf[args_write_off + 20..args_write_off + 24].copy_from_slice(&msg_va.to_le_bytes());
    buf[args_write_off + 24..args_write_off + 28].copy_from_slice(&(msg.len() as u32).to_le_bytes());

    // IAT proof write ("IATOK")
    buf[args_iat_proof_off + 16..args_iat_proof_off + 20].copy_from_slice(&0u32.to_le_bytes());
    buf[args_iat_proof_off + 20..args_iat_proof_off + 24].copy_from_slice(&iat_proof_msg_va.to_le_bytes());
    buf[args_iat_proof_off + 24..args_iat_proof_off + 28].copy_from_slice(&(iat_proof_msg.len() as u32).to_le_bytes());

    // Import descriptor directory entry
    buf[opt_off + 104..opt_off + 108].copy_from_slice(&import_desc_rva.to_le_bytes());
    buf[opt_off + 108..opt_off + 112].copy_from_slice(&40u32.to_le_bytes());

    // Import descriptor: ntdll.dll, NtWriteFile
    buf[import_desc_off..import_desc_off + 4].copy_from_slice(&import_int_rva.to_le_bytes());
    buf[import_desc_off + 12..import_desc_off + 16].copy_from_slice(&import_dll_rva.to_le_bytes());
    buf[import_desc_off + 16..import_desc_off + 20].copy_from_slice(&import_iat_rva.to_le_bytes());
    buf[import_int_off..import_int_off + 4].copy_from_slice(&import_ibn_rva.to_le_bytes());
    buf[import_iat_off..import_iat_off + 4].copy_from_slice(&0x1000_1000u32.to_le_bytes());
    buf[import_ibn_off..import_ibn_off + 2].copy_from_slice(&0u16.to_le_bytes()); // hint
    buf[import_ibn_off + 2..import_ibn_off + 14].copy_from_slice(b"NtWriteFile\0");
    buf[import_dll_off..import_dll_off + 10].copy_from_slice(b"ntdll.dll\0");

    // NtAllocateVirtualMemory args
    buf[args_alloc_off + 4..args_alloc_off + 8].copy_from_slice(&out_base_va.to_le_bytes());
    buf[args_alloc_off + 8..args_alloc_off + 12].copy_from_slice(&0u32.to_le_bytes());
    buf[args_alloc_off + 12..args_alloc_off + 16].copy_from_slice(&out_size_va.to_le_bytes());
    buf[args_alloc_off + 16..args_alloc_off + 20].copy_from_slice(&0x3000u32.to_le_bytes());
    buf[args_alloc_off + 20..args_alloc_off + 24].copy_from_slice(&0x4u32.to_le_bytes());

    // NtCreateProcess args
    buf[args_create_proc_off..args_create_proc_off + 4].copy_from_slice(&out_proc_handle_va.to_le_bytes());
    buf[out_proc_handle_off..out_proc_handle_off + 4].copy_from_slice(&0u32.to_le_bytes());

    // NtCreateThread args
    buf[args_create_thread_off..args_create_thread_off + 4].copy_from_slice(&out_thread_handle_va.to_le_bytes());
    buf[args_create_thread_off + 12..args_create_thread_off + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf[args_create_thread_off + 16..args_create_thread_off + 20].copy_from_slice(&out_client_id_va.to_le_bytes());
    buf[out_thread_handle_off..out_thread_handle_off + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[out_client_id_off..out_client_id_off + 8].copy_from_slice(&0u64.to_le_bytes());

    // IAT call args
    buf[iat_iosb_off..iat_iosb_off + 8].copy_from_slice(&0u64.to_le_bytes());
    buf[iat_msg_off..iat_msg_off + iat_msg.len()].copy_from_slice(iat_msg);
    buf[iat_proof_msg_off..iat_proof_msg_off + iat_proof_msg.len()].copy_from_slice(iat_proof_msg);

    // NtTerminateProcess args
    buf[out_base_off..out_base_off + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[out_size_off..out_size_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[args_term_off + 4..args_term_off + 8].copy_from_slice(&0u32.to_le_bytes());

    // Payload text
    buf[msg_off..msg_off + msg.len()].copy_from_slice(msg);

    // SYSENTER data (iosb zeroed by vec!, msg copied)
    buf[sysenter_iosb_off..sysenter_iosb_off + 8].copy_from_slice(&0u64.to_le_bytes());
    buf[sysenter_msg_off..sysenter_msg_off + sysenter_msg.len()].copy_from_slice(sysenter_msg);

    // ── Win32 test data (offsets 0x200..0x2DC within .data section) ──────────
    let wc_off         = data_off + 0x200; // WNDCLASSA (40 bytes); lpfnWndProc patched above
    let cls_name_off   = data_off + 0x228; // "TestWnd\0"
    let w32_msg_off    = data_off + 0x230; // MSG struct (28 bytes, zeroed)
    let args_rc_off    = data_off + 0x24C; // RegisterClassA args (4 bytes)
    let args_cw_off    = data_off + 0x250; // CreateWindowExA args (48 bytes)
    let args_gm_off    = data_off + 0x280; // GetMessageA args (16 bytes)
    let wp_marker_off  = data_off + 0x298; // "[smoke] WndProc called\n"
    let wp_iosb_off    = data_off + 0x2B0; // WndProc NtWriteFile IOSB (8 bytes)
    let args_wp_off    = data_off + 0x2B8; // WndProc NtWriteFile args (36 bytes)

    // WNDCLASSA: lpszClassName = class_name_va (+36)
    buf[wc_off + 36..wc_off + 40].copy_from_slice(&class_name_va.to_le_bytes());
    // (lpfnWndProc at +4 was already patched into buf above)

    // Class name string
    buf[cls_name_off..cls_name_off + 8].copy_from_slice(b"TestWnd\0");

    // MSG struct — zeroed by vec!, nothing to write

    // RegisterClassA args: [0] = ptr to WNDCLASSA
    buf[args_rc_off..args_rc_off + 4].copy_from_slice(&wc_ptr_va.to_le_bytes());

    // CreateWindowExA args (12 × 4 = 48 bytes):
    // [0] dwExStyle = 0, [1] lpClassName = atom (runtime-patched by ring-3 code),
    // [2..11] all zero (NULL strings, no style, no pos/size, no parent, etc.)

    // GetMessageA args (4 × 4 = 16 bytes):
    // [0] lpMsg = w32_msg_va, [1..3] = 0 (hWnd=0 → all windows, no filter)
    buf[args_gm_off..args_gm_off + 4].copy_from_slice(&w32_msg_va.to_le_bytes());

    // WndProc marker string
    buf[wp_marker_off..wp_marker_off + wp_marker.len()].copy_from_slice(wp_marker);

    // WndProc IOSB — zeroed

    // WndProc NtWriteFile args (9 × 4 = 36 bytes):
    // [0] FileHandle=0, [4] IoStatusBlock=wp_iosb_va, [5] Buffer=wp_marker_va, [6] Length
    buf[args_wp_off + 16..args_wp_off + 20].copy_from_slice(&wp_iosb_va.to_le_bytes());
    buf[args_wp_off + 20..args_wp_off + 24].copy_from_slice(&wp_marker_va.to_le_bytes());
    buf[args_wp_off + 24..args_wp_off + 28].copy_from_slice(&(wp_marker.len() as u32).to_le_bytes());

    let _ = w32_msg_off; // used via w32_msg_va in code

    buf
}

fn build_cmd_pe32(image_base: u32, entry_rva: u32) -> Vec<u8> {
    use pe32::*;

    let mut buf = vec![0u8; 0x3000];
    buf[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
    let nt_off: u32 = 0x40;
    buf[0x3C..0x40].copy_from_slice(&nt_off.to_le_bytes());
    buf[0x40..0x44].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

    let fh_off  = 0x44usize;
    let opt_sz  = std::mem::size_of::<ImageOptionalHeader32>() as u16;
    let nsec: u16 = 2;
    buf[fh_off..fh_off + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
    buf[fh_off + 2..fh_off + 4].copy_from_slice(&nsec.to_le_bytes());
    buf[fh_off + 16..fh_off + 18].copy_from_slice(&opt_sz.to_le_bytes());

    let opt_off = fh_off + std::mem::size_of::<ImageFileHeader>();
    buf[opt_off..opt_off + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&entry_rva.to_le_bytes());
    buf[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
    let size_of_image: u32 = 0x3000;
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());
    let size_of_headers: u32 = 0x400;
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&size_of_headers.to_le_bytes());
    let n_dirs: u32 = 16;
    buf[opt_off + 92..opt_off + 96].copy_from_slice(&n_dirs.to_le_bytes());

    let sh_off   = opt_off + opt_sz as usize;
    let text_rva: u32 = 0x1000;
    let text_raw: u32 = 0x600;
    let text_off = size_of_headers as usize;
    buf[sh_off..sh_off + 5].copy_from_slice(b".text");
    buf[sh_off + 8..sh_off + 12].copy_from_slice(&text_raw.to_le_bytes());
    buf[sh_off + 12..sh_off + 16].copy_from_slice(&text_rva.to_le_bytes());
    buf[sh_off + 16..sh_off + 20].copy_from_slice(&text_raw.to_le_bytes());
    buf[sh_off + 20..sh_off + 24].copy_from_slice(&size_of_headers.to_le_bytes());
    let text_chars: u32 = SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_CNT_CODE;
    buf[sh_off + 36..sh_off + 40].copy_from_slice(&text_chars.to_le_bytes());

    let sh2      = sh_off + 40;
    let data_rva: u32 = 0x2000;
    let data_raw: u32 = 0x600;
    let data_off = (size_of_headers + text_raw) as usize;
    buf[sh2..sh2 + 5].copy_from_slice(b".data");
    buf[sh2 + 8..sh2 + 12].copy_from_slice(&data_raw.to_le_bytes());
    buf[sh2 + 12..sh2 + 16].copy_from_slice(&data_rva.to_le_bytes());
    buf[sh2 + 16..sh2 + 20].copy_from_slice(&data_raw.to_le_bytes());
    buf[sh2 + 20..sh2 + 24].copy_from_slice(&(size_of_headers + text_raw).to_le_bytes());
    let data_chars: u32 = SCN_MEM_READ | SCN_MEM_WRITE | SCN_CNT_INITIALIZED_DATA;
    buf[sh2 + 36..sh2 + 40].copy_from_slice(&data_chars.to_le_bytes());

    let args_write_prompt_va = image_base.wrapping_add(data_rva + 0x00);
    let args_write_help_va = image_base.wrapping_add(data_rva + 0x30);
    let args_write_unknown_va = image_base.wrapping_add(data_rva + 0x60);
    let args_read_va = image_base.wrapping_add(data_rva + 0x90);
    let read_iosb_va = image_base.wrapping_add(data_rva + 0xC0);
    let input_buf_va = image_base.wrapping_add(data_rva + 0xC8);
    let args_list_va = image_base.wrapping_add(data_rva + 0x120);
    let list_written_va = image_base.wrapping_add(data_rva + 0x130);
    let dir_out_va = image_base.wrapping_add(data_rva + 0x138);
    let args_write_dir_va = image_base.wrapping_add(data_rva + 0x240);
    let args_write_runok_va = image_base.wrapping_add(data_rva + 0x270);
    let args_write_runfail_va = image_base.wrapping_add(data_rva + 0x280);
    let args_cat_va = image_base.wrapping_add(data_rva + 0x290);
    let args_create_proc_va = image_base.wrapping_add(data_rva + 0x2A0);
    let out_proc_handle_va = image_base.wrapping_add(data_rva + 0x2B0);
    let args_create_thread_va = image_base.wrapping_add(data_rva + 0x2C0);
    let out_thread_handle_va = image_base.wrapping_add(data_rva + 0x2D8);
    let out_client_id_va = image_base.wrapping_add(data_rva + 0x2E0);
    let args_term_va = image_base.wrapping_add(data_rva + 0x2F0);
    let args_write_usage_run_va = image_base.wrapping_add(data_rva + 0x480);
    let args_write_usage_cat_va = image_base.wrapping_add(data_rva + 0x4A0);
    let path_root_va = image_base.wrapping_add(data_rva + 0x300);
    let prompt_va = image_base.wrapping_add(data_rva + 0x308);
    let help_va = image_base.wrapping_add(data_rva + 0x320);
    let unknown_va = image_base.wrapping_add(data_rva + 0x3A0);
    let runok_va = image_base.wrapping_add(data_rva + 0x3C0);
    let exec_path_va = image_base.wrapping_add(data_rva + 0x3D0);
    let runfail_va = image_base.wrapping_add(data_rva + 0x3E0);
    let usage_run_va = image_base.wrapping_add(data_rva + 0x4C0);
    let usage_cat_va = image_base.wrapping_add(data_rva + 0x4D8);

    let prompt = b"[smoke] cmd> ";
    let help = b"help dir cat run exit\n";
    let unknown = b"unknown\n";
    let runok = b"run ok\n";
    let runfail = b"run fail\n";
    let usage_run = b"usage: run <file>\n";
    let usage_cat = b"usage: cat <file>\n";

    let mut code = Vec::<u8>::new();
    code.extend_from_slice(&[0x66, 0xB8, 0x23, 0x00]);
    code.extend_from_slice(&[0x8E, 0xD8]);
    code.extend_from_slice(&[0x8E, 0xC0]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_boot_run = code.len() - 4;

    let loop_off = code.len();
    code.push(0xBA); eu32(&mut code, args_write_prompt_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.push(0xBA); eu32(&mut code, args_read_va);
    code.extend_from_slice(&[0xB8, 0xB7, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xA1]); eu32(&mut code, input_buf_va);
    code.extend_from_slice(&[0x3D]); eu32(&mut code, 0x706C_6568);
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); let j_help_nomatch = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 4);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_help_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_help_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_help_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_help_s = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_help_bad = code.len() - 4;

    let dir_check_off = code.len();
    code.push(0xA0); eu32(&mut code, input_buf_va);
    code.extend_from_slice(&[0x3C, b'd', 0x0F, 0x85, 0, 0, 0, 0]); let j_dir_nomatch = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 1);
    code.extend_from_slice(&[0x3C, b'i', 0x0F, 0x85, 0, 0, 0, 0]); let j_dir_nomatch2 = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 2);
    code.extend_from_slice(&[0x3C, b'r', 0x0F, 0x85, 0, 0, 0, 0]); let j_dir_nomatch3 = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 3);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_dir_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_dir_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_dir_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_dir_s = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_dir_bad = code.len() - 4;

    let cat_check_off = code.len();
    code.push(0xA0); eu32(&mut code, input_buf_va);
    code.extend_from_slice(&[0x3C, b'c', 0x0F, 0x85, 0, 0, 0, 0]); let j_cat_nomatch = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 1);
    code.extend_from_slice(&[0x3C, b'a', 0x0F, 0x85, 0, 0, 0, 0]); let j_cat_nomatch2 = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 2);
    code.extend_from_slice(&[0x3C, b't', 0x0F, 0x85, 0, 0, 0, 0]); let j_cat_nomatch3 = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 3);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_cat_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_cat_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_cat_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_cat_s = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_cat_bad = code.len() - 4;

    let run_check_off = code.len();
    code.push(0xA0); eu32(&mut code, input_buf_va);
    code.extend_from_slice(&[0x3C, b'r', 0x0F, 0x85, 0, 0, 0, 0]); let j_run_nomatch = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 1);
    code.extend_from_slice(&[0x3C, b'u', 0x0F, 0x85, 0, 0, 0, 0]); let j_run_nomatch2 = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 2);
    code.extend_from_slice(&[0x3C, b'n', 0x0F, 0x85, 0, 0, 0, 0]); let j_run_nomatch3 = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 3);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_run_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_run_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_run_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_run_s = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_run_bad = code.len() - 4;

    let exit_check_off = code.len();
    code.extend_from_slice(&[0xA1]); eu32(&mut code, input_buf_va);
    code.extend_from_slice(&[0x3D]); eu32(&mut code, 0x7469_7865);
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); let j_exit_nomatch = code.len() - 4;
    code.push(0xA0); eu32(&mut code, input_buf_va + 4);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_exit_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_exit_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_exit_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_exit_s = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_unknown = code.len() - 4;

    let help_off = code.len();
    code.push(0xBA); eu32(&mut code, args_write_help_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_help_loop = code.len() - 4;

    let dir_off = code.len();
    code.push(0xBA); eu32(&mut code, args_list_va);
    code.extend_from_slice(&[0xB8, 0x40, 0x20, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xA1]); eu32(&mut code, list_written_va);
    code.extend_from_slice(&[0xA3]); eu32(&mut code, args_write_dir_va + 24);
    code.push(0xBA); eu32(&mut code, args_write_dir_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_dir_loop = code.len() - 4;

    let cat_off = code.len();
    code.extend_from_slice(&[0xBE]); eu32(&mut code, input_buf_va);
    code.extend_from_slice(&[0x83, 0xC6, 0x03]);
    code.extend_from_slice(&[0xBF]); eu32(&mut code, exec_path_va);
    code.extend_from_slice(&[0xC6, 0x07, b'/']);
    code.push(0x47);
    let cskip_loop = code.len();
    code.extend_from_slice(&[0x8A, 0x06]);
    code.extend_from_slice(&[0x3C, b' ']);
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); let j_cskip_done = code.len() - 4;
    code.push(0x46);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_cskip_back = code.len() - 4;
    let ccopy_loop = code.len();
    patch_rel32(&mut code, j_cskip_done, ccopy_loop);
    patch_rel32(&mut code, j_cskip_back, cskip_loop);
    code.extend_from_slice(&[0x8A, 0x06]);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_cusage_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_cusage_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_cusage_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_cusage_s = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'a']);
    code.extend_from_slice(&[0x0F, 0x82, 0, 0, 0, 0]); let j_cup_lo = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'z']);
    code.extend_from_slice(&[0x0F, 0x87, 0, 0, 0, 0]); let j_cup_hi = code.len() - 4;
    code.extend_from_slice(&[0x2C, 0x20]);
    let cup_done = code.len();
    patch_rel32(&mut code, j_cup_lo, cup_done);
    patch_rel32(&mut code, j_cup_hi, cup_done);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_cdone_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_cdone_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_cdone_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_cdone_s = code.len() - 4;
    code.extend_from_slice(&[0x88, 0x07]);
    code.push(0x47);
    code.push(0x46);
    code.extend_from_slice(&[0x81, 0xFF]); eu32(&mut code, exec_path_va + 63);
    code.extend_from_slice(&[0x0F, 0x83, 0, 0, 0, 0]); let j_cdone_ge = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_ccopy_back = code.len() - 4;
    let cparse_done = code.len();
    patch_rel32(&mut code, j_cdone_0, cparse_done);
    patch_rel32(&mut code, j_cdone_n, cparse_done);
    patch_rel32(&mut code, j_cdone_r, cparse_done);
    patch_rel32(&mut code, j_cdone_s, cparse_done);
    patch_rel32(&mut code, j_cdone_ge, cparse_done);
    patch_rel32(&mut code, j_ccopy_back, ccopy_loop);
    code.extend_from_slice(&[0xC6, 0x07, 0x00]);
    code.push(0xBA); eu32(&mut code, args_cat_va);
    code.extend_from_slice(&[0xB8, 0x41, 0x20, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0x85, 0xC0]);
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); let j_cat_fail = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_cat_loop = code.len() - 4;
    let cat_fail_off = code.len();
    code.push(0xBA); eu32(&mut code, args_write_runfail_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_catfail_loop = code.len() - 4;
    let cat_usage_off = code.len();
    code.push(0xBA); eu32(&mut code, args_write_usage_cat_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_catusage_loop = code.len() - 4;

    let run_off = code.len();
    code.extend_from_slice(&[0xBE]); eu32(&mut code, input_buf_va);
    code.extend_from_slice(&[0x83, 0xC6, 0x04]);
    code.extend_from_slice(&[0xBF]); eu32(&mut code, exec_path_va);
    code.extend_from_slice(&[0xC6, 0x07, b'/']);
    code.push(0x47);
    let skip_loop = code.len();
    code.extend_from_slice(&[0x8A, 0x06]);
    code.extend_from_slice(&[0x3C, b' ']);
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); let j_skip_done = code.len() - 4;
    code.push(0x46);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_skip_back = code.len() - 4;
    let copy_loop = code.len();
    patch_rel32(&mut code, j_skip_done, copy_loop);
    patch_rel32(&mut code, j_skip_back, skip_loop);
    code.extend_from_slice(&[0x8A, 0x06]);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_rusage_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_rusage_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_rusage_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_rusage_s = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'a']);
    code.extend_from_slice(&[0x0F, 0x82, 0, 0, 0, 0]); let j_up_lo = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'z']);
    code.extend_from_slice(&[0x0F, 0x87, 0, 0, 0, 0]); let j_up_hi = code.len() - 4;
    code.extend_from_slice(&[0x2C, 0x20]);
    let up_done = code.len();
    patch_rel32(&mut code, j_up_lo, up_done);
    patch_rel32(&mut code, j_up_hi, up_done);
    code.extend_from_slice(&[0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0]); let j_done_0 = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\n', 0x0F, 0x84, 0, 0, 0, 0]); let j_done_n = code.len() - 4;
    code.extend_from_slice(&[0x3C, b'\r', 0x0F, 0x84, 0, 0, 0, 0]); let j_done_r = code.len() - 4;
    code.extend_from_slice(&[0x3C, b' ', 0x0F, 0x84, 0, 0, 0, 0]); let j_done_s = code.len() - 4;
    code.extend_from_slice(&[0x88, 0x07]);
    code.push(0x47);
    code.push(0x46);
    code.extend_from_slice(&[0x81, 0xFF]); eu32(&mut code, exec_path_va + 63);
    code.extend_from_slice(&[0x0F, 0x83, 0, 0, 0, 0]); let j_done_ge = code.len() - 4;
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_copy_back = code.len() - 4;
    let parse_done = code.len();
    patch_rel32(&mut code, j_done_0, parse_done);
    patch_rel32(&mut code, j_done_n, parse_done);
    patch_rel32(&mut code, j_done_r, parse_done);
    patch_rel32(&mut code, j_done_s, parse_done);
    patch_rel32(&mut code, j_done_ge, parse_done);
    patch_rel32(&mut code, j_copy_back, copy_loop);
    code.extend_from_slice(&[0xC6, 0x07, 0x00]);
    let run_usage_off = code.len();
    code.push(0xBA); eu32(&mut code, args_write_usage_run_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_runusage_loop = code.len() - 4;
    let run_create_off = code.len();
    code.push(0xBA); eu32(&mut code, args_create_proc_va);
    code.extend_from_slice(&[0xB8, 0x1B, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xA1]); eu32(&mut code, out_proc_handle_va);
    code.extend_from_slice(&[0xA3]); eu32(&mut code, args_create_thread_va + 12);
    code.push(0xBA); eu32(&mut code, args_create_thread_va);
    code.extend_from_slice(&[0xB8, 0x35, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0x85, 0xC0]);
    code.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]); let j_runfail_thread = code.len() - 4;
    code.push(0xBA); eu32(&mut code, args_write_runok_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_run_loop = code.len() - 4;
    let run_fail_off = code.len();
    code.push(0xBA); eu32(&mut code, args_write_runfail_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_runfail_loop = code.len() - 4;

    let unknown_off = code.len();
    code.push(0xBA); eu32(&mut code, args_write_unknown_va);
    code.extend_from_slice(&[0xB8, 0x12, 0x01, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E]);
    code.extend_from_slice(&[0xE9, 0, 0, 0, 0]); let j_unknown_loop = code.len() - 4;

    let exit_off = code.len();
    code.push(0xBA); eu32(&mut code, args_term_va);
    code.extend_from_slice(&[0xB8, 0xC2, 0x00, 0x00, 0x00]);
    code.extend_from_slice(&[0xCD, 0x2E, 0xEB, 0xFE]);

    patch_rel32(&mut code, j_help_nomatch, dir_check_off);
    patch_rel32(&mut code, j_help_0, help_off);
    patch_rel32(&mut code, j_help_n, help_off);
    patch_rel32(&mut code, j_help_r, help_off);
    patch_rel32(&mut code, j_help_s, help_off);
    patch_rel32(&mut code, j_help_bad, unknown_off);
    patch_rel32(&mut code, j_dir_nomatch, cat_check_off);
    patch_rel32(&mut code, j_dir_nomatch2, cat_check_off);
    patch_rel32(&mut code, j_dir_nomatch3, cat_check_off);
    patch_rel32(&mut code, j_dir_0, dir_off);
    patch_rel32(&mut code, j_dir_n, dir_off);
    patch_rel32(&mut code, j_dir_r, dir_off);
    patch_rel32(&mut code, j_dir_s, dir_off);
    patch_rel32(&mut code, j_dir_bad, unknown_off);
    patch_rel32(&mut code, j_cat_nomatch, run_check_off);
    patch_rel32(&mut code, j_cat_nomatch2, run_check_off);
    patch_rel32(&mut code, j_cat_nomatch3, run_check_off);
    patch_rel32(&mut code, j_cat_0, cat_off);
    patch_rel32(&mut code, j_cat_n, cat_off);
    patch_rel32(&mut code, j_cat_r, cat_off);
    patch_rel32(&mut code, j_cat_s, cat_off);
    patch_rel32(&mut code, j_cat_bad, unknown_off);
    patch_rel32(&mut code, j_cusage_0, cat_usage_off);
    patch_rel32(&mut code, j_cusage_n, cat_usage_off);
    patch_rel32(&mut code, j_cusage_r, cat_usage_off);
    patch_rel32(&mut code, j_cusage_s, cat_usage_off);
    patch_rel32(&mut code, j_run_nomatch, exit_check_off);
    patch_rel32(&mut code, j_run_nomatch2, exit_check_off);
    patch_rel32(&mut code, j_run_nomatch3, exit_check_off);
    patch_rel32(&mut code, j_run_0, run_off);
    patch_rel32(&mut code, j_run_n, run_off);
    patch_rel32(&mut code, j_run_r, run_off);
    patch_rel32(&mut code, j_run_s, run_off);
    patch_rel32(&mut code, j_run_bad, unknown_off);
    patch_rel32(&mut code, j_rusage_0, run_usage_off);
    patch_rel32(&mut code, j_rusage_n, run_usage_off);
    patch_rel32(&mut code, j_rusage_r, run_usage_off);
    patch_rel32(&mut code, j_rusage_s, run_usage_off);
    patch_rel32(&mut code, j_exit_nomatch, unknown_off);
    patch_rel32(&mut code, j_exit_0, exit_off);
    patch_rel32(&mut code, j_exit_n, exit_off);
    patch_rel32(&mut code, j_exit_r, exit_off);
    patch_rel32(&mut code, j_exit_s, exit_off);
    patch_rel32(&mut code, j_unknown, unknown_off);
    patch_rel32(&mut code, j_help_loop, loop_off);
    patch_rel32(&mut code, j_dir_loop, loop_off);
    patch_rel32(&mut code, j_cat_fail, cat_fail_off);
    patch_rel32(&mut code, j_cat_loop, loop_off);
    patch_rel32(&mut code, j_catfail_loop, loop_off);
    patch_rel32(&mut code, j_catusage_loop, loop_off);
    patch_rel32(&mut code, j_run_loop, loop_off);
    patch_rel32(&mut code, j_runusage_loop, loop_off);
    patch_rel32(&mut code, j_runfail_thread, run_fail_off);
    patch_rel32(&mut code, j_runfail_loop, loop_off);
    patch_rel32(&mut code, j_unknown_loop, loop_off);
    patch_rel32(&mut code, j_boot_run, run_create_off);

    let code_end = text_off + code.len();
    buf[text_off..code_end].copy_from_slice(&code);

    let args_write_prompt_off = data_off;
    let args_write_help_off = data_off + 0x30;
    let args_write_unknown_off = data_off + 0x60;
    let args_read_off = data_off + 0x90;
    let read_iosb_off = data_off + 0xC0;
    let input_buf_off = data_off + 0xC8;
    let args_list_off = data_off + 0x120;
    let list_written_off = data_off + 0x130;
    let dir_out_off = data_off + 0x138;
    let args_write_dir_off = data_off + 0x240;
    let args_write_runok_off = data_off + 0x270;
    let args_write_runfail_off = data_off + 0x280;
    let args_cat_off = data_off + 0x290;
    let args_create_proc_off = data_off + 0x2A0;
    let out_proc_handle_off = data_off + 0x2B0;
    let args_create_thread_off = data_off + 0x2C0;
    let out_thread_handle_off = data_off + 0x2D8;
    let out_client_id_off = data_off + 0x2E0;
    let args_term_off = data_off + 0x2F0;
    let args_write_usage_run_off = data_off + 0x480;
    let args_write_usage_cat_off = data_off + 0x4A0;
    let path_root_off = data_off + 0x300;
    let prompt_off = data_off + 0x308;
    let help_off_d = data_off + 0x320;
    let unknown_off_d = data_off + 0x3A0;
    let runok_off = data_off + 0x3C0;
    let exec_path_off = data_off + 0x3D0;
    let runfail_off = data_off + 0x3E0;
    let usage_run_off = data_off + 0x4C0;
    let usage_cat_off = data_off + 0x4D8;

    buf[args_write_prompt_off + 20..args_write_prompt_off + 24].copy_from_slice(&prompt_va.to_le_bytes());
    buf[args_write_prompt_off + 24..args_write_prompt_off + 28].copy_from_slice(&(prompt.len() as u32).to_le_bytes());
    buf[args_write_help_off + 20..args_write_help_off + 24].copy_from_slice(&help_va.to_le_bytes());
    buf[args_write_help_off + 24..args_write_help_off + 28].copy_from_slice(&(help.len() as u32).to_le_bytes());
    buf[args_write_unknown_off + 20..args_write_unknown_off + 24].copy_from_slice(&unknown_va.to_le_bytes());
    buf[args_write_unknown_off + 24..args_write_unknown_off + 28].copy_from_slice(&(unknown.len() as u32).to_le_bytes());

    buf[args_read_off..args_read_off + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[args_read_off + 16..args_read_off + 20].copy_from_slice(&read_iosb_va.to_le_bytes());
    buf[args_read_off + 20..args_read_off + 24].copy_from_slice(&input_buf_va.to_le_bytes());
    buf[args_read_off + 24..args_read_off + 28].copy_from_slice(&64u32.to_le_bytes());
    buf[read_iosb_off..read_iosb_off + 8].copy_from_slice(&0u64.to_le_bytes());

    buf[args_list_off..args_list_off + 4].copy_from_slice(&path_root_va.to_le_bytes());
    buf[args_list_off + 4..args_list_off + 8].copy_from_slice(&dir_out_va.to_le_bytes());
    buf[args_list_off + 8..args_list_off + 12].copy_from_slice(&256u32.to_le_bytes());
    buf[args_list_off + 12..args_list_off + 16].copy_from_slice(&list_written_va.to_le_bytes());
    buf[list_written_off..list_written_off + 4].copy_from_slice(&0u32.to_le_bytes());

    buf[args_write_dir_off + 20..args_write_dir_off + 24].copy_from_slice(&dir_out_va.to_le_bytes());
    buf[args_write_dir_off + 24..args_write_dir_off + 28].copy_from_slice(&0u32.to_le_bytes());
    buf[args_write_runok_off + 20..args_write_runok_off + 24].copy_from_slice(&runok_va.to_le_bytes());
    buf[args_write_runok_off + 24..args_write_runok_off + 28].copy_from_slice(&(runok.len() as u32).to_le_bytes());
    buf[args_write_runfail_off + 20..args_write_runfail_off + 24].copy_from_slice(&runfail_va.to_le_bytes());
    buf[args_write_runfail_off + 24..args_write_runfail_off + 28].copy_from_slice(&(runfail.len() as u32).to_le_bytes());
    buf[args_write_usage_run_off + 20..args_write_usage_run_off + 24].copy_from_slice(&usage_run_va.to_le_bytes());
    buf[args_write_usage_run_off + 24..args_write_usage_run_off + 28].copy_from_slice(&(usage_run.len() as u32).to_le_bytes());
    buf[args_write_usage_cat_off + 20..args_write_usage_cat_off + 24].copy_from_slice(&usage_cat_va.to_le_bytes());
    buf[args_write_usage_cat_off + 24..args_write_usage_cat_off + 28].copy_from_slice(&(usage_cat.len() as u32).to_le_bytes());
    buf[args_cat_off..args_cat_off + 4].copy_from_slice(&exec_path_va.to_le_bytes());

    buf[args_create_proc_off..args_create_proc_off + 4].copy_from_slice(&out_proc_handle_va.to_le_bytes());
    buf[args_create_proc_off + 4..args_create_proc_off + 8].copy_from_slice(&exec_path_va.to_le_bytes());
    buf[out_proc_handle_off..out_proc_handle_off + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[args_create_thread_off..args_create_thread_off + 4].copy_from_slice(&out_thread_handle_va.to_le_bytes());
    buf[args_create_thread_off + 12..args_create_thread_off + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf[args_create_thread_off + 16..args_create_thread_off + 20].copy_from_slice(&out_client_id_va.to_le_bytes());
    buf[out_thread_handle_off..out_thread_handle_off + 4].copy_from_slice(&0u32.to_le_bytes());
    buf[out_client_id_off..out_client_id_off + 8].copy_from_slice(&0u64.to_le_bytes());

    buf[args_term_off + 4..args_term_off + 8].copy_from_slice(&0u32.to_le_bytes());

    buf[path_root_off] = b'/';
    buf[path_root_off + 1] = 0;
    buf[prompt_off..prompt_off + prompt.len()].copy_from_slice(prompt);
    buf[help_off_d..help_off_d + help.len()].copy_from_slice(help);
    buf[unknown_off_d..unknown_off_d + unknown.len()].copy_from_slice(unknown);
    buf[runok_off..runok_off + runok.len()].copy_from_slice(runok);
    buf[runfail_off..runfail_off + runfail.len()].copy_from_slice(runfail);
    buf[usage_run_off..usage_run_off + usage_run.len()].copy_from_slice(usage_run);
    buf[usage_cat_off..usage_cat_off + usage_cat.len()].copy_from_slice(usage_cat);
    buf[exec_path_off..exec_path_off + 9].copy_from_slice(b"/TEST.EXE");
    buf[exec_path_off + 9] = 0;

    let _ = input_buf_off;
    let _ = dir_out_off;

    buf
}

// ── PE32 constants/types ──────────────────────────────────────────────────────
mod pe32 {
    pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
    pub const IMAGE_NT_SIGNATURE:  u32 = 0x0000_4550;
    pub const MACHINE_I386:        u16 = 0x014C;
    pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;
    pub const SCN_CNT_CODE:              u32 = 0x0000_0020;
    pub const SCN_CNT_INITIALIZED_DATA:  u32 = 0x0000_0040;
    pub const SCN_MEM_EXECUTE:           u32 = 0x2000_0000;
    pub const SCN_MEM_READ:              u32 = 0x4000_0000;
    pub const SCN_MEM_WRITE:             u32 = 0x8000_0000;

    // Sized placeholders to get sizeof without a full definition.
    // ImageFileHeader = 20 bytes, ImageOptionalHeader32 = 96 + 16*8 = 224 bytes.
    pub struct ImageFileHeader([u8; 20]);
    pub struct ImageOptionalHeader32([u8; 224]);
}

// ── Byte-emission helpers ──────────────────────────────────────────────────────
fn eu32(v: &mut Vec<u8>, val: u32) {
    v.extend_from_slice(&val.to_le_bytes());
}
fn epush(v: &mut Vec<u8>, val: u32) {
    v.push(0x68);
    v.extend_from_slice(&val.to_le_bytes());
}
fn patch_rel32(code: &mut [u8], imm_off: usize, target_off: usize) {
    let next = imm_off + 4;
    let rel = (target_off as isize - next as isize) as i32;
    code[imm_off..imm_off + 4].copy_from_slice(&rel.to_le_bytes());
}
