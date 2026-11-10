//! The pinned ReactOS's SYSTEM hive (`cargo xtask fetch-userland`), read as
//! smss reads it; skipped when the userland is not fetched.

const SYSTEM: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/reactos/0.4.16/reactos/system32/config/system");

fn utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units).trim_end_matches('\0').to_owned()
}

#[test]
fn the_session_manager_of_reactos_system_hive() {
    let Ok(file) = std::fs::read(SYSTEM) else {
        eprintln!("skipped: no {SYSTEM} (cargo xtask fetch-userland)");
        return;
    };
    let hive = regf::Hive::parse(&file).expect("ReactOS's SYSTEM hive");
    let root = hive.root().unwrap();
    let current = root.open("Select").unwrap().expect("Select").value("Current").unwrap().expect("Current");
    assert_eq!((current.data_type(), &*current.data().unwrap()), (4, &[1u8, 0, 0, 0][..]), "ControlSet001");
    let session = root.open("controlset001\\CONTROL\\Session Manager").unwrap().expect("Session Manager, without case");
    let directories = session.value("ObjectDirectories").unwrap().expect("ObjectDirectories");
    assert_eq!(directories.data_type(), 7, "REG_MULTI_SZ");
    assert!(utf16(&directories.data().unwrap()).starts_with("\\Windows\0\\RPC Control"));
    let known = session.open("KnownDLLs").unwrap().expect("KnownDLLs");
    assert!(known.value("ntdll").unwrap().is_none(), "ntdll is always known, never listed");
    assert_eq!(utf16(&known.value("KERNEL32").unwrap().expect("kernel32").data().unwrap()), "kernel32.dll");
    let environment = session.open("Environment").unwrap().expect("Environment");
    assert_eq!(environment.value("ComSpec").unwrap().expect("ComSpec").data_type(), 2, "REG_EXPAND_SZ");
    assert!(root.open("CurrentControlSet").unwrap().is_none(), "the kernel makes CurrentControlSet, not the file");
}
