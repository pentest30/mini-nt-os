use super::*;

fn sz(text: &str) -> Vec<u8> {
    utf16z(text)
}

fn dword(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// A SYSTEM hive whose current control set is 2, and an empty DEFAULT.
fn sample_hives() -> BTreeMap<Hive, KeyNode> {
    let mut system = KeyNode::new("SYSTEM");
    system.key_mut("Select").set_value("Current", REG_DWORD, dword(2));
    system.key_mut("ControlSet002\\Control\\Session Manager").set_value(
        "BootExecute",
        REG_MULTI_SZ,
        multi_sz(&["autocheck autochk *".into()]),
    );
    system.key_mut("Setup").set_value("CmdLine", REG_SZ, sz("setup -mini"));
    BTreeMap::from([(Hive::System, system), (Hive::Default, KeyNode::new("DEFAULT"))])
}

#[test]
fn reads_fields_quotes_comments_and_continuations() {
    let layer = parse(
        "[Version]\n\
         Signature = \"$Windows NT$\" ; ignored\n\
         [AddReg]\n\
         ; a comment\n\
         HKLM,\"SYSTEM\\Setup\",\"CmdLine\",0x00020000,\"a;b \"\"quoted\"\"\" ; the rest\n\
         HKLM,\"SYSTEM\\Select\",\"Current\",0x00010001,\\\n   2\n\
         HKCU,\"Keyboard Layout\\Preload\",\"1\",,\"00000409\"\n",
    )
    .expect("a layer");
    assert!(layer.delete.is_empty());
    assert_eq!(layer.add.len(), 3, "[Version] is not read");
    assert_eq!(layer.add[0].path, "Setup");
    assert_eq!(
        layer.add[0].action,
        Action::Set {
            name: "CmdLine".into(),
            data_type: REG_EXPAND_SZ,
            data: sz("a;b \"quoted\""),
            keep_existing: false
        },
        "a `;` and doubled quotes inside quotes"
    );
    assert_eq!(layer.add[1].line, 6, "the line where it starts");
    assert_eq!(
        layer.add[1].action,
        Action::Set { name: "Current".into(), data_type: REG_DWORD, data: dword(2), keep_existing: false },
        "continued on the next line"
    );
    assert_eq!((layer.add[2].hive, layer.add[2].path.as_str()), (Hive::Default, "Keyboard Layout\\Preload"));
    assert_eq!(
        layer.add[2].action,
        Action::Set { name: "1".into(), data_type: REG_SZ, data: sz("00000409"), keep_existing: false },
        "no flags: a string"
    );
}

#[test]
fn reads_types_and_modifiers() {
    let layer = parse(
        "[AddReg]\n\
         HKLM,\"SOFTWARE\\A\",,0x00000012\n\
         HKLM,\"SOFTWARE\\A\",\"M\",0x00010000,\"x\",\"y\"\n\
         HKLM,\"SOFTWARE\\A\",\"N\",0x00010003,5\n\
         HKLM,\"SOFTWARE\\A\",\"B\",0x00000001,01,ff\n\
         HKLM,\"SOFTWARE\\A\",\"Z\",0x00020001\n\
         HKLM,\"SOFTWARE\\A\",\"M\",0x00010008,\"z\"\n\
         HKLM,\"SOFTWARE\\A\",\"D\",0x00000004\n\
         HKCR,\".txt\",,,\"txtfile\"\n\
         HKU,\".DEFAULT\\Console\",\"Size\",0x00010001,0x10\n",
    )
    .unwrap();
    let actions: Vec<_> = layer.add.iter().map(|e| e.action.clone()).collect();
    assert_eq!(actions[0], Action::Key, "0x12: the key only");
    assert_eq!(
        actions[1],
        Action::Set {
            name: "M".into(),
            data_type: REG_MULTI_SZ,
            data: multi_sz(&["x".into(), "y".into()]),
            keep_existing: false
        }
    );
    assert_eq!(actions[2], Action::Set { name: "N".into(), data_type: REG_DWORD, data: dword(5), keep_existing: true });
    assert_eq!(
        actions[3],
        Action::Set { name: "B".into(), data_type: REG_BINARY, data: vec![1, 0xFF], keep_existing: false }
    );
    assert_eq!(
        actions[4],
        Action::Set { name: "Z".into(), data_type: REG_NONE, data: Vec::new(), keep_existing: false }
    );
    assert_eq!(actions[5], Action::Append { name: "M".into(), strings: vec!["z".into()] });
    assert_eq!(actions[6], Action::DeleteValue { name: "D".into() });
    assert_eq!((layer.add[7].hive, layer.add[7].path.as_str()), (Hive::Software, "Classes\\.txt"));
    assert_eq!((layer.add[8].hive, layer.add[8].path.as_str()), (Hive::Default, "Console"));
}

#[test]
fn refuses_what_it_does_not_read() {
    assert!(parse("[AddReg]\nHKLM,\"HARDWARE\\X\",\"V\",0,\"a\"").unwrap_err().contains("line 2"), "a volatile hive");
    assert!(parse("[AddReg]\nHKXX,\"X\",\"V\",0,\"a\"").is_err(), "an unknown root");
    assert!(parse("[AddReg]\nHKLM,\"SYSTEM\\X\",\"V\",0x00000100,\"a\"").is_err(), "an unknown modifier");
    assert!(parse("[AddReg]\nHKLM,\"SYSTEM\\X\",\"V\",0x00030000,\"a\"").is_err(), "an unknown type");
    assert!(parse("[AddReg]\nHKLM,\"SYSTEM\\X\",\"V\",0x00000008,\"a\"").is_err(), "append to a string");
    assert!(parse("[AddReg]\nHKLM,\"SYSTEM\\X,\"V\"").is_err(), "an unclosed quote");
    assert!(parse("[AddReg]\nHKLM,\"SYSTEM\\X\",\"V\",0x00000001,zz").is_err(), "a binary byte");
    assert!(parse("[Strings]\nHKXX,\"anything\"").is_ok(), "other sections are not read");
}

#[test]
fn applies_deletions_then_additions() {
    let layer = parse(
        "[AddReg]\n\
         HKLM,\"SYSTEM\\CurrentControlSet\\Control\\Session Manager\",\"BootExecute\",0x00010000,\"\"\n\
         HKLM,\"SYSTEM\\Setup\",\"CmdLine\",0x00000002,\"kept?\"\n\
         HKLM,\"SYSTEM\\Setup\",\"SetupType\",0x00010001,1\n\
         HKLM,\"SYSTEM\\New\\Deep\",,0x00000012\n\
         HKLM,\"SYSTEM\\CurrentControlSet\\Control\\Session Manager\",\"Extra\",0x00010008,\"one\",\"two\"\n\
         HKLM,\"SYSTEM\\CurrentControlSet\\Control\\Session Manager\",\"Extra\",0x00010008,\"TWO\",\"three\"\n\
         HKCU,\"Console\",\"FontSize\",0x00010001,0x100000\n\
         [DelReg]\n\
         HKLM,\"SYSTEM\\Select\"\n\
         HKLM,\"SYSTEM\\Setup\",\"Missing\"\n",
    )
    .unwrap();
    let mut hives = sample_hives();
    apply(&layer, &mut hives).expect("applied");
    let system = &hives[&Hive::System];
    assert!(value(system, "Select", "Current").is_none(), "[DelReg] first: the key is gone");
    let boot = value(system, "ControlSet002\\Control\\Session Manager", "BootExecute").expect("in ControlSet002");
    assert_eq!(boot.data, multi_sz(&["".into()]), "CurrentControlSet read before Select was deleted");
    assert!(find_key(&mut hives.get_mut(&Hive::System).unwrap().clone(), "CurrentControlSet").is_none());
    let system = &hives[&Hive::System];
    assert_eq!(value(system, "Setup", "CmdLine").unwrap().data, sz("setup -mini"), "0x2: not overwritten");
    assert_eq!(value(system, "Setup", "SetupType").unwrap().data, dword(1));
    let extra = value(system, "ControlSet002\\Control\\Session Manager", "Extra").unwrap();
    assert_eq!(strings_of(&extra.data), ["one", "two", "three"], "appended once, without case");
    assert!(system.subkeys.iter().any(|k| k.name == "New" && k.subkeys[0].name == "Deep"), "created with the way");
    assert_eq!(value(&hives[&Hive::Default], "Console", "FontSize").unwrap().data, dword(0x10_0000));
}

#[test]
fn a_line_for_a_hive_not_given_is_an_error() {
    let layer = parse("[AddReg]\nHKLM,\"SOFTWARE\\X\",\"V\",0,\"a\"").unwrap();
    let error = apply(&layer, &mut sample_hives()).unwrap_err();
    assert!(error.contains("line 2") && error.contains("Software"), "{error}");
}

#[test]
fn the_mino_layer_installs_a_system_that_logs_on() {
    let layer = parse(MINO_LAYER).expect("mino.inf");
    assert_eq!(layer.hives(), [Hive::System, Hive::Software, Hive::Default]);
    let mut hives = sample_hives();
    hives.insert(Hive::Software, KeyNode::new("SOFTWARE"));
    apply(&layer, &mut hives).expect("applied");
    let (system, software) = (&hives[&Hive::System], &hives[&Hive::Software]);
    assert_eq!(value(system, "Setup", "SetupType").unwrap().data, dword(1), "the first boot sets up");
    let command = value(system, "Setup", "CmdLine").unwrap();
    assert_eq!((command.data_type, command.data.clone()), (REG_EXPAND_SZ, sz("%SystemRoot%\\system32\\minoinit.exe")));
    let name = value(system, "ControlSet002\\Control\\ComputerName\\ComputerName", "ComputerName").unwrap();
    assert_eq!(name.data, sz("MINO"), "in the current control set");
    let winlogon = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    assert_eq!(value(software, winlogon, "AutoAdminLogon").unwrap().data, sz("1"));
    assert_eq!(value(software, winlogon, "DefaultUserName").unwrap().data, sz("Administrator"));
    assert_eq!(value(software, winlogon, "DefaultPassword").unwrap().data, sz(""));
    let profiles = value(software, "Microsoft\\Windows NT\\CurrentVersion\\ProfileList", "ProfilesDirectory").unwrap();
    assert_eq!(profiles.data, sz("%SystemDrive%\\Documents and Settings"));
}

/// The pinned ReactOS hives (`cargo xtask fetch-userland`), layered as
/// `xtask` does it; skipped without them.
#[test]
fn the_mino_layer_on_the_pinned_hives() {
    let config = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/reactos/0.4.16/reactos/system32/config");
    let layer = parse(MINO_LAYER).unwrap();
    for hive in layer.hives() {
        let path = format!("{config}/{}", hive.file_name());
        let Ok(file) = std::fs::read(&path) else {
            eprintln!("skipped: no {path} (cargo xtask fetch-userland)");
            return;
        };
        let rebuilt = layered(hive, &file, &layer, hive.file_name()).expect("layered");
        let tree = KeyNode::read(&regf::Hive::parse(&rebuilt).unwrap().root().unwrap()).unwrap();
        let original = KeyNode::read(&regf::Hive::parse(&file).unwrap().root().unwrap()).unwrap();
        match hive {
            Hive::System => {
                assert_eq!(value(&tree, "Setup", "CmdLine").unwrap().data, sz("%SystemRoot%\\system32\\minoinit.exe"));
                let session = "ControlSet001\\Control\\Session Manager";
                assert_eq!(value(&tree, session, "ObjectDirectories"), value(&original, session, "ObjectDirectories"));
            }
            Hive::Software => {
                let winlogon = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
                assert_eq!(value(&tree, winlogon, "DefaultUserName").unwrap().data, sz("Administrator"));
                assert!(value(&tree, winlogon, "DisableLockWorkstation").is_none(), "the LiveCD's, deleted");
                assert_eq!(value(&tree, winlogon, "Shell"), value(&original, winlogon, "Shell"), "the rest kept");
            }
            _ => {
                let policies = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
                assert!(value(&tree, policies, "DisableChangePassword").is_none());
                assert_eq!(
                    value(&tree, "Keyboard Layout\\Preload", "1"),
                    value(&original, "Keyboard Layout\\Preload", "1")
                );
            }
        }
    }
}
