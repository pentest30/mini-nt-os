//! Les `rostests` de ReactOS (`modules/rostests/apitests`), le dernier
//! critère du M5 : les apitests `ntdll` et `kernel32` compilés par
//! [`build`] et lancés par le scénario `rostests`, leur bilan lu du port
//! série et comparé au seuil du jalon ([`THRESHOLD`]).
//!
//! La compilation est autonome : MinGW, contre une copie du PSDK de
//! l'arbre 0.4.16 où `winnt.h` — que ReactOS génère au build — est
//! remplacé par un shim (`rostests-src/psdk-winnt.h` : le préambule du
//! template, le corps complet `xdk/winnt_old.h`). Le `main` d'un seul test
//! de `wine/test.h` est écarté (`-Dmain=apitest_wine_main` sur testlist.c) ;
//! `rostests-src/testmain.c` itère la liste et rend chaque résumé par
//! `DbgPrint`. Les tests qui ne compilent pas sont écartés, listés — le
//! seuil du jalon s'entend sur ce qui tourne, et le nombre d'écartés fait
//! partie du suivi.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::native;
use crate::{Result, Workspace};

/// Le seuil du jalon M5 : la part des tests qui passent (ok + todo — un
/// todo réussi compte, un todo attendu ne bloque pas). Fixé au moment du
/// jalon ; le suivi se fait dans le temps — la valeur ne baisse pas. Le
/// scénario `rostests` le comparera au bilan ([`super::qemu`], quand le
/// banc compile — voir l'en-tête du module).
#[expect(dead_code, reason = "comparé par le scénario rostests, pas encore branché")]
pub const THRESHOLD: f64 = 0.50;

/// Les modules du critère.
const MODULES: [&str; 2] = ["ntdll", "kernel32"];

/// Où l'arbre des sources ReactOS épinglé vit (gitignoré, cloné par
/// [`fetch`] — le proxy Git, comme le documente la passation).
fn source_tree(ws: &Workspace) -> PathBuf {
    ws.root.join("third_party").join("reactos-0.4.16")
}

/// `rostests-fetch` : l'clone éparse de l'arbre 0.4.16 — apitests, le SDK
/// d'en-têtes, PSEH — sous third_party (gitignoré).
pub fn fetch(ws: &Workspace) -> Result<()> {
    let tree = source_tree(ws);
    if tree.join(".git").is_dir() {
        println!("xtask: {} déjà là", tree.display());
        return Ok(());
    }
    fs::create_dir_all(tree.parent().expect("un parent")).map_err(|e| e.to_string())?;
    let dir = tree.display().to_string();
    run(Command::new("git")
        .args(["clone", "--filter=blob:none", "--no-checkout", "--depth", "1", "--branch", "0.4.16"])
        .arg("https://github.com/reactos/reactos")
        .arg(&dir))?;
    Command::new("git")
        .args([
            "-C",
            &dir,
            "sparse-checkout",
            "set",
            "modules/rostests/apitests/include",
            "modules/rostests/apitests/ntdll",
            "modules/rostests/apitests/kernel32",
            "sdk/include/psdk",
            "sdk/include/ndk",
            "sdk/include/wine",
            "sdk/include/reactos",
            "sdk/include/xdk",
            "sdk/include/ddk",
            "sdk/lib/pseh",
        ])
        .status()
        .map_err(|e| format!("git sparse-checkout : {e}"))?
        .success()
        .then_some(())
        .ok_or_else(|| "git sparse-checkout a échoué".to_string())?;
    run(Command::new("git").args(["-C", &dir, "checkout"]))?;
    println!("xtask: rostests : l'arbre 0.4.16 cloné dans {}", tree.display());
    Ok(())
}

/// `rostests-build` : les deux modules compilés en `NTAPITST.EXE` et
/// `K32APITST.EXE` (sous-système WINDOWS : la commande initiale de smss
/// n'accepte que lui), sur le disque de démarrage des scénarios. Rend les
/// fichiers ajoutés au ramdisk (`HOST:FAT_PATH`).
pub fn build(ws: &Workspace) -> Result<Option<Vec<String>>> {
    let tree = source_tree(ws);
    if !tree.join("modules").is_dir() {
        return Err("rostests : l'arbre 0.4.16 manque (cargo xtask rostests-fetch)".into());
    }
    if native::missing_tool().is_some() {
        return Ok(None);
    }
    let out = ws.target.join("xtask").join("rostests");
    let sdk = prepare_sdk(&tree, &out)?;
    let mut files = Vec::new();
    for module in MODULES {
        let name = if module == "ntdll" { "NTAPITST.EXE" } else { "K32APITST.EXE" };
        let exe = compile_module(ws, &tree, &sdk, module, &out, name)?;
        files.push(format!("{}:{}", exe.display(), name));
    }
    Ok(Some(files))
}

/// La copie du SDK : psdk recopié avec le shim winnt.h, les précompils
/// locaux, testmain.c — et les chemins d'inclusion qui vont avec.
fn prepare_sdk(tree: &Path, out: &Path) -> Result<PathBuf> {
    let sdk = out.join("sdk");
    let psdk = sdk.join("include").join("psdk");
    if psdk.join("windef.h").is_file() {
        return Ok(sdk);
    }
    fs::create_dir_all(&psdk).map_err(|e| e.to_string())?;
    copy_dir(&tree.join("sdk").join("include").join("psdk"), &psdk)?;
    fs::copy(ws_shim("psdk-winnt.h"), psdk.join("winnt.h")).map_err(|e| format!("winnt.h overlay : {e}"))?;
    // msvctarget.h (gcc) vit dans reactos/ ; basetsd.h l'inclut sans chemin.
    for loose in ["msvctarget.h", "no_sal2.h"] {
        let from = tree.join("sdk").join("include").join("reactos").join(loose);
        if from.is_file() {
            fs::copy(&from, psdk.join(loose)).map_err(|e| format!("{loose} : {e}"))?;
        }
    }
    Ok(sdk)
}

/// Les fichiers sources du banc (dans le dépôt).
fn ws_shim(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rostests-src").join(name)
}

/// La recopie d'un répertoire (fichiers plats).
fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    for entry in fs::read_dir(from).map_err(|e| format!("{} : {e}", from.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_file() {
            fs::copy(&path, to.join(entry.file_name())).map_err(|e| format!("{} : {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Un module : ses .c, son testlist.c, testmain.c — compilés puis liés.
fn compile_module(ws: &Workspace, tree: &Path, sdk: &Path, module: &str, out: &Path, name: &str) -> Result<PathBuf> {
    let apitests = tree.join("modules").join("rostests").join("apitests");
    let module_dir = apitests.join(module);
    let objs = out.join(module);
    fs::create_dir_all(&objs).map_err(|e| e.to_string())?;
    fs::copy(ws_shim("testmain.c"), out.join("testmain.c")).map_err(|e| e.to_string())?;
    fs::copy(ws_shim(&format!("{module}-precomp.h")), module_dir.join("precomp.h.autostandalone"))
        .map_err(|e| e.to_string())?;

    let includes: Vec<String> = [
        out.display().to_string(),
        apitests.join("include").display().to_string(),
        tree.join("sdk").join("lib").join("pseh").join("include").display().to_string(),
        tree.join("sdk").join("include").display().to_string(),
        tree.join("sdk").join("include").join("ndk").display().to_string(),
        sdk.join("include").join("psdk").display().to_string(),
    ]
    .into_iter()
    .chain(std::iter::once(".".to_string()))
    .map(|path| format!("-I{path}"))
    .collect();
    let defines = [
        "-DSTATUS_WAIT_0=0x00000000L",
        "-DSTATUS_ABANDONED_WAIT_0=0x00000080L",
        "-DSTATUS_DISCONNECTION=0xC0000254L",
        "-DSTATUS_INVALID_CID=0xC000000BL",
        "-D__kernel_entry=",
    ];

    let mut compiled = Vec::new();
    let mut skipped = Vec::new();
    let sources = fs::read_dir(&module_dir).map_err(|e| format!("{} : {e}", module_dir.display()))?;
    let mut sources: Vec<PathBuf> = sources
        .filter_map(|entry| {
            entry.ok().map(|entry| entry.path()).filter(|path| path.extension().is_some_and(|e| e == "c"))
        })
        .collect();
    sources.sort();
    for source in &sources {
        if source.file_stem().is_some_and(|stem| stem == "testlist") {
            continue;
        }
        let object = objs.join(source.file_name().expect("un nom").to_string_lossy().replace(".c", ".o"));
        let mut command = Command::new("i686-w64-mingw32-gcc");
        command
            .args(["-c", "-O1", "-w", "-D_WIN32_WINNT=0x0501"])
            .args(defines)
            .arg(format!("-I{}", module_dir.display()))
            .args(&includes)
            .arg(source)
            .arg("-o")
            .arg(&object);
        if command.status().map_err(|e| e.to_string())?.success() {
            compiled.push(object);
        } else {
            skipped.push(source.file_stem().expect("un nom").to_string_lossy().into_owned());
        }
    }
    if !skipped.is_empty() {
        println!(
            "xtask: rostests {module} : {} tests écartés (ne compilent pas) : {}",
            skipped.len(),
            skipped.join(", ")
        );
    }
    // testlist.c référence les tests des deux architectures ; les fonctions
    // absentes (x86 seulement) sortent du lien par --unresolved-symbols
    // ignore — non : son main neutralisé, et les références manquantes
    // retirées à la compilation par _M_IX86... Le fichier référence aussi
    // les écartés : lier sans eux exige --unresolved-symbols=ignore-all,
    // qui casse les imports DLL. À la place : un testlist réduit, écrit
    // d'après les objets compilés.
    let testlist = out.join(format!("{module}-testlist.c"));
    let mut list = String::from(
        "/* Généré : la liste des tests qui compilent, pour le main de lot. */\n\
         #define STANDALONE\n#include <apitest.h>\n",
    );
    let mut entries = Vec::new();
    for object in &compiled {
        let stem = object.file_stem().expect("un nom").to_string_lossy().into_owned();
        let test = stem.strip_suffix(".o").unwrap_or(&stem);
        list.push_str(&format!("extern void func_{test}(void);\n"));
        entries.push(format!("    {{ \"{test}\", func_{test} }},"));
    }
    list.push_str(&format!(
        "\nconst struct test winetest_testlist[] = {{\n{}\n    {{ 0, 0 }}\n}};\n",
        entries.join("\n")
    ));
    fs::write(&testlist, list).map_err(|e| e.to_string())?;

    let testlist_object = objs.join("testlist.o");
    run(Command::new("i686-w64-mingw32-gcc")
        .args(["-c", "-O1", "-w", "-Dmain=apitest_wine_main", "-D_WIN32_WINNT=0x0501"])
        .args(defines)
        .arg(format!("-I{}", module_dir.display()))
        .args(&includes)
        .arg(&testlist)
        .arg("-o")
        .arg(&testlist_object))?;
    let testmain_object = objs.join("testmain.o");
    run(Command::new("i686-w64-mingw32-gcc")
        .args(["-c", "-O1", "-w"])
        .arg(out.join("testmain.c"))
        .arg("-o")
        .arg(&testmain_object))?;

    let exe = out.join(name);
    let native_libs = ws.target.join("xtask").join("native");
    let mut link = Command::new("i686-w64-mingw32-gcc");
    link.args(["-nostartfiles", "-Wl,--subsystem,windows:5.1", "-Wl,-e,_WinMain@16", "-o"])
        .arg(&exe)
        .arg(&testmain_object)
        .arg(&testlist_object)
        .args(&compiled)
        .arg("-L")
        .arg(&native_libs)
        .args(["-lntdll", "-lkernel32", "-luser32", "-lgdi32", "-lmsvcrt", "-lpseh"]);
    run(&mut link)?;
    println!("xtask: rostests {module} : {} ({} tests compilés)", name, compiled.len());
    Ok(exe)
}

fn run(command: &mut Command) -> Result<()> {
    command
        .status()
        .map_err(|e| format!("{:?} : {e}", command.get_program()))?
        .success()
        .then_some(())
        .ok_or_else(|| format!("{:?} a échoué", command.get_program()))
}
