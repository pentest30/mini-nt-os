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

/// La copie du SDK : psdk recopié avec le winnt.h **généré**, les
/// précompils locaux, testmain.c — et les chemins d'inclusion qui vont
/// avec.
fn prepare_sdk(tree: &Path, out: &Path) -> Result<PathBuf> {
    let sdk = out.join("sdk");
    let psdk = sdk.join("include").join("psdk");
    if psdk.join("windef.h").is_file() {
        return Ok(sdk);
    }
    fs::create_dir_all(&psdk).map_err(|e| e.to_string())?;
    copy_dir(&tree.join("sdk").join("include").join("psdk"), &psdk)?;
    let winnt = generate_winnt(tree).map_err(|e| format!("winnt.h généré : {e}"))?;
    fs::write(psdk.join("winnt.h"), winnt).map_err(|e| format!("winnt.h : {e}"))?;
    // Les en-têtes volés : msvctarget.h (gcc) dans reactos/, kernelspecs.h
    // dans ddk/ — le winnt.h généré les inclut sans chemin.
    for (from, loose) in [
        (tree.join("sdk").join("include").join("reactos").join("msvctarget.h"), "msvctarget.h"),
        (tree.join("sdk").join("include").join("reactos").join("no_sal2.h"), "no_sal2.h"),
        (tree.join("sdk").join("include").join("ddk").join("kernelspecs.h"), "kernelspecs.h"),
        (tree.join("sdk").join("include").join("psdk").join("driverspecs.h"), "driverspecs.h"),
        (tree.join("sdk").join("include").join("ddk").join("ntnls.h"), "ntnls.h"),
    ] {
        if from.is_file() {
            fs::copy(&from, psdk.join(loose)).map_err(|e| format!("{loose} : {e}"))?;
        }
    }
    fs::copy(ws_shim("apitest-macros.h"), psdk.join("apitest-macros.h"))
        .map_err(|e| format!("apitest-macros.h : {e}"))?;
    Ok(sdk)
}

/// Le winnt.h que ReactOS génère au build : son template
/// (xdk/winnt.template.h) compose huit en-têtes XDK (`$include`) dont les
/// directives s'évaluent pour la cible — ici le PSDK i386 : `_WINNT_`
/// seul (ni `_NTDEF_` — c'est le ntdef.h généré — ni `_WDMDDK_`/
/// `_NTDDK_`), les `$define` du template (ULONG=DWORD…), et les alias de
/// types (`$ULONG` → le define actif, sinon lui-même).
fn generate_winnt(tree: &Path) -> std::result::Result<String, String> {
    let xdk = tree.join("sdk").join("include").join("xdk");
    let mut defines: Vec<(String, String)> = vec![("_WINNT_".into(), String::new())];
    let mut out = String::new();
    let mut kept = vec![true];
    expand_file(&xdk.join("winnt.template.h"), &xdk, &mut defines, &mut kept, &mut Vec::new(), &mut out)?;
    Ok(out)
}

/// Les définitions actives (les `$define` du template, avec `_WINNT_`).
type Defines = Vec<(String, String)>;

/// Évalue un fichier XDK dans `out` : ses `$include` inlinés (le même
/// répertoire), ses `$define`, et les alias `$ULONG`… remplacés par leur
/// définition. L'état `$if`/`$endif` est **global à la composition** — un
/// `$endif` d'un fichier inclus ferme le `$if` du fichier englobant (la
/// génération de ReactOS compose ainsi) — porté par `kept` ;
/// `defines` aussi. `stack` détecte les inclusions circulaires.
fn expand_file(
    path: &Path,
    dir: &Path,
    defines: &mut Defines,
    kept: &mut Vec<bool>,
    stack: &mut Vec<PathBuf>,
    out: &mut String,
) -> std::result::Result<(), String> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if stack.contains(&canonical) {
        return Err(format!("{} s'inclut lui-même", path.display()));
    }
    stack.push(canonical);
    let text = fs::read_to_string(path).map_err(|e| format!("{} : {e}", path.display()))?;
    // Les variables $if actives : le nom existe dans defines (valeur vide).
    fn active(defines: &Defines, name: &str) -> bool {
        defines.iter().any(|(key, _)| key == name)
    }
    let mut local: Vec<usize> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let open = *kept.last().unwrap_or(&true);
        // `$if (…)` aussi bien que `$if(…)` — les XDK écrivent les deux.
        let directive = |name: &str| trimmed.strip_prefix(name).map(str::trim);
        if let Some(rest) = directive("$include") {
            let file = rest
                .strip_prefix('(')
                .and_then(|rest| rest.strip_suffix(')'))
                .ok_or_else(|| format!("{} : $include sans fermeture", path.display()))?;
            if open {
                expand_file(&dir.join(file), dir, defines, kept, stack, out)?;
            }
            continue;
        }
        if let Some(rest) = directive("$define") {
            if open {
                let body = rest
                    .strip_prefix('(')
                    .and_then(|rest| rest.strip_suffix(')'))
                    .ok_or_else(|| format!("{} : $define sans fermeture", path.display()))?;
                if let Some((name, value)) = body.split_once('=') {
                    defines.retain(|(key, _)| key != name);
                    defines.push((name.to_string(), value.to_string()));
                } else {
                    defines.retain(|(key, _)| key != body);
                    defines.push((body.to_string(), String::new()));
                }
            }
            continue;
        }
        if let Some(rest) = directive("$if") {
            let body = rest
                .strip_prefix('(')
                .and_then(|rest| rest.strip_suffix(')'))
                .ok_or_else(|| format!("{} : $if sans fermeture", path.display()))?;
            // `A || B` : l'une des variables ; une seule variable ; 0 :
            // jamais fermé.
            let now = open
                && body.split("||").any(|name| {
                    let name = name.trim();
                    name != "0" && active(defines, name)
                });
            kept.push(now);
            local.push(kept.len() - 1);
            continue;
        }
        if trimmed.starts_with("$endif") {
            // Le $endif d'un fichier inclus ferme le $if de son englobant :
            // ne dépiler que ce que ce fichier a empilé ; le reste reste
            // ouvert pour l'appelant (il le fermera).
            if let Some(at) = local.pop() {
                kept.truncate(at);
            }
            continue;
        }
        if open {
            out.push_str(&substitute(line, defines));
            out.push('\n');
        }
    }
    stack.pop();
    Ok(())
}

/// Les `$Nom` d'une ligne remplacés par leur définition (eux-mêmes sinon).
fn substitute(line: &str, defines: &Defines) -> String {
    let mut out = line.to_string();
    for (name, value) in defines {
        if name.as_str() != "_WINNT_" {
            out = out.replace(&format!("${name}"), value);
        }
    }
    out
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
    // Des .o périmés d'un run passé ne doivent pas survivre : le testlist
    // généré ne référence que ce qui compile maintenant.
    if objs.is_dir() {
        fs::remove_dir_all(&objs).map_err(|e| e.to_string())?;
    }
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
        // Les annotations à vide (MinGW n'a pas sal.h) : no_sal2.h les
        // définit toutes ainsi (256), et ce qu'il oublie suit.
        "--include",
        "no_sal2.h",
        "-D__callback=",
        "-D__inner_callback=",
        "-D__drv_interlocked=",
        "-D_Interlocked_operand_=",
        "-D__inner_control_entrypoint(x)=",
        // Les macros SAL à argument que no_sal2.h n'a pas (elles prennent
        // une taille — vide, elles disparaissent).
        "-D_Deref_post_bytecap_(s)=",
        "-D_Out_cap_(n)=",
        "-D_In_bytecount_(n)=",
        "-D_In_count_(n)=",
        "-D_Out_bytecap_(n)=",
        "-D_Inout_bytecap_(n)=",
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
            .arg("--include")
            .arg("apitest-macros.h")
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
    // d'après les **symboles** des objets compilés — le nom d'un test est
    // celui de son START_TEST, qui peut différer du nom de son fichier
    // (`RtlQueryTimeZoneInformation.c` définit func_RtlQueryTimeZoneInfo).
    let testlist = out.join(format!("{module}-testlist.c"));
    let mut list = String::from(
        "/* Généré : la liste des tests qui compilent, pour le main de lot. */\n\
         #define STANDALONE\n#include <apitest.h>\n",
    );
    let mut entries = Vec::new();
    for object in &compiled {
        let symbols = Command::new("nm").arg(object).output().map_err(|e| format!("nm : {e}"))?;
        let text = String::from_utf8_lossy(&symbols.stdout);
        let mut found: Vec<String> = Vec::new();
        for line in text.lines() {
            // `00000000 T _func_Name`
            if let Some(rest) = line.split_whitespace().nth(1) {
                if let Some(name) = rest.strip_prefix("_func_") {
                    found.push(name.to_string());
                }
            }
        }
        for test in found {
            list.push_str(&format!("extern void func_{test}(void);\n"));
            entries.push(format!("    {{ \"{test}\", func_{test} }},"));
        }
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
    build_pseh(tree, &native_libs)?;
    build_ntdll_import(out)?;
    // Les imports : le ntdll des sondes (DbgPrint y est), la lib PSEH
    // statique, et les DLL de Mino par leurs libs MinGW — le chargeur de
    // Mino résout à l'exécution depuis les vraies (kernel32, msvcrt…).
    let mut link = Command::new("i686-w64-mingw32-gcc");
    link.args(["-nostartfiles", "-Wl,--kill-at", "-Wl,--subsystem,windows:5.1", "-Wl,-e,_WinMain@16", "-o"])
        .arg(&exe)
        .arg(&testmain_object)
        .arg(&testlist_object)
        .args(&compiled)
        // La lib ntdll de MinGW : les deux formes de chaque stdcall
        // (`Nom` et `Nom@N`) — le chargeur de Mino résout à l'exécution
        // depuis la ntdll.dll du payload.
        .args(["-lntdll"])
        .arg(native_libs.join("libpseh.a"))
        .args(["-lkernel32", "-luser32", "-lgdi32", "-lmsvcrt", "-ladvapi32"]);
    run(&mut link)?;
    println!("xtask: rostests {module} : {} ({} tests compilés)", name, compiled.len());
    Ok(exe)
}

/// La lib PSEH de ReactOS, compilée en statique (`libpseh.a`) : les tests
/// s'en servent pour `__try`/`__except` sous MinGW.
/// La lib d'import ntdll complète : les 1400 exports de la ntdll.dll du
/// payload, relus par objdump — les tests s'en servent tous (Rtl*, Ldr*,
/// Nt*), la sonde n'en exportait que cinq.
fn build_ntdll_import(out: &Path) -> Result<()> {
    let lib = out.join("libntdll_full.a");
    if lib.is_file() {
        return Ok(());
    }
    let dump = std::process::Command::new("objdump")
        .args(["-p", "third_party/reactos/0.4.16/reactos/system32/ntdll.dll"])
        .output()
        .map_err(|e| format!("objdump : {e}"))?;
    let text = String::from_utf8_lossy(&dump.stdout);
    let mut def = String::from(
        "LIBRARY ntdll.dll
EXPORTS
",
    );
    let mut count = 0;
    for line in text.lines() {
        let trimmed = line.trim_start();
        // `[  12] +base[  13]  0000 Name`
        let Some(rest) = trimmed.strip_prefix('[') else { continue };
        let Some((_, tail)) = rest.split_once("] ") else { continue };
        let mut parts = tail.rsplit(' ');
        let _hint = parts.next();
        let Some(name) = parts.next() else { continue };
        if !name.is_empty() && name != "+base[" {
            def.push_str(name);
            def.push('\n');
            count += 1;
        }
    }
    if count < 1000 {
        return Err(format!("ntdll.dll : {} exports seulement (objdump a-t-il lu ?)", count));
    }
    let def_path = out.join("ntdll-full.def");
    fs::write(&def_path, def).map_err(|e| e.to_string())?;
    run(Command::new("i686-w64-mingw32-dlltool").arg("--kill-at").arg("-d").arg(&def_path).arg("-l").arg(&lib))?;
    println!("xtask: rostests : libntdl_full.a ({count} exports)");
    Ok(())
}

fn build_pseh(tree: &Path, native_libs: &Path) -> Result<()> {
    let lib = native_libs.join("libpseh.a");
    if lib.is_file() {
        return Ok(());
    }
    let pseh = tree.join("sdk").join("lib").join("pseh");
    fs::create_dir_all(native_libs).map_err(|e| e.to_string())?;
    let out = native_libs.join("pseh");
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let mut objects = Vec::new();
    let mut sources: Vec<std::path::PathBuf> = vec![pseh.join("framebased.c"), pseh.join("dummy.c")];
    // Les entrées SEH2 en assembleur (i386) et le .c du gcchack ; pseh3.c
    // ne compile pas sans le générateur de ReactOS.
    let asm = pseh.join("i386");
    sources.extend([asm.join("framebased-gcchack.c")]);
    if let Ok(entries) = fs::read_dir(&asm) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "S") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    for source in sources {
        let stem = source.file_stem().expect("un nom").to_string_lossy().into_owned();
        let object = out.join(format!("{stem}.o"));
        run(Command::new("i686-w64-mingw32-gcc")
            .args(["-c", "-O2", "-w"])
            .arg(format!("-I{}", pseh.join("include").display()))
            .arg(&source)
            .arg("-o")
            .arg(&object))?;
        objects.push(object);
    }
    run(Command::new("i686-w64-mingw32-gcc-ar").arg("crs").arg(&lib).args(&objects))?;
    println!("xtask: rostests : libpseh.a");
    Ok(())
}

fn run(command: &mut Command) -> Result<()> {
    command
        .status()
        .map_err(|e| format!("{:?} : {e}", command.get_program()))?
        .success()
        .then_some(())
        .ok_or_else(|| format!("{:?} a échoué", command.get_program()))
}
