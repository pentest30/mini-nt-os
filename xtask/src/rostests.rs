//! Les `rostests` de ReactOS (`modules/rostests/apitests`), le dernier
//! critère du M5 : les apitests `ntdll` et `kernel32` compilés par
//! [`build`] et lancés par les scénarios `rostests` (ntdll) et
//! `rostests-kernel32`, leur bilan lu du port série et jugé ([`judge`]) :
//! sous le plancher du scénario (`apitests-floor`), il échoue ; le seuil du
//! jalon ([`THRESHOLD`]) dit si le critère du M5 est atteint.
//!
//! La compilation est autonome : MinGW, contre une copie du PSDK de
//! l'arbre 0.4.16 où `winnt.h` — que ReactOS génère au build — est généré
//! ici ([`generate_winnt`]). Chaque module donne deux programmes : le
//! **coureur** (`NTAPIRUN.EXE`, `K32APIRUN.EXE` ; console, le `main` de
//! `wine/test.h` : `argv[1]` est le test, son code de sortie ses échecs) et
//! le **pilote** (`NTAPITST.EXE`, `K32APITST.EXE` ; `rostests-src/testdriver.c`),
//! commande initiale de `smss` à la place de winlogon, qui lance chaque test
//! de la liste dans un coureur et relaie sa sortie et son verdict par
//! `DbgPrint`. Les tests qui ne compilent pas sont écartés, listés — le
//! seuil du jalon s'entend sur ce qui tourne, et le nombre d'écartés fait
//! partie du suivi.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::native;
use crate::{Result, Workspace};

/// Le bilan d'une ligne `[apitest] TOTALS: tests=N failures=N skipped=N`
/// — (tests, échecs, écartés) ; `None` pour toute autre ligne.
pub fn parse_totals(line: &str) -> Option<(u32, u32, u32)> {
    let at = line.find("[apitest] TOTALS:")?;
    let rest = &line[at + "[apitest] TOTALS:".len()..];
    let mut fields = [0u32; 3];
    for (at, field) in rest.split_whitespace().enumerate() {
        let value = field.split('=').nth(1)?.parse().ok()?;
        fields[at] = value;
    }
    Some((fields[0], fields[1], fields[2]))
}

/// Ce qui manque pour construire le banc : l'arbre des sources
/// ([`fetch`]), ou le premier outil (celui des sondes natives, le même
/// MinGW).
pub fn missing(ws: &Workspace) -> Option<String> {
    if !source_tree(ws).join("modules").is_dir() {
        return Some("the ReactOS 0.4.16 tree (cargo xtask rostests-fetch)".into());
    }
    native::missing_tool().map(String::from)
}

/// Le seuil du jalon M5 : la part des tests qui passent (un test passe
/// quand son coureur rend 0 : aucun échec, todo compris). Fixé au moment du
/// jalon ; le suivi se fait dans le temps, par le plancher de chaque
/// scénario ([`judge`]).
pub const THRESHOLD: f64 = 0.50;

/// Le bilan d'un banc (`tests` lancés, `failures` en échec) jugé : `Err`
/// sous `floor`, le plancher du scénario (les tests qui passaient à la
/// dernière mesure : il ne baisse pas) ; sinon `Ok`. Le rapport dit aussi
/// où en est le critère du M5 ([`THRESHOLD`]), et si le plancher peut
/// monter.
pub fn judge(tests: u32, failures: u32, floor: u32) -> std::result::Result<String, String> {
    let passing = tests.saturating_sub(failures);
    let share = f64::from(passing) / f64::from(tests.max(1));
    let criterion = if share >= THRESHOLD { "critère du M5 atteint" } else { "sous le seuil du M5" };
    let report = format!(
        "apitests {passing}/{tests} passent ({:.0} %), plancher {floor}, seuil {:.0} % : {criterion}",
        share * 100.0,
        THRESHOLD * 100.0
    );
    if passing < floor {
        Err(format!("{report} ; sous le plancher"))
    } else if passing > floor {
        Ok(format!("{report} ; le plancher peut monter à {passing}"))
    } else {
        Ok(report)
    }
}

/// Les options de ReactOS pour tout code i386 compilé par GCC
/// (`sdk/cmake/gcc.cmake`). PSEH2 en dépend : son `_SEH2GlobalUnwind` pousse
/// quatre mots puis la trame cible, un opérande que GCC peut adresser par ESP
/// quand il omet le pointeur de trame — RtlUnwind reçoit alors une mauvaise
/// trame, ne la trouve pas dans la chaîne et lève STATUS_UNWIND : chaque test
/// dont un `__except` attrapait une exception mourait ainsi (`c0000027`).
const I386_FLAGS: [&str; 3] = ["-fno-optimize-sibling-calls", "-fno-omit-frame-pointer", "-mstackrealign"];

/// Les avertissements dont GCC 14 fait des erreurs, imposés aux tests quel
/// que soit le GCC : un test qui appelle une fonction que le banc ne déclare
/// pas (`ok_size_t`, `wine_dbgstr_w`, `IsReactOS`…) est écarté à la
/// compilation, au lieu de compiler sous GCC 13 et de faire échouer le lien
/// de tout le module. Les tests qui tournent sont ainsi les mêmes sous les
/// deux.
const GCC14_ERRORS: [&str; 4] = [
    "-Werror=implicit-function-declaration",
    "-Werror=implicit-int",
    "-Werror=int-conversion",
    "-Werror=incompatible-pointer-types",
];

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
/// n'accepte que lui) et leurs coureurs, sur le disque de démarrage des
/// scénarios. Rend les fichiers ajoutés au ramdisk (`HOST:FAT_PATH`), ou
/// `None` s'il manque l'arbre ou un outil ([`missing`]) : le scénario est
/// alors sauté.
pub fn build(ws: &Workspace) -> Result<Option<Vec<String>>> {
    let tree = source_tree(ws);
    if missing(ws).is_some() {
        return Ok(None);
    }
    let out = ws.target.join("xtask").join("rostests");
    let sdk = prepare_sdk(&tree, &out)?;
    let mut files = Vec::new();
    for module in MODULES {
        let (driver, runner) =
            if module == "ntdll" { ("NTAPITST.EXE", "NTAPIRUN.EXE") } else { ("K32APITST.EXE", "K32APIRUN.EXE") };
        let (driver_exe, runner_exe) = compile_module(ws, &tree, &sdk, module, &out, driver, runner)?;
        files.push(format!("{}:{}", driver_exe.display(), driver));
        files.push(format!("{}:{}", runner_exe.display(), runner));
    }
    Ok(Some(files))
}

/// La copie du SDK : psdk recopié avec le winnt.h **généré**, les en-têtes
/// qu'il inclut sans chemin, et le shim des macros de test.
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

/// Un module : ses .c et son testlist réduit, liés en coureur ; la même
/// liste, sans les fonctions, liée au pilote.
fn compile_module(
    ws: &Workspace,
    tree: &Path,
    sdk: &Path,
    module: &str,
    out: &Path,
    name: &str,
    runner_name: &str,
) -> Result<(PathBuf, PathBuf)> {
    let apitests = tree.join("modules").join("rostests").join("apitests");
    let module_dir = apitests.join(module);
    let objs = out.join(module);
    // Des .o périmés d'un run passé ne doivent pas survivre : le testlist
    // généré ne référence que ce qui compile maintenant.
    if objs.is_dir() {
        fs::remove_dir_all(&objs).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(&objs).map_err(|e| e.to_string())?;
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
        // Une annotation SAL 1 de rtlfuncs.h (RtlQueryTagHeap) que no_sal2.h
        // n'a pas : le sal.h des MinGW récents la définit, celui de
        // mingw-w64 11 (Ubuntu 24.04) non, et sans elle ntndk.h ne compile
        // plus — presque tous les tests étaient écartés.
        "-D_Ret_opt_z_=",
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
        // Les diagnostics du test dans son journal, à côté de son objet :
        // sans `-w` (qui l'emporterait sur les -Werror), ils sont des
        // milliers.
        let log = fs::File::create(object.with_extension("log")).map_err(|e| e.to_string())?;
        let mut command = Command::new("i686-w64-mingw32-gcc");
        command
            .args(["-c", "-O1", "-D_WIN32_WINNT=0x0501"])
            .args(GCC14_ERRORS)
            .args(I386_FLAGS)
            .args(defines)
            .arg("--include")
            .arg("apitest-macros.h")
            .arg(format!("-I{}", module_dir.display()))
            .args(&includes)
            .arg(source)
            .arg("-o")
            .arg(&object)
            .stderr(log);
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
            // `00000000 T _func_Name` — l'adresse, le type, le nom.
            if let Some(name) = line.split_whitespace().nth(2) {
                if let Some(test) = name.strip_prefix("_func_") {
                    found.push(test.to_string());
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
        .args(["-c", "-O1", "-w", "-D_WIN32_WINNT=0x0501"])
        .args(I386_FLAGS)
        .args(defines)
        .arg(format!("-I{}", module_dir.display()))
        .args(&includes)
        .arg(&testlist)
        .arg("-o")
        .arg(&testlist_object))?;
    // Le pilote : la même liste, mais seule sa partie table lui sert — le
    // cadre wine est coupé (STANDALONE, apitest.h) : la struct y est
    // redéfinie ; il lance chaque test dans un processus fils.
    let driver_list = out.join(format!("{module}-driver.c"));
    let driver_source = fs::read_to_string(&testlist).map_err(|e| e.to_string())?;
    // La table du pilote ne tient que les noms (les fonctions vivent dans
    // le coureur) : ses déclarations extern sautent, ses entrées perdent
    // leur fonction.
    let list_only = driver_source
        .split_once("#include <apitest.h>")
        .map(|(_, rest)| rest)
        .unwrap_or(driver_source.as_str())
        .lines()
        .filter(|line| !line.starts_with("extern void func_"))
        .map(|line: &str| match line.find(", func_") {
            Some(at) => format!("{}}},", &line[..at]),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    let driver = format!(
        "#include <windows.h>\nstruct test {{ const char *name; void (*func)(void); }};\n{list_only}\n{}",
        include_str!("../rostests-src/testdriver.c").replace("NTAPIRUN.EXE", runner_name)
    );
    fs::write(&driver_list, driver).map_err(|e| e.to_string())?;

    let exe = out.join(name);
    let native_libs = ws.target.join("xtask").join("native");
    build_pseh(tree, &native_libs)?;
    // Le coureur : le main de wine/test.h (argv[1] = le test, son code de
    // sortie = ses échecs) — le pilote l'attend avec un délai.
    let runner = out.join(runner_name);
    let stubs_object = objs.join("runner-stubs.o");
    run(Command::new("i686-w64-mingw32-gcc")
        .args(["-c", "-O1", "-w"])
        .args(I386_FLAGS)
        .arg(ws_shim("runner-stubs.c"))
        .arg("-o")
        .arg(&stubs_object))?;
    // Le coureur est une application console au CRT de MinGW : le main de
    // wine/test.h y lit argv (argv[1] = le test) — le pilote le lance par
    // CreateProcess et lit son code de sortie.
    let mut link = Command::new("i686-w64-mingw32-gcc");
    link.args(["-Wl,--kill-at", "-Wl,--subsystem,console:5.1", "-o"])
        .arg(&runner)
        .arg(&testlist_object)
        .arg(&stubs_object)
        .args(&compiled)
        .args(["-lntdll"])
        .arg(native_libs.join("libpseh.a"))
        .args(["-lkernel32", "-luser32", "-lgdi32", "-lmsvcrt", "-ladvapi32"]);
    run(&mut link)?;
    // Le pilote : la liste embarquée, chaque test dans un fils.
    let driver_object = objs.join("driver.o");
    run(Command::new("i686-w64-mingw32-gcc")
        .args(["-c", "-O1", "-w"])
        .args(I386_FLAGS)
        .arg(&driver_list)
        .arg("-o")
        .arg(&driver_object))?;
    let mut driver_link = Command::new("i686-w64-mingw32-gcc");
    driver_link
        .args(["-nostartfiles", "-Wl,--kill-at", "-Wl,--subsystem,windows:5.1", "-Wl,-e,_WinMain@16", "-o"])
        .arg(&exe)
        .arg(&driver_object)
        .args(["-lntdll", "-lkernel32", "-luser32", "-lmsvcrt"]);
    run(&mut driver_link)?;
    println!("xtask: rostests {module} : {} + {} ({} tests compilés)", name, runner_name, compiled.len());
    Ok((exe, runner))
}

/// La lib PSEH de ReactOS, compilée en statique (`libpseh.a`) : les tests
/// s'en servent pour `__try`/`__except` sous MinGW.
fn build_pseh(tree: &Path, native_libs: &Path) -> Result<()> {
    // Refaite à chaque construction (quelques fichiers) : une copie d'avant
    // ces options aurait gardé le défaut qu'elles corrigent.
    let lib = native_libs.join("libpseh.a");
    if lib.is_file() {
        fs::remove_file(&lib).map_err(|e| format!("{} : {e}", lib.display()))?;
    }
    let pseh = tree.join("sdk").join("lib").join("pseh");
    fs::create_dir_all(native_libs).map_err(|e| e.to_string())?;
    let out = native_libs.join("pseh");
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let mut objects = Vec::new();
    let mut sources: Vec<PathBuf> = vec![pseh.join("framebased.c"), pseh.join("dummy.c")];
    // Les entrées SEH2 en assembleur (i386) et le .c du gcchack ; pseh3.c
    // ne compile pas sans le générateur de ReactOS.
    let asm = pseh.join("i386");
    sources.extend([asm.join("framebased-gcchack.c")]);
    for entry in fs::read_dir(&asm).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "S") {
            sources.push(path);
        }
    }
    sources.sort();
    for source in sources {
        let stem = source.file_stem().expect("un nom").to_string_lossy().into_owned();
        let object = out.join(format!("{stem}.o"));
        run(Command::new("i686-w64-mingw32-gcc")
            .args(["-c", "-O2", "-w"])
            .args(I386_FLAGS)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_totals_line_only() {
        let line = "[INFO] DbgPrint 28.48: [apitest] TOTALS: tests=84 failures=60 skipped=0";
        assert_eq!(parse_totals(line), Some((84, 60, 0)));
        assert_eq!(parse_totals("[INFO] DbgPrint 28.48: [apitest] NtReadFile: pass"), None);
        assert_eq!(parse_totals("[apitest] TOTALS: tests=many"), None);
    }

    #[test]
    fn a_bench_fails_below_its_floor_only() {
        assert!(judge(84, 60, 25).is_err(), "24 pass, 25 did");
        let report = judge(84, 59, 25).expect("25 pass, as before");
        assert!(report.contains("25/84") && report.contains("sous le seuil du M5"), "{report}");
        assert!(!report.contains("peut monter"), "{report}");
        let report = judge(84, 40, 25).expect("more pass");
        assert!(report.contains("critère du M5 atteint") && report.contains("peut monter à 44"), "{report}");
        assert!(judge(0, 0, 0).is_ok(), "nothing compiled, nothing promised");
        assert!(judge(10, 0, 11).is_err(), "fewer tests than the floor");
    }
}
