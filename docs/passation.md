# Notes de passation

Où en est le travail, ce qui vient ensuite, et comment le reprendre. Ces notes ne font pas foi (les documents 01 à
06 et `docs/compat/` font foi) ; elles servent à reprendre une session, depuis n'importe quel compte. Les mettre à
jour à chaque commit qui change l'état.

## État

- Jalon : **M3 terminé** (spike S1 réussi, ses trois critères cochés) ; prochain : **M4**
  ([05](05-feuille-de-route.md#m4--es-registre-systèmes-de-fichiers)).
- Branche de travail : `claude/new-session-696xfc`. Les PR se fusionnent dans `main` ; après une fusion, repartir de
  `origin/main` (avance rapide si la branche y est déjà incluse : `git merge-base --is-ancestor HEAD origin/main`).
- PR fusionnées : #29 (étape 1 du spike et ces notes), #30 (étapes 2 et 3). PR ouverte : #31 (étapes 4 et 5, la
  course du TID, le job CI `native`). Après sa fusion, repartir de `origin/main`.
- Observations du spike : [`compat/s1-ntdll.md`](compat/s1-ntdll.md).

## Spike S1 : les étapes

Critères de sortie (05) : un programme natif compilé avec MinGW et lié au `ntdll` de ReactOS affiche par `DbgPrint`
et se termine ; un test SEH (`__try`/`__except` sur une écriture en 0) passe ; la liste des appels système
rencontrés est publiée.

1. [x] **Sonde** : `ntoskrnl::userland::run_native_probe` démarre une image native construite dans le noyau
   (`pe::builder`, imports `DbgPrint` et `NtTerminateProcess`) sous le vrai `ntdll`, et journalise sa fin et les
   appels système faits (`sys::service_calls`). Résultat : `LdrInitializeThunk` lit `Peb->ProcessParameters`,
   absent, et faute.
2. [x] **Paramètres du processus** : `abi::process_parameters` (`RTL_USER_PROCESS_PARAMETERS` 32 bits, 0x290
   octets, assertions de layout) ; `ps::process_parameters::write` les écrit dans un processus (bloc normalisé,
   chaînes UTF-16 à la suite, répertoire courant sur `MAX_PATH` caractères ; environnement dans une allocation à
   lui, car `RtlSetEnvironmentVariable` le réalloue et libère l'ancien) et met leur adresse dans le PEB ;
   `ProcessParameters::system` pour un programme du système (chemins sous `C:\WINDOWS`, la racine de
   `KUSER_SHARED_DATA`). Résultat : `ntdll` lit le registre, puis s'arrête à la création du tas
   (`NtQuerySystemInformation` absent) ; statut `STATUS_NO_MEMORY`.
3. [x] **Services du chargeur** : la sonde va au bout (statut `0x5151`, `DbgPrint ... [s1] hello from a native
   process`) ; le scénario `userland` l'attend. Faits, chacun révélé par la sonde : 
   `NtQuerySystemInformation(SystemBasicInformation)` (`sys::system` ; classes non implémentées journalisées une
   fois par `sys::ClassReport`, tailles fixes par `sys::return_information`), les **tables NLS** (`ps::nls`, une
   section en lecture seule projetée dans chaque processus, adresses dans le PEB ; fichiers mis sur le disque par
   `xtask`, chargés par `userland::install_nls_tables`), `NtProtectVirtualMemory` (`sys::memory`). Les cas sont
   testés dans `loader_services_self_test` (`kernel/ntoskrnl/src/main.rs`, marqueur
   `[smoke] sys: the loader's services:`).
   Encore absents mais tolérés par `ntdll` (liste et arguments dans `compat/s1-ntdll.md`, étape 3), à faire quand
   ils comptent, selon `mino-syscall-impl` :
   - justes sans Io ni Cm : `NtQueryInformationProcess(ProcessCookie)` (seulement `NtCurrentProcess()`, 4 octets,
     cookie non nul tiré au premier appel, gardé dans l'EPROCESS), `NtSetInformationProcess(ProcessExecuteFlags)`
     (sur `EProcess::set_execute_options`), `NtFlushInstructionCache` (rien à vider sur x86 : vérifier le handle),
     `NtOpenDirectoryObject` (par Ob : `\KnownDlls` n'existe pas, `STATUS_OBJECT_NAME_NOT_FOUND`),
     `NtQueryDefaultLocale` (0x0409 tant qu'il n'y a pas de registre, à documenter) ;
   - en attente de Cm (`NtOpenKey`, `NtQueryValueKey`), d'Io (`NtOpenFile`, `NtQueryAttributesFile`), des
     événements à clé d'Ex (`NtCreateKeyedEvent`).
4. [x] **Programme MinGW** : `tests/native/s1hello.c` (C sans bibliothèque, `NtProcessStartup(PPEB)`), lié à
   `ntdll` par `tests/native/ntdll.def` (`dlltool --kill-at` ; ajouter à ce fichier chaque export appelé, avec ses
   octets d'arguments `@N` pour un `stdcall`). `xtask/src/native.rs` compile `tests/native/*` quand MinGW est là
   (`i686-w64-mingw32-gcc`, paquet `gcc-mingw-w64-i686`) ; les scénarios `requires = native` reçoivent les
   programmes sur le disque, ou sont sautés sans MinGW (la CI l'installe, job `native`). Le noyau lance ceux de
   `BOOT_PROGRAMS` (`ntoskrnl::userland::run_boot_programs`) avec le PEB en argument
   (`ps::create_thread_with_parameter`). Scénario `native` : le `DbgPrint` du programme et son statut `0x5152`.
   Critère de sortie coché dans 05.
5. [x] **Test SEH** : `tests/native/s1seh.c`, compilé par clang (`i686-pc-windows-msvc`, `-fasync-exceptions`)
   et lié par `lld-link` avec `tests/native/seh3.c`, notre `_except_handler3` (le `ntdll` de ReactOS ne l'exporte
   pas) ; bibliothèque d'import par `llvm-dlltool` depuis `ntdll.def`. Écriture en 0, filtre intérieur qui décline,
   `__finally` exécuté au déroulement (`RtlUnwind`), `__except` extérieur ; statut `0x5153`. Outils : `clang`,
   `lld`, `llvm` (la CI les installe dans le job `native`). En chemin, course corrigée dans Ps/Ke : le TID Ke d'un
   thread est publié avant qu'il soit prêt (`UserThreadStart::tid`), test `early_exit_self_test`.
6. [x] Critères cochés dans 05 : **le M3 est terminé**. L'ADR-002 reste « Proposée » (S1 réussi, S2 et S3 à
   faire). CLAUDE.md : jalon courant M4.

## Prochain jalon : M4 (E/S, registre, systèmes de fichiers)

But (05) : lancer `smss.exe`. Critères : `smss` démarre, lit `Session Manager`, crée les variables d'environnement
et `\KnownDlls` ; une valeur du registre persiste après un redémarrage ; un fichier créé sur `C:` reste lisible après
un redémarrage, sans erreur de `fsck.vfat`. Travaux (05) : Io (IRP, piles de périphériques, objets fichier, E/S
synchrones et asynchrones, ports de complétion) ; pilotes ATA, virtio-blk, partitions, FAT32 en lecture et écriture
(ADR-017) ; Cm et `libs/regf`, `tools/mkhive` (ADR-012) ; `\??\C:`, `\SystemRoot`, `\KnownDlls`. Méthode
recommandée : la même que S1 — lancer `smss.exe` de ReactOS sous la sonde (`userland::run_native`, avec ses
paramètres), lire où il s'arrête, et ajouter ce qu'il demande, composant par composant. Une session par composant
(CLAUDE.md) ; commencer par décider de l'ordre avec le mainteneur.

Services vus pendant S1 et encore absents (tolérés par `ntdll`, détail dans `compat/s1-ntdll.md`, étape 3) :
`NtQueryInformationProcess(ProcessCookie)`, `NtSetInformationProcess(ProcessExecuteFlags)`,
`NtFlushInstructionCache`, `NtOpenDirectoryObject`, `NtQueryDefaultLocale` (justes sans Io ni Cm) ; `NtOpenKey`,
`NtQueryValueKey` (Cm) ; `NtOpenFile`, `NtQueryAttributesFile` (Io) ; `NtCreateKeyedEvent` (Ex).

## Ensuite (hors jalon)

- Router #DB, #BR, #NP, #SS, #AC du mode utilisateur vers KiDispatchException (aujourd'hui seuls #DE, #BP, #UD,
  #GP, #PF et `int 2Ch`).
- KiDispatchException : si la pile utilisateur ne reçoit pas le contexte, le processus se termine avec le code de
  l'exception d'origine (XP lèverait plutôt l'exception de l'écriture sur la pile).
- Avant de supprimer l'ancien code (Win32 dans `syscall.rs`, stubs de `loader.rs`, `launcher.rs`, `win32/*`,
  `directx/*`), extraire la connaissance utile dans `docs/compat/` (audit §5).

## Reprendre

```bash
cargo xtask fetch-userland                                  # ReactOS 0.4.16 (SourceForge), une fois
cargo xtask test --boot --scenario userland --cpu intel     # la sonde ; journal dans target/xtask/boot/userland-intel/
cargo xtask lint && cargo xtask test                        # avant chaque commit poussé
```

- Lire la sonde : `grep -h "\[s1\]\|sys: \|DbgPrint" target/xtask/boot/userland-intel/*.log`. Un service sans
  handler est journalisé à son premier appel avec l'appelant et les arguments ; une exception qui termine un
  processus, avec son adresse et ses paramètres.
- Situer une adresse de `ntdll` (base `0x7c920000`) :
  `llvm-objdump -d --no-show-raw-insn --start-address=0x... --stop-address=0x... third_party/reactos/0.4.16/reactos/system32/ntdll.dll`
  (le symbole affiché est l'export le plus proche, pas forcément la fonction) ; exports :
  `llvm-readobj --coff-exports ...`.
- Points d'entrée du `ntdll` épinglé : `LdrInitializeThunk` `0x7c92f358`, `KiUserExceptionDispatcher`
  `0x7c92f46e`, `KiUserApcDispatcher` `0x7c92f381`.
- Une exception que `ntdll` traite elle-même (SEH) ne laisse pas de trace : pour la voir, ajouter
  temporairement dans `raise` (`kernel/ntoskrnl/src/sys/exceptions.rs`) un
  `log::warn!("TEMP exception {code} at {:#x} esp {:#x} {parameters:x?}", frame.rip, frame.rsp);`, à retirer avant
  de committer.
- ReactOS sert de spécification (ses sources `ntdll`, en lecture) ; on ne porte pas son code noyau. Jamais de code
  Microsoft.
- Réseau : SourceForge passe ; les pages de publication et l'API de GitHub, et reactos.org, sont bloquées.

## Pratiques de la session

- Commits en français, `<composant>: <résumé à l'impératif>`, un sujet chacun ; chaque commit intermédiaire compile
  sans warning (le vérifier dans un worktree :
  `git worktree add --detach target/work/wt <commit>` puis
  `CARGO_TARGET_DIR=../wt-target cargo build -p ntoskrnl --target x86_64-unknown-none --profile kernel`).
- Tests par mutation des nouveaux tests : casser à la main la ligne testée, relancer le scénario, vérifier qu'il
  échoue, rétablir. Un script le fait pour une liste de mutations JSON `[nom, [[chemin, ancien, nouveau], ...]]`
  (`target/work/mutate.py`, hors dépôt : à réécrire au besoin, une vingtaine de lignes autour de
  `cargo xtask test --boot --scenario NOM --cpu CPU`).
- Un symptôme contourné est documenté ; un bogue corrigé vient avec le test qui l'aurait détecté.
