# Notes de passation

Où en est le travail, ce qui vient ensuite, et comment le reprendre. Ces notes ne font pas foi (les documents 01 à
06 et `docs/compat/` font foi) ; elles servent à reprendre une session, depuis n'importe quel compte. Les mettre à
jour à chaque commit qui change l'état.

## État

- Jalon courant : **M4** ([05](05-feuille-de-route.md#m4--es-registre-systèmes-de-fichiers)) ; M3 terminé
  (spike S1 réussi). Étapes 0, 1, 2 et 5 du M4 faites : la sonde `smss`, le registre en lecture, les répertoires
  d'Ob, Io (le volume système, les fichiers, les sections de `\KnownDlls`) ; ensuite, `SystemProcessorInformation`
  puis l'écriture dans le registre (étape 4), les prochains murs de `smss`.
- Branche de travail : `claude/m4-io`, partie d'`origin/main` après la fusion de #32. Les PR se fusionnent dans
  `main` ; après une fusion, repartir de `origin/main` (avance rapide si la branche y est déjà incluse :
  `git merge-base --is-ancestor HEAD origin/main`).
- PR fusionnées : #29, #30, #31 (spike S1) et #32 (étapes 0 à 2 du M4). L'étape 5 (Io) est sur `claude/m4-io`, PR à
  ouvrir. Après chaque fusion, repartir de `origin/main` (`git fetch origin main && git merge --ff-only origin/main`,
  ou `git merge origin/main` si la branche a des commits non fusionnés : jamais de réécriture).
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

## Jalon courant : M4 (E/S, registre, systèmes de fichiers)

But (05) : lancer `smss.exe`. Critères : `smss` démarre, lit `Session Manager`, crée les variables d'environnement
et `\KnownDlls` ; une valeur du registre persiste après un redémarrage ; un fichier créé sur `C:` reste lisible après
un redémarrage, sans erreur de `fsck.vfat`. Travaux (05) : Io, pilotes (ATA, virtio-blk, partitions, FAT32 en
lecture et écriture, ADR-017), Cm et `libs/regf`, `tools/mkhive` (ADR-012), `\??\C:`, `\SystemRoot`,
`\KnownDlls`.

0. [x] **Sonde `smss.exe`** (`docs/compat/m4-smss.md`, scénario `smss`, feature `test-smss`,
   `userland::run_smss_probe`) : le noyau lance le `smss.exe` de ReactOS comme premier processus et journalise ses
   appels (préfixe `[m4]`). Ajouts pour la sonde : `DbgPrompt` reçoit `i` faute de débogueur (sans quoi `RtlAssert`
   boucle), `NtQueryVirtualMemory` (`MemoryBasicInformation`). Résultat : `smss` s'arrête au **registre**
   (`RtlQueryRegistryValues` sur `Session Manager`) ; avant, il demande `ThreadBreakOnTermination`, `NtCreatePort`
   (LPC), `NtCreateThread` et `NtWriteVirtualMemory`, `NtCreateEvent`, toutes en échec toléré.
1. [x] **Registre en lecture** (ordre choisi avec le mainteneur : le registre d'abord, LPC laissé au M5) :
   `libs/regf` (lecture d'une ruche en mémoire ; constructeur sous la feature `builder`), `kernel/cm` (type `Key`,
   `\REGISTRY` avec `MACHINE` et `USER`, ruches montées en lecture, lien `CurrentControlSet`, `cm::info` pour les
   classes d'information), Ob (nom relatif à une racine à procédure *parse*), `abi::object::ObjectAttributes32`,
   `abi::registry`, services `NtOpenKey`, `NtQueryKey`, `NtEnumerateKey`, `NtQueryValueKey`,
   `NtEnumerateValueKey` (`sys::registry`, capture dans `sys::object`). La ruche montée est celle que ReactOS a
   générée (`system32/config/system`, mise sur le disque par `xtask` ; `userland::mount_system_hive`) : `tools/mkhive`
   reste à faire (ADR-012), à partir des `.inf` de ReactOS, absents de l'arborescence extraite (à chercher dans
   l'ISO). Test : `registry_self_test` (une ruche construite et montée en `\REGISTRY\MACHINE\MinoTest`).
   Résultat : `smss` lit `Session Manager`, puis s'arrête à `\??` (`NtOpenDirectoryObject`).
2. [x] **Services de répertoires d'Ob** : `NtCreateDirectoryObject`, `NtOpenDirectoryObject`,
   `NtCreateSymbolicLinkObject`, `NtOpenSymbolicLinkObject` (`sys::object` : `open_by_name`, `create_named` ;
   un lien ouvert comme lien n'est pas suivi). Test : `object_directory_self_test`. Résultat : `smss` crée ses
   répertoires et ses liens de `DOS Devices`, puis s'arrête à `NtOpenFile` sur `C:\WINDOWS\system32` (KnownDlls) :
   **Io est le prochain mur**.
3. [ ] **Ex et Ps** que `smss` demande : `NtCreateEvent`, `NtCreateThread` et `NtWriteVirtualMemory`,
   `ThreadBreakOnTermination` (avec l'arrêt `CRITICAL_OBJECT_TERMINATION` : la sonde ne devra plus terminer `smss`).
4. [ ] **Écriture dans le registre** (`NtDeleteValueKey`, `NtSetValueKey`, `NtCreateKey`), en mémoire d'abord, et
   `tools/mkhive`.
5. [x] **Io** (`docs/compat/m4-smss.md`, étape 3) : le disque RAM de démarrage tient lieu du volume système.
   `tools/mkfat` écrit des sous-répertoires (`HOTE:DIR/NOM.EXT`, composants 8.3) et des répertoires sur plusieurs
   clusters ; `cargo xtask` range l'espace utilisateur dans `WINDOWS/SYSTEM32` avec les 21 KnownDLLs
   (`xtask/src/userland.rs`, `KNOWN_DLLS`) ; le chargeur accepte 64 Mio de disque RAM. `kernel/io` : `io::volume`
   (FAT32 monté, résolution sans casse, erreurs d'un pilote d'XP, dates FAT en temps NT), type `Device` (procédure
   *parse* : IopParseDevice), type `File` (nom relatif à un répertoire ouvert : IopParseFile ; position, mode
   synchrone, informations), `check_open` (disposition et options) ; `mount_boot_volume` : `\Device\Ramdisk0`,
   `\GLOBAL??\C:`, `\SystemRoot`. Le noyau lit ntdll, les NLS, la ruche et `smss` par Io (`userland::read_boot_file`).
   Services (`sys::file`, `sys::section`) : NtCreateFile (ouverture seule), NtOpenFile, NtQueryAttributesFile,
   NtQueryFullAttributesFile, NtQueryInformationFile (Basic, Standard, Position, NetworkOpen),
   NtQueryVolumeInformationFile (FileFsDeviceInformation), NtCreateSection (fichier d'échange, données, image),
   NtOpenSection, NtMapViewOfSection, NtUnmapViewOfSection. Tests : `kernel/io/src/tests.rs` (hôte),
   `file_self_test` et `section_service_self_test` (depuis le mode utilisateur), vérifiés par mutation.
   Résultat : `smss` met 21 sections d'image dans `\KnownDlls`, puis s'arrête à
   `NtQuerySystemInformation(SystemProcessorInformation)`.
   Pas encore : IRP et piles de périphériques (les lectures vont droit au volume), noms longs FAT, écriture FAT
   (critère 3), partage, création ; une section de fichier copie le fichier (deux copies de `shell32` quand deux
   sections le tiennent : à partager par fichier, comme les SectionObjectPointers d'XP).
6. [ ] **`SystemProcessorInformation`** (classe 1 de NtQuerySystemInformation, 12 octets : architecture, niveau,
   révision, fonctions ; depuis `hal::cpuid`), puis l'étape 4 : `SmpCreateDynamicEnvironmentVariables` ouvre
   `Session Manager\Environment` en `GENERIC_WRITE` et y écrit `OS`, `PROCESSOR_*` (NtSetValueKey).
7. [ ] **LPC**, seulement si `smss` ne peut aller plus loin sans.
   Méthode : après chaque composant, relancer `cargo xtask test --boot --scenario smss`, lire le journal `[m4]`,
   mettre à jour `docs/compat/m4-smss.md` et les marqueurs du scénario (`expect` de l'endroit où il s'arrête).

Services vus pendant S1 et encore absents (tolérés par `ntdll`, détail dans `compat/s1-ntdll.md`, étape 3) :
`NtQueryInformationProcess(ProcessCookie)`, `NtSetInformationProcess(ProcessExecuteFlags)`,
`NtFlushInstructionCache`, `NtQueryDefaultLocale` (justes sans Io ni Cm) ; `NtCreateKeyedEvent` (Ex). `NtOpenKey`,
`NtQueryValueKey`, `NtOpenDirectoryObject`, `NtOpenFile` et `NtQueryAttributesFile` sont faits.

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
- ReactOS sert de spécification (ses sources `ntdll`, `smss`, en lecture) ; on ne porte pas son code noyau. Jamais
  de code Microsoft. Les sources, hors du dépôt, par le proxy Git (sans l'API de GitHub) :
  `git clone --filter=blob:none --no-checkout --depth 1 --branch 0.4.16 https://github.com/reactos/reactos ../reactos-src`,
  puis `git sparse-checkout set --no-cone base/system/smss dll/ntdll sdk/lib/rtl` et `git checkout`.
- Réseau : SourceForge et les clones Git de GitHub passent ; les pages de publication et l'API de GitHub, et
  reactos.org, sont bloquées.
- Le scénario `smss` : `cargo xtask test --boot --scenario smss --cpu intel`, journal `[m4]` dans
  `target/xtask/boot/smss-intel/serial.log` ; `[m4] \KnownDlls:` dit ce que `smss` a mis dans `\KnownDlls`.

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
