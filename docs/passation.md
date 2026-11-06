# Notes de passation

Où en est le travail, ce qui vient ensuite, et comment le reprendre. Ces notes ne font pas foi (les documents 01 à
06 et `docs/compat/` font foi) ; elles servent à reprendre une session, depuis n'importe quel compte. Les mettre à
jour à chaque commit qui change l'état.

## État

- Jalon courant : **M5** ([05](05-feuille-de-route.md#m5--mode-console-puis-spike-s2)) ; **M4 terminé** : ses trois
  critères de sortie sont cochés (`smss` crée ses variables d'environnement et `\KnownDlls` ; un fichier de `C:` et une
  valeur du registre se relisent après un redémarrage, scénarios `persistence` et `registry-persistence`, `fsck.vfat`
  propre). Ce que le M4 laisse à faire est listé ci-dessous (« Dettes du M4 »). Au M5, `smss` crée sa session et
  lance `csrss.exe`, qui protège son processus (Se), crée sa section partagée (Mm), charge `basesrv`, puis `winsrv`
  (USER sur le win32k minimal, puis la console `consrv`), se connecte à `smss` par LPC (et `smss` à lui) : **`csrss`
  est démarré**. `smss` lance ensuite sa commande initiale, `winlogon.exe` (étape 9, en cours), garde un handle
  sur son processus (NtDuplicateObject) et le confie à `csrss`, qui en fait un processus CSR ; `winlogon` se
  connecte à `csrss` (vue `SEC_NO_CHANGE` de sa section partagée) et à win32k, s'inscrit comme processus de logon,
  crée la station interactive `WinSta0` et ses bureaux, s'y place (la fenêtre du bureau d'entrée est montrée et peinte
  par WM_PAINT : premier affichage, GDI et `gopfb`), charge sa disposition de clavier (dont la page de code vient
  d'un rappel de `user32` : KeUserModeCallback), puis s'arrête à son serveur RPC (un tube nommé :
  NtCreateNamedPipeFile, Io) : [`compat/m5-csrss.md`](compat/m5-csrss.md), étapes 15 à 23.
- La sonde console, étape 8 (M5, [`compat/m5-console.md`](compat/m5-console.md)) : ce que `dir` affiche autour des
  noms (en-tête du volume, dates, place libre ; NtQueryDefaultLocale, FileFsVolume/Size/FullSizeInformation,
  FileNameInformation, FileBasicInformation en écriture ; dates de FAT) : **le critère de `cmd.exe` interactif du M5
  est coché**. Sur `claude/new-session-696xfc`, par-dessus l'étape 7 (`claude/m5-cmd`, PR #66). L'étape 6 (le clavier
  jusqu'aux fenêtres) est la PR #65, l'étape 5 (le texte de la console peint) la PR #64 ; les étapes 3 (Sleep(0) :
  **le critère des 8 threads du M5 est coché**) et 4 (la fenêtre console montrée) sont les PR #62 et #63. Une branche
  locale `backup/thread-is-terminated-stale` garde un travail périmé d'une session antérieure (remplacé par `main`) :
  à supprimer.
- Branches de travail : `claude/m5-se` (l'étape 2 du M5, PR à ouvrir), partie de `main` après la fusion de #35, puis,
  chacune par-dessus la précédente, `claude/m5-mm` (l'étape 3), `claude/m5-boot` (l'étape 4), `claude/m5-services`
  (l'étape 5), `claude/m5-ex` (l'étape 8), `claude/m5-win32k` (l'étape 6) et `claude/m5-lpc` (l'étape 7) ;
  l'étape 9 sur `claude/new-session-696xfc`, partie de `main` après la fusion de #43. Les PR se fusionnent dans `main` ; après une fusion, repartir de `origin/main` (avance rapide si la
  branche y est déjà incluse : `git merge-base --is-ancestor HEAD origin/main`).
- Chantier « installation et formatage » (parallèle à la ligne GUI, crates disjointes ; plan en F1–F7, ADR-022) :
  `claude/libs-fatfs`, par-dessus `claude/new-session-696xfc` puis `main` (après la fusion de #57), en fait les
  étapes F2 et F1 — la crate `libs/fatfs` (`no_std`, avec `alloc`) tient la construction d'image FAT32 déplacée de
  `tools/mkfat` sans un changement d'octet (seul changement : les `use` de `alloc`, le `no_std` l'exigeant) ;
  `mkfat` ne garde que ses arguments et ses programmes de test, et les tests croisés (`fatfs` construit,
  `io-manager` relit, `fsck.vfat` valide) ont suivi la crate ; **F1, `NtQueryDirectoryFile`** (le `FindFirstFile`
  du vrai kernel32, scénario `dir` : motif `?`/`*` et méta-caractères de DOS, reprise du scan, motif que le file
  object garde, ordre des arguments de ReactOS, `ShortNameLength` en octets — détails dans
  [`compat/io-install.md`](compat/io-install.md)).
  Vérifié sur un hôte **Windows** (rustup, nightly épinglé, Build Tools VS, QEMU 11, MSYS2) : **tous les scénarios
  boot passent**, `gui` compris (22 boot runs) ; `cargo check -p fatfs -p mkfat` et `cargo test --release -p fatfs
  -p mkfat` verts (10/10 ; `fsck.vfat` absent de l'hôte : sauté, comme prévu) ; le noyau et le chargeur y compilent
  (`cargo build -p ntoskrnl -p mino-loader --profile kernel`) ; l'userland ReactOS 0.4.16 y est en place
  (`third_party/reactos/0.4.16` : l'ISO vient de l'archive au SHA-256 épinglé, le tampon `.fetched` écrit à la
  main). Pour cela, `xtask` tourne sous Windows : son monitor HMP passe par un port TCP de localhost (`Monitor`,
  `screen.rs`) là où les sockets Unix n'existent pas, et le chemin du `screendump` est quoté (un répertoire du run
  peut tenir un espace, sur tout hôte) ; les compilateurs natifs viennent de MSYS2 (`mingw-w64-i686-gcc`, et
  `clang`/`lld`/`llvm` en x86_64 — les paquets i686 ont disparu ; des copies `i686-w64-mingw32-dlltool` et
  `-as` sont posées à côté de `dlltool` et `as`, que le préfixe d'`argv[0]` fait chercher), et QEMU par la variable
  `QEMU`. Reste la limite de l'hôte : le profil dev de `hal` n'y compile pas (le
  `#[thread_local]` d'`irql.rs` et le codegen COFF/TLS du nightly : « offset is not a multiple of 16 » ; le profil
  release passe ; même racine que le commentaire de `.cargo/config.toml` pour le noyau).
  Reprise Linux sur **`claude/libs-fatf`** :
  `cargo check --workspace` et `cargo test --workspace` passent ; l'image du
  `mkfat` avant l'extraction (parent de `834686a`) et celle de la branche sont
  identiques octet par octet (SHA-256
  `8bd13156c1b240a4c888e8bee7a68d9cf7c5b81b1960ff561efe3af7e2dab095`, fichiers
  standard ; même comparaison réussie avec des sous-répertoires, noms longs,
  fichier vide et fichier de plusieurs clusters). **F3, la bibliothèque de formatage, est faite** : `fatfs::format`,
  `WriteSectors`, géométrie vérifiée avant écriture, formatage rapide en mémoire
  constante, en-têtes communs à l'image, erreurs d'E/S propagées ; tests hôte,
  relecture par Io et `fsck.vfat`, quatre mutations détectées (voir
  `compat/io-install.md`). Validation Linux : `cargo xtask lint` sans warning,
  721 tests hôte réussis et 28 démarrages QEMU réussis (les 6 avec captures
  relancés avec accès aux sockets locales du moniteur), aucun scénario sauté ;
  `cargo check -p fatfs --target x86_64-unknown-none` passe.
  F1 est déjà fait sur cette branche.
  **F4 est fait sur cette branche** : `libs/gpt` lit et écrit les tableaux,
  leurs CRC et le MBR protecteur ; récupération par une copie valide,
  conflits refusés. `io::partition` expose une vue bornée et monte la première
  partition Basic Data (EFI ignorée) ; les volumes FAT32 bruts restent pris
  en charge. `disk = system-gpt` et `gpt-persistence` testent la persistance
  après redémarrage, sur AMD et Intel, les deux GPT et la FAT vérifiées ;
  `sgdisk -v` indépendant valide les images. Tests unitaires et croisés
  FAT/GPT/Io, cinq mutations détectées ; `cargo xtask lint` propre et
  738 tests hôte et 30 scénarios QEMU réussis, aucun scénario sauté.
  Détails et limites dans
  `compat/io-install.md`. Aucun appel système ni IOCTL ajouté.
  Étape suivante réalisée : image de développement unique ESP + système,
  `cargo xtask image --output ...`, plan de disposition pur dans
  `xtask::install::Plan`, écriture dans un fichier neuf, puis
  `cargo xtask run --image ...`. Le noyau reconnaît aussi le GPT du disque
  primaire (sans confondre l'ancienne ESP FAT virtuelle avec `C:`), et le
  scénario `installed-persistence` démarre puis redémarre cette unique image.
  Le prompt UI/UX réutilisable est dans `design/installer-ui-prompt.md`.
  Validation Linux : lint propre, 740 tests hôte et 32 scénarios QEMU
  réussis (suite reprise après saturation de l’espace temporaire, sans
  scénario sauté). Les commandes publiques `image` et `run --image` ont
  été exécutées ; la seconde atteint la sonde SMSS sur le disque primaire.
  GPT vérifié par `sgdisk`, ESP et système par `fsck.vfat`, destination
  existante refusée sans altération.
  `main` est maintenant intégré à la branche : son pilote PS/2 et son chemin
  clavier jusqu'aux fenêtres donnent à l'installateur le focus, WM_KEYDOWN,
  WM_CHAR et la traduction de la disposition. La souris et les curseurs
  restent absents. **Premier jalon UI réalisé** : `SETUP1.EXE`, sonde Win32
  native à cinq écrans et contrôles GDI, navigation Tab/Retour/Espace/Échap,
  revue avant la limite d'écriture, cinq étapes de progression et écran de
  fin vérifié. Le scénario `installer-ui` exerce les retours et la progression
  au clavier et vérifie l'écran ; l'installation est explicitement simulée et
  le programme n'écrit aucun disque. **Premier contrat noyau branché** :
  `NtDeviceIoControlFile` et `IOCTL_MINO_SETUP_QUERY` rendent à l'UI la cible
  ATA secondaire de 96 Mio, un plan immuable (ESP 40 Mio, système 54 Mio) et
  son jeton. `io_manager::install` refuse le disque système et le média de
  démarrage, valide les deux géométries avec `fatfs::format`, et ne contient
  aucune commande d'écriture. Le scénario `disk = target` fournit un disque
  vierge distinct ; `installer-ui` passe sur AMD et Intel. Détails et plan dans
  [`compat/install-ui.md`](compat/install-ui.md).
  **Lot 2 du moteur fait** : `IOCTL_MINO_SETUP_PREPARE` (`abi::setup`,
  `SetupPrepare` de 16 octets) — le média de démarrage et le disque qui
  porte `C:` refusés avant toute écriture, le plan recalculé et le jeton
  reverifié (la capacité est dans son empreinte), un disque qui porte déjà
  des tables refusé sans être touché, puis `libs/gpt::write` (secours
  d'abord, flush entre copies) et la relecture `libs/gpt::read` exigeant
  les deux copies valides et les plages du plan ; GUID déterministes tirés
  du jeton (la même demande écrit les mêmes octets). Self-test noyau
  `install_prepare_self_test` sur chaque boot (refus du disque système
  vérifié dans les scénarios `disk = system`, chemin complet dans le
  scénario `installer-prepare`, AMD et Intel) ; cinq tests hôte de
  `prepare_disk` ; statuts NT de chaque refus. Détails dans
  [`compat/io-install.md`](compat/io-install.md), lot 2.
  **Lot 3 fait** : l'UI appelle la préparation réelle — `SETUP1.EXE`
  renvoie le jeton de l'aperçu par `IOCTL_MINO_SETUP_PREPARE` à
  l'activation d'« Install », journalise la réussite ou le refus, et
  l'écran final dit ce qui reste simulé ; le self-test noyau passe derrière
  la feature `test-install` (les autres scénarios gardent la cible vierge
  pour l'UI) ; **verrou exclusif du moteur** (`Exclusive`, Busy →
  `STATUS_DEVICE_BUSY`), une seule préparation à la fois ; chaque marqueur
  `[setup] screen …` part après le paint (le screendump du scénario
  prenait une fenêtre à moitié peinte sur SYSENTER). `installer-ui`,
  `installer-prepare` et `persistence` verts sur AMD et Intel ; 106 tests
  hôte ; lint propre. Détails dans [`compat/io-install.md`](compat/io-install.md),
  lot 3, et [`compat/install-ui.md`](compat/install-ui.md).
  Restent le formatage des deux vues bornées (`fatfs::format` est prêt),
  la copie des fichiers, la progression et la reprise du moteur (partie
  proposée de l'ADR-022), puis la souris.
- **VirtualBox** ([`compat/vbox.md`](compat/vbox.md)) : le boot arrive loin
  (GPT du disque primaire lu, `C:` monté, GOP 1024×768, smss, processus)
  puis `process_round` bugchecke : le CPU voit des pages `.text` autres
  que celles que les mêmes tables de pages rendent au noyau (faute de
  lecture à `0xFFFFFFFF` sur un store, `.data` intacte à zéro, code lu
  correct par le noyau, `rax` = le TID lu par `fs:[0x24]`). Bogue de
  portabilité TLB/segment propre aux profils CPU de VBox, sans effet sur
  QEMU. Analyse, instrumentation (à reposer : TEMP dans
  `sys::exceptions::raise`) et pistes dans le document. La VM « Mino »
  reste définie dans le VirtualBox de l'hôte Windows (VHD régénérable par
  `cargo xtask image` + `convertfromraw`).
- PR fusionnées : #29, #30, #31 (spike S1), #32 à #34 (M4) et #35 (l'étape 1 du M5). Après chaque fusion, repartir de
  `origin/main` (`git fetch origin main && git merge --ff-only origin/main`, ou `git merge origin/main` si la branche a
  des commits non fusionnés : jamais de réécriture).
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

## M4 (terminé) : E/S, registre, systèmes de fichiers

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
3. [ ] (reporté au M5, étapes 1 et 2) **Ex et Ps** que `smss` demande : `NtCreateEvent`, `NtCreateThread` et `NtWriteVirtualMemory`,
   `ThreadBreakOnTermination` (avec l'arrêt `CRITICAL_OBJECT_TERMINATION` : la sonde ne devra plus terminer `smss`).
4. [x] **Écriture dans le registre, en mémoire** (`docs/compat/m4-smss.md`, étape 5) : une ruche montée est un arbre de
   clés en mémoire (`cm::HiveKey`, chacune sous son verrou), lu du fichier regf à son montage, sans récursion, borné à
   512 niveaux ; `Key::set_value`, `delete_value`, `create_subkey` (volatile ou non,
   `STATUS_CHILD_MUST_BE_VOLATILE`). Services : NtCreateKey (ouvre ou crée, sous un parent qui existe ;
   `REG_OPTION_CREATE_LINK` : `STATUS_NOT_IMPLEMENTED`), NtSetValueKey, NtDeleteValueKey. Tests : hôte (`kernel/cm`),
   `registry_write_self_test` (mode utilisateur), vérifiés par mutation. La ruche HARDWARE (`ntoskrnl::hardware`),
   volatile, bâtie au démarrage. Résultat : `smss` écrit ses six variables, puis ne trouve pas `csrss.exe`.
   **Pas encore** : l'écriture des ruches sur disque (critère 2 : la ruche entière par `regf::builder`, sur FAT32 en
   écriture ; NtFlushKey, écriture différée), NtDeleteKey, `tools/mkhive` (ADR-012).
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
   `NtQuerySystemInformation(SystemProcessorInformation)` (étape 6).
   Pas encore : IRP et piles de périphériques (les lectures vont droit au volume), noms longs FAT, écriture FAT
   (critère 3), partage, création ; une section de fichier copie le fichier (deux copies de `shell32` quand deux
   sections le tiennent : à partager par fichier, comme les SectionObjectPointers d'XP).
6. [x] **`SystemProcessorInformation`** (`sys::system`, décodage de CPUID dans `hal::cpuid`, testé sur l'hôte ;
   `abi::system_information` : structure et `KF_*` d'XP SP2 ; test dans `loader_services_self_test`). Résultat : `smss`
   ouvre `Session Manager\Environment` en écriture et s'arrête à `NtSetValueKey` (`OS`) : **l'étape 4 (écriture dans
   le registre) est la prochaine**.
7. [x] **FAT32 en écriture, sur le disque RAM** (une partie du critère 3). `tools/mkfat` écrit un vrai volume FAT32
   (secteur d'amorçage, FSInfo et leurs copies, 32 secteurs réservés, deux FAT, au moins 65 525 clusters et 4 Mio
   libres : 33 Mio au moins) ; ses tests le passent à `fsck.vfat -n` (paquet `dosfstools`). `kernel/io` :
   `BlockDevice::write_sector`, `FatVolume` écrit (FAT dans chaque copie, clusters alloués à zéro et libérés, chaînes
   vérifiées, données à une position avec l'intervalle à zéro, taille, entrées ajoutées, répertoire qui grandit,
   sous-répertoires) ; `Volume` (un verrou ; `current` relit l'entrée : toutes les ouvertures voient la même taille ;
   `create`, `write`, `set_size`) ; `File` (`create_child`, `write`, `set_size`) ; `check_open` écrase ou refuse
   (lecture seule, répertoire). Services : NtCreateFile qui crée, NtReadFile, NtWriteFile (synchrones),
   NtSetInformationFile (position, fin de fichier), NtFlushBuffersFile. Tests : hôte (`kernel/io/src/write_tests.rs`,
   avec `fsck.vfat` sur ce que le pilote écrit), `file_write_self_test` (mode utilisateur), vérifiés par mutation.
   **Pas encore** : noms longs (un nom que le 8.3 ne tient pas : `STATUS_OBJECT_NAME_INVALID`), suppression et
   renommage, dates, partage, E/S asynchrones ; le compte de FSInfo reste « inconnu ».
8. [x] **Un vrai disque pour `C:`, le critère 3 coché**. `hal::ata` : `AtaDrive` (un disque d'un canal IDE, PIO sans
   interruption : IDENTIFY, READ et WRITE SECTORS, FLUSH CACHE) ; `hal::power::reset`. `io::disk::AtaDisk` ;
   `BlockDevice::flush` jusqu'à `File::flush` et NtFlushBuffersFile. `io_manager::mount_boot_volumes` : le disque RAM
   reste `\Device\Ramdisk0` ; un disque FAT32 au maître du canal secondaire devient `\Device\HarddiskVolume1`, et
   `\??\C:` et `\SystemRoot` y mènent (sans lui, au disque RAM, comme avant). `xtask` : `disk = system` (l'image du disque
   RAM devient aussi `c.img`, attachée au canal secondaire), `boots = N` (les démarrages sauf le dernier finissent par
   l'arrêt de QEMU, `-no-reboot`), puis `fsck.vfat -n` sur l'image. Scénario `persistence` (feature
   `test-persistence`) : le premier démarrage écrit `C:\PERSIST` et redémarre, le second relit et ajoute ; `fsck.vfat`
   propre. Le test d'écriture depuis le mode utilisateur (`file_write_self_test`) écrit sur le disque RAM, que chaque
   démarrage refait. **Pas encore** : table de partitions (le disque porte un seul volume), LBA 48 bits, DMA et
   interruptions, virtio-blk ; le verrou du volume est tournant (attentes actives à DISPATCH_LEVEL : un mutex avec les
   interruptions) ; un cache de secteurs (chaque cluster d'une chaîne relit un secteur de la FAT, lent en PIO).
9. [x] **Le critère 2 : une valeur du registre après un redémarrage.** `regf::builder` écrit les classes et les dates
   des clés. `cm::HiveFile` retient son fichier (`with_file`) et s'il a changé ; `to_regf` rend la ruche en entier, sans
   ses clés volatiles (au-delà de 64 niveaux : STATUS_REGISTRY_IO_FAILED, le constructeur est récursif) ; `flush` la
   récrit par Io et vide le cache du disque ; `Key::flush`, `Key::digest` (FNV-1a des noms, classes et valeurs).
   NtFlushKey. La ruche SYSTEM se récrit dans `\SystemRoot\System32\config\SYSTEM`. Tests : hôte (réécriture et relecture,
   la ruche SYSTEM de ReactOS comprise), `registry_write_self_test` (NtFlushKey sur une ruche du disque RAM, relue),
   scénario `registry-persistence` (`requires = userland`) ; vérifiés par mutation. Critère coché : le M4 est terminé.
## Dettes du M4

Ce que le M4 prévoyait (05) ou a laissé en chemin, à reprendre quand cela comptera :

- Io : IRP, piles de périphériques, E/S asynchrones (un événement ou une APC de fin : `STATUS_NOT_IMPLEMENTED`), ports
  de complétion, partage (IoCheckShareAccess), suppression et renommage de fichiers, énumération de répertoires
  (NtQueryDirectoryFile, que `cmd.exe` demandera), noms longs FAT, dates des fichiers.
- Disques : virtio-blk, gestionnaire de partitions complet (GPT et vue bornée faits au F4 ;
  une seule partition système montée, pas encore d’IOCTL), LBA 48 bits,
  DMA et interruptions ; le verrou d'un volume est tournant (attentes actives à DISPATCH_LEVEL : un mutex quand Ke en
  aura un) ; un cache de secteurs (en PIO, chaque pas d'une chaîne relit un secteur de la FAT).
- Registre : `tools/mkhive` (ADR-012 ; la ruche SYSTEM vient encore de ReactOS), écriture différée (rien ne va sur
  disque sans NtFlushKey), journal `.LOG`, NtDeleteKey, clés liens, notifications, ruches SOFTWARE et DEFAULT.

## Jalon courant : M5 (mode console, spike S2)

Étapes, dans l'ordre où `smss` et `csrss` les demandent (journal : [`compat/m5-csrss.md`](compat/m5-csrss.md)) :

1. [x] **`csrss.exe` sur le disque, et lancé par `smss`.** `xtask` met `csrss.exe`, `csrsrv.dll`, `basesrv.dll` et
   `winsrv.dll` dans `WINDOWS\SYSTEM32`. Pour que `smss` crée `csrss` (`RtlCreateUserProcess`) :
   - crate `ex` : le type `Event` ; NtCreateEvent (attributs facultatifs), NtOpenEvent, NtSetEvent, NtResetEvent,
     NtClearEvent, NtPulseEvent, NtQueryEvent ; NtWaitForSingleObject et NtWaitForMultipleObjects (processus,
     thread, événement) ;
   - Mm : une plage désignée sous 64 Kio (le premier Mio d'un sous-système, depuis l'adresse 4) ; les tables NLS au
     plus haut (`0x7FFB0000`, `map_view_top_down`, `MEM_TOP_DOWN`) ; NtReadVirtualMemory, NtWriteVirtualMemory
     (`STATUS_PARTIAL_COPY`) ; NtQuerySection (`SectionImageInformation`, `SectionBasicInformation`) ;
   - Ke et Ps : un thread créé sans être prêt (`UserThreadStart::ready`, `ready_new_thread`), le trampoline de
     `hal::ring3` qui livre les APC noyau avant le mode utilisateur, la suspension (APC qui attend l'événement de
     reprise, reprise forcée à la fin) ; NtCreateProcess(Ex), NtCreateThread (contexte assaini, `INITIAL_TEB`),
     NtSuspendThread, NtResumeThread, NtTerminateThread, NtQueryInformationProcess et NtSetInformationProcess
     (`ProcessBasicInformation`, `ProcessSessionInformation`) ; la session d'un processus ; son nom d'après son image ;
   - Ob : NtQuerySymbolicLinkObject ;
   - crate `lpc` : le type `Port`, NtCreatePort, NtReplyWaitReceivePort qui attend (le noyau peut envoyer un
     datagramme, LpcRequestPort) : les threads d'API de `smss` attendent sur `\SmApiPort` ;
   - la sonde journalise les processus que `smss` crée.
   Tests : `event_service_self_test`, `process_memory_self_test`, `suspend_self_test`, `process_creation_self_test`,
   `port_self_test`, `object_directory_self_test` étendu, tests hôte (ex, lpc, VAD, contexte) ; vérifiés par
   mutation. `csrss` démarre, charge `csrsrv`, entre dans `main`, puis `CsrServerInitialization` échoue à
   `CsrSetProcessSecurity` (NtOpenProcessToken).
2. [x] **Se : les jetons** (02 §5.8, ADR-011 ; `compat/m5-csrss.md`, étapes 6 et 7). `abi::security` (SID, ACL,
   descripteurs, enregistrements des jetons). Crate `se` : `Sid`, `Acl` (RtlValidAcl), `SecurityDescriptor` (capture
   absolue ou relative sur une fonction de lecture, forme relative, `select`, `merge`), `Token` (type `Token`, jeton
   de System, `duplicate_primary`, `adjust_privileges`, `query` des classes d'XP), `allocate_luid`. Ob : le
   descripteur (forme relative) dans l'en-tête, `update_security_descriptor`. Ps : un jeton primaire par processus
   (`EProcess::primary_token`, copie de celui du créateur), `ps::session` (SystemSessionCreate et Detach, le meneur
   `smss`). Services (`sys::security`, `sys::system`) : NtOpenProcessToken(Ex), NtOpenThreadToken(Ex)
   (`STATUS_NO_TOKEN`), NtQueryInformationToken, NtAdjustPrivilegesToken, NtSetSecurityObject,
   NtQuerySecurityObject ; NtSetSystemInformation (`SystemSessionCreate`, `SystemSessionDetach`,
   `SystemExtendServiceTableInformation` : win32k fait partie du noyau, rien n'est chargé), sous
   `SeLoadDriverPrivilege` (SeSinglePrivilegeCheck, appliqué). Tests : hôte (`se`, `ob`, `ps::session`),
   `security_self_test` ; vérifiés par mutation. `smss` obtient `SeLoadDriverPrivilege`, crée la session 0, lance
   `csrss`, qui passe `CsrSetProcessSecurity` et s'arrête à `CsrParseServerCommandLine`.
3. [x] **Mm : la section partagée de `csrss`** (`compat/m5-csrss.md`, étape 8). `mm::section` : `SEC_RESERVE`
   (`Section::create_shared`, l'engagement par page dans la section, `Section::commit`, `committed_run`) et
   `SEC_BASED` (une adresse prise à la création sous `HIGH_SECTION_BASE`, `0x7F7F0000`, parmi les sections basées,
   rendue à leur destruction) ; `VadNode::page_state` (la suite de la vue et l'engagement de la section), dont se
   servent la faute de page et NtQueryVirtualMemory ; MEM_COMMIT dans une vue commite la section ; une vue d'une
   section basée va à son adresse. `sys::section` : NtCreateSection avec ces attributs, NtQuerySection (adresse,
   `SEC_RESERVE`, `SEC_BASED`). Tests : hôte (`mm`), `shared_section_self_test` ; vérifiés par mutation. `csrss` met
   sa section en `0x7F6F0000`, y bâtit son tas, charge `basesrv`, puis échoue à charger `winsrv`.
4. [x] **Le disque de démarrage, fermé pour les imports** (`compat/m5-csrss.md`, étape 9). `xtask` :
   `userland::import_closure`, la fermeture des imports des programmes et DLL du disque, lue par `libs/pe` (16 DLL de
   plus), et la page de code 20127 (la locale C de `msvcrt`). Noms longs (VFAT) : `tools/mkfat` les écrit (alias
   `BASIS~N.EXT`), `io::fat` les lit (`find_entry` par nom long ou alias, sans casse ; pas encore de création). Tests :
   hôte (`io`, `mkfat` avec `fsck.vfat`, la fermeture) ; vérifiés par mutation. `smss` met 37 sections dans
   `\KnownDlls` ; `csrss` charge `winsrv` et ses imports, puis `user32` appelle `NtUserProcessConnect` (win32k).
5. [x] **Les services simples que `csrss` tolérait** (`compat/m5-csrss.md`, étape 10). `hal::rtc` (l'heure du
   démarrage, lue au CMOS ; le temps système, aussi dans `KUSER_SHARED_DATA`), le compteur de temps du processeur
   calibré (`hal::timer::performance_counter`). Services : NtQuerySystemTime, NtQueryPerformanceCounter,
   NtQuerySystemInformation(`SystemTimeOfDayInformation`, `SystemRangeStartInformation`), NtQueryDebugFilterState
   (tout passe), NtSetInformationObject (attributs d'un handle ; session d'un répertoire, `ob::Directory`, sous
   `SeTcbPrivilege`), NtQueryInformationProcess(`ProcessLUIDDeviceMapsEnabled`, `ProcessCookie`, `EProcess::cookie`),
   NtFlushInstructionCache. Tests : hôte (`hal::rtc`), `information_services_self_test` ; vérifiés par mutation.
   Les assertions de `basesrv` disparaissent ; `csrss` s'arrête toujours à `NtUserProcessConnect`.
6. [x] **win32k minimal** (02 §7.2, ADR-021 ; `compat/m5-csrss.md`, étape 12), décidé avec le mainteneur : le M5
   prend la partie minimale du M6, l'initialisation de `user32` (premier critère du spike S3). Crate `win32k` : la
   section partagée de USER (`shared` : `SERVERINFO`, table des handles, adresses du serveur en `0xBC000000`), les
   threads et processus GUI (`gui` : conversion au premier appel à win32k dans `sys::dispatch`, `CLIENTINFO` et
   `Win32ThreadInfo` dans le TEB, vue en lecture seule, `GdiDCAttributeList`), `client` (les procédures de `user32`),
   `csrss` (NtUserInitialize). `abi::user` ; Mm : `Section::write_kernel`, `read_kernel` ; Ps : emplacements Win32
   (`EProcess::win32_process`, `EThread::win32_thread`) ; Ex : les sémaphores (`ex::semaphore`). Services :
   NtUserProcessConnect, NtUserInitializeClientPfnArrays, NtGdiInit, NtUserInitialize, NtCreateSemaphore,
   NtOpenSemaphore, NtReleaseSemaphore, NtQuerySemaphore, NtQueryObject(`ObjectHandleFlagInformation`). `xtask` met
   `lpk.dll` sur le disque. Tests : hôte (`abi`, `win32k`, `ex`), `win32k_self_test`, le résumé `[m4] USER:` de la
   sonde ; vérifiés par mutation. `csrss` charge `winsrv` (USER, puis `consrv`) et s'arrête à `SmConnectToSm`
   (`NtConnectPort`).
7. [x] **La connexion LPC** (`compat/m5-csrss.md`, étape 13). `lpc` : trois sortes de ports (connexion, client,
   communication du serveur), routage des messages et contexte, threads en attente inscrits par TID
   (`lpc::conversation`), section partagée du client (projetée des deux côtés). Services : NtConnectPort,
   NtSecureConnectPort (SID du serveur), NtAcceptConnectPort, NtCompleteConnectPort, NtListenPort,
   NtRequestWaitReplyPort, NtRequestPort, NtReplyPort, NtReplyWaitReceivePort (avec réponse) et son Ex,
   NtSetDefaultHardErrorPort ; NtOpenProcess, NtOpenThread ; `SystemFlagsInformation`. La sonde laisse passer la fin
   d'un objet critique (`ps::set_critical_breaks_ignored`). `hal` : l'IRQL des tests hôte est propre à chaque thread.
   Tests : hôte (`lpc`, `hal`), `lpc_connection_self_test` ; vérifiés par mutation. `csrss` et `smss` se connectent
   dans les deux sens, `csrss` est démarré ; `smss` s'arrête à `winlogon.exe`, absent du disque.
8. [x] **Les événements à clé, les processus critiques** (`compat/m5-csrss.md`, étape 11). `ex::keyed_event` (le
   type `KeyedEvent`, le rendez-vous d'une clé dans un processus, `\KernelObjects\CritSecOutOfMemoryEvent` pour un
   handle nul) ; `ke::sched::set_base_priority` (KeSetBasePriorityThread) ; Ps : processus et threads critiques
   (`EProcess::set_critical`, `clear_critical`, `EThread::set_critical`), dont la fin arrête le système
   (`CRITICAL_OBJECT_TERMINATION`, `ps::exit`), la priorité de base du processus (ses threads, et ceux créés
   ensuite), le mode d'erreur grave (hérité). Services : NtCreateKeyedEvent, NtOpenKeyedEvent, NtWaitForKeyedEvent,
   NtReleaseKeyedEvent ; NtSetInformationProcess et NtQueryInformationProcess (`ProcessBasePriority`,
   `ProcessDefaultHardErrorMode`, `ProcessBreakOnTermination`) ; NtSetInformationThread
   (`ThreadBreakOnTermination`). La sonde retire ses drapeaux à `smss` avant de le terminer. Tests : hôte (`ex`,
   `ke`), `keyed_event_self_test`, `process_settings_self_test`, scénarios `critical-process` et `critical-thread` ;
   vérifiés par mutation. L'assertion de `smss` disparaît ; `csrss` s'arrête toujours à `NtUserProcessConnect`.

9. [ ] **`winlogon`** (`compat/m5-csrss.md`, étape 14). Fait : `winlogon.exe` sur le disque ; NtDuplicateObject
   (`ob::duplicate` : `DuplicateSource::Pseudo` pour `NtCurrentProcess()` et `NtCurrentThread()`, résolus par Ps ;
   sans cible, la source se ferme seulement ; `DUPLICATE_CLOSE_SOURCE` quel que soit le résultat), `OBJ_PROTECT_CLOSE`.
   Tests : hôte (`ob`), `duplicate_object_self_test`. `smss` confie `winlogon` à `csrss` (`SmExecPgm`) et attend ;
   `csrss` (`CsrSbCreateSession`) s'arrêtait à NtSetInformationProcess(`ProcessExceptionPort`). Fait ensuite :
   - [x] `ProcessExceptionPort` (8) : sous `SeTcbPrivilege`, un port LPC, une fois (`STATUS_PORT_ALREADY_SET`),
     `EProcess::set_exception_port` ; le noyau ne s'en sert pas encore (une exception non traitée en seconde chance
     devrait y aller, au lieu de terminer le processus) : dette ;
   - [x] NtQueryInformationThread : `ThreadBasicInformation`, `ThreadTimes` (`EThread::create_time`, `exit_time` ;
     les temps noyau et utilisateur restent nuls, Ke ne les compte pas encore : dette), `ThreadIsTerminated`
     (`EThread::is_terminating`, pour `CsrInsertThread`) ; vérifiés dans QEMU (`smoke`, `smss`) ;
   - [x] la connexion de `kernel32` à `csrss` : `csrss` la refusait (« CSRSS: Rejecting Connection Request »), car
     NtMapViewOfSection refusait `SEC_NO_CHANGE` (`CsrSrvAttachSharedSection`) ; une vue `SEC_NO_CHANGE` garde
     maintenant sa protection (`VadNode::no_change`, `AddressSpace::map_view_with`) ; `MEM_LARGE_PAGES` et
     `MEM_DOS_LIM` rendent `STATUS_NOT_IMPLEMENTED` (journalisé). Tests : hôte (`mm`), `shared_section_self_test`.
   - `ProcessForegroundInformation` (25, toléré par `csrss`) : le quantum de premier plan (PsPrioritySeparation)
     demande un quantum par thread dans Ke ;
   - [x] un service de win32k sans handler rend 0 et `ERROR_CALL_NOT_IMPLEMENTED` s'il rend une valeur
     (`Service::returns_status`, tiré des prototypes de ReactOS : `w32k-ntstatus.lst`) ; la dette de l'étape 6 est
     levée ;
   - [x] `RegisterLogonProcess` : NtUserCallTwoParam (`0x69`, `win32k::logon`), NtUserSetInformationThread
     (`UserThreadCsrApiPort`, le port d'API de `csrss` gardé par win32k) ;
   - [x] les stations de fenêtres (`win32k::winsta`, `sys::winsta`) : NtUserCreateWindowStation (la première du
     processus de logon est la station interactive), NtUserOpenWindowStation, NtUserCloseWindowStation,
     NtUserGetProcessWindowStation, NtUserSetProcessWindowStation, NtUserSetWindowStationUser ;
   - [x] les bureaux (`win32k::desktop`, `win32k::gui`, `sys::desktop`) : NtUserCreateDesktop (un tas par bureau,
     son `DESKTOPINFO`, adresses du serveur sur 32 bits), NtUserOpenDesktop, NtUserCloseDesktop,
     NtUserSetThreadDesktop (vue du tas, `CLIENTTHREADINFO`, `CLIENTINFO`), NtUserSwitchDesktop ;
   - [x] les dispositions de clavier (`win32k::keyboard`) : NtUserLoadKeyboardLayoutEx (le fichier lu par le noyau
     d'après le registre, les tables trouvées sans exécuter `KbdLayerDescriptor`), NtUserGetKeyboardLayoutList ;
   - [x] premier affichage (choisi avec le mainteneur avant les tubes nommés) : le pilote d'affichage
     (`win32k::display`, trait `DisplayDriver` ; `drivers/video/gopfb` sur le framebuffer UEFI), le moteur DIB
     (`win32k::gdi::dib` : surface de 32 bits, couleurs, `fill_rect`), `COLOR_BACKGROUND` ; NtUserSwitchDesktop peint
     le fond du bureau d'entrée ; l'ancien lanceur ne dessine plus sur un écran que win32k a pris ; `xtask` vérifie des
     pixels d'une capture de l'écran (`screen = X Y RRGGBB`) ;
   - [x] la fenêtre du bureau (`win32k::window`, `win32k::handles`) : la table des handles USER dans la section
     partagée, `WND` et `CLS` dans le tas du bureau, `spwnd` ; DesktopWindowProc côté serveur (WM_PAINT, BeginPaint,
     WM_ERASEBKGND, EndPaint) ; NtUserSwitchDesktop montre la fenêtre et la met à jour ;
   - [x] les files de messages (`win32k::queue`, `sys::message`) : NtUserPostThreadMessage, NtUserPostMessage (sans
     fenêtre), NtUserPeekMessage, NtUserGetMessage (attente), NtUserWaitMessage, NtUserCallOneParam
     (PostQuitMessage, GetQueueStatus), bits de réveil dans le `CLIENTTHREADINFO` ;
   - [x] les rappels en mode utilisateur (étape 23) : KeUserModeCallback (`ps::callback`, `ke::callout`,
     `hal::callout`), NtCallbackReturn et `int 2Bh`, la pile noyau qui grandit en place jusqu'à 72 Kio
     (`mm::kstack::grow`) ; win32k rappelle `user32` : ClientThreadSetup (conversion d'un thread client),
     GetCharsetInfo (la page de code d'une disposition de clavier, que `winlogon` obtient de `gdi32`) ;
   - [x] le banc d'essai des fenêtres ([`compat/m6-fenetres.md`](compat/m6-fenetres.md)) : le scénario `gui`
     met `tests/native/gui1.c` (MinGW, lié aux vrais `kernel32` et `user32`) à la place de `winlogon.exe`
     (`initial-command`) ; les classes de fenêtres (`win32k::atom`, `win32k::class`) : NtUserRegisterClassExWOW,
     NtUserGetClassInfo ;
   - [x] NtUserCreateWindowEx (`win32k::window::create_window`) : WM_NCCREATE, WM_NCCALCSIZE, WM_CREATE, WM_SIZE,
     WM_MOVE, WM_PARENTNOTIFY envoyés à la procédure du client par KeUserModeCallback
     (`USER32_CALLBACK_WINDOWPROC`, `lParam` emballé comme PackParam) ; le `WND` complet (liens, nom, procédure),
     que `user32` lit lui-même ; NtUserDefSetText ;
   - [x] les métriques et les couleurs du système (`win32k::metrics` : `aiSysMet` et `argbSystem` du `SERVERINFO`)
     et la partie noyau de DefWindowProc (`win32k::defwnd`, NtUserMessageCall avec FNID_DEFWINDOWPROC :
     WM_NCCALCSIZE, la zone cliente sans le cadre ni le titre) ; WM_GETMINMAXINFO à la création ; la capture d'un
     `LARGE_STRING` de NtUserCreateWindowEx ignore `bAnsi` (corrigé : une classe n'était parfois pas trouvée) ;
   - [x] le moniteur principal (`win32k::monitor`, NtUserMonitorFrom*, NtUserGetMonitorInfo : place par défaut en
     cascade, WM_GETMINMAXINFO adapté) et SetWindowPos (`win32k::winpos`, NtUserSetWindowPos, NtUserMoveWindow :
     WM_WINDOWPOSCHANGING, WM_NCCALCSIZE, ordre Z avec le premier plan, enfants déplacés, WM_WINDOWPOSCHANGED,
     WM_MOVE et WM_SIZE de DefWindowProc) ; `syscall-gen` suit la variante publiée (`DBG`) et vérifie les stubs
     de `ntdll`, `user32` et `gdi32` (corrigé : 26 numéros de win32k décalés) ;
   - [x] ShowWindow (`win32k::winpos::show_window`, NtUserShowWindow : WM_SHOWWINDOW, SetWindowPos, WM_SIZE et
     WM_MOVE différés, commande du `STARTUPINFO`, fenêtres créées visibles) ;
   - [x] le cadre des fenêtres peint par le noyau (`win32k::paint`, `win32k::nonclient`, `gdi::draw`,
     `gdi::region` : régions visibles, invalidation, WM_NCPAINT, bords, titre en dégradé, boutons ; le bureau
     repeint là où une fenêtre le découvre) : des fenêtres apparaissent à l'écran ;
   - [x] la zone cliente effacée (M6, étape 7) : la table des handles GDI partagée (`win32k::gdi::handles`,
     `PEB.GdiSharedHandleTable`), les pinceaux de stock et des couleurs du système (`ahbrSystem`), les DC de
     l'écran et leurs attributs dans la mémoire du client (`gdi::dc`), le cache des DC de fenêtres (`win32k::dce`),
     les appels de GDI en lot exécutés au retour d'un rappel et avant chaque service de win32k (`gdi::batch`) ;
     WM_ERASEBKGND après WM_NCPAINT, NtGdiPatBlt, NtGdiGetAppClipBox, NtGdiFlush ;
   - [x] WM_PAINT (M6, étape 8) : le compte des fenêtres à peindre de chaque thread (`QS_PAINT`, tenu à chaque
     changement d'une fenêtre), WM_PAINT tiré par PeekMessage et GetMessage, NtUserDispatchMessage, BeginPaint et
     EndPaint (NtUserBeginPaint, NtUserEndPaint ; DefWindowProc de WM_PAINT) : une fenêtre se peint et se valide ;
   - [x] InvalidateRect, ValidateRect, RedrawWindow, UpdateWindow, GetUpdateRect (M6, étape 9) : la région à
     mettre à jour est une région ; NtUserRedrawWindow, NtUserInvalidateRect, NtUserValidateRect,
     NtUserGetUpdateRect, NtUserCallHwndLock (UpdateWindow) ;
   - [x] GetDC et ReleaseDC, les régions de GDI (M6, étape 10) : les entrées de la table des handles rendues et
     reprises, les régions d'un client et leurs attributs (`RGN_ATTR`, `win32k::gdi::rgnobj`), la région de
     découpage d'un DC (SelectClipRgn, en lot ou non), DeleteObject en lot ; NtUserGetDC, NtUserGetDCEx,
     NtUserGetWindowDC, ReleaseDC (`ONEPARAM_ROUTINE_RELEASEDC`), DeleteDC, NtGdiCreateRectRgn, NtGdiCombineRgn,
     NtGdiGetRgnBox, NtGdiExtSelectClipRgn, NtUserInvalidateRgn, ValidateRgn (NtUserCallHwndParamLock),
     NtUserGetUpdateRgn, NtUserRedrawWindow avec une région ;
   - [x] le texte du titre et les symboles des boutons (M6, étape 11, ADR-013) : `libs/glyph` (`ttf-parser` 0.21,
     rastériseur en virgule fixe 16.16, niveaux de gris, sans hinting ; métriques de GDI), les polices sur le disque
     (`WINDOWS\FONTS` : Tahoma, Tahoma gras, Marlett ; `userland::install_fonts`), `win32k::font` (texte mis en
     glyphes, « ... », monochrome, cache), `Op::Glyph` et `Bitmap::blend_coverage`, le titre (UserDrawCaptionText) et
     les symboles Marlett des boutons (UITOOLS95_DrawFrameCaption, grisés sans leur style) dans `nonclient` ;
   - [x] le texte des clients (M6, étape 12) : `win32k::gdi::fontobj` (objet police, polices de stock, correspondance
     d'un LOGFONT avec Tahoma, Tahoma gras ou Marlett, TMW_INTERNAL, étendue), `win32k::gdi::text` (ExtTextOut :
     alignement, fond, ETO_OPAQUE, ETO_CLIPPED, `lpDx`), le lot (GdiBCTextOut, GdiBCExtTextOut, GdiBCSelObj),
     NtGdiGetStockObject, NtGdiHfontCreate, NtGdiSelectFont, NtGdiGetTextMetricsW, NtGdiGetTextExtent,
     NtGdiExtTextOutW ; le programme `tests/native/text1.c` et son scénario `text` ;
   - [x] DrawText (M6, étape 13) : NtGdiGetTextExtentExW (`win32k::font::advances`, `fontobj::text_extents`),
     NtGdiGetRandomRgn, NtGdiIntersectClipRect ; le `DrawTextW` de `user32` coupe des mots, centre, calcule son
     rectangle et rend la région de découpage du DC ;
   - [x] la sonde console, étape 1 (M5, `compat/m5-console.md`) : le PEB d'un processus créé rendu dans le TEB de
     son créateur (comme le noyau de ReactOS) ; l'emprunt d'identité (`ps::EThread::impersonate`,
     `se::client::client_security`, NtImpersonateThread, ThreadImpersonationToken, NtOpenThreadToken) ;
     NtUserConsoleControl et NtUserResolveDesktop (`win32k::console`, `sys::console`) ;
   - [x] la sonde console, étape 2 (les polices) : la ruche SOFTWARE montée (`userland::mount_software_hive`) ; les
     polices de `\SystemRoot\Fonts` installées (`io::Volume::list`, `win32k::font` : table de polices, noms, graisse,
     italique, pas, jeu de caractères ; `glyph::Names`) ; la correspondance d'un LOGFONT par substitut, famille,
     graisse, italique et pas (`fontobj::realize`) ; NtGdiGetFontFamilyInfo (`fontobj::family_info`) ;
   - [x] la sonde console, étape 3 : Sleep(0) cède le reste du quantum à un thread prêt de même priorité
     (`Scheduler::yield_to_equal`, `Platform::yield_execution`) ; le critère des 8 threads est coché ;
   - [x] la sonde console, étape 4 : la fenêtre console montrée (NtUserSetWindowLong : octets de plus, USERDATA ;
     NtUserShowWindowAsync ; NtUserPostMessage à une fenêtre ; le bureau de démarrage d'un thread converti,
     `win32k::startup`) ; `CONSHOW1.EXE` garde sa console à l'écran ;
   - [x] la sonde console, étape 5 : le texte de la console peint : les vues système de Mm (`mm::system_view`), les
     capacités de l'écran (`win32k::gdi::devcaps`), les DIB sections vues du processus et du noyau
     (`win32k::gdi::surface`), les DC en mémoire (NtGdiCreateCompatibleDC, NtGdiSelectBitmap), BitBlt
     (`win32k::gdi::bitblt`), les pinceaux d'un client (NtGdiCreateSolidBrush) ; `consrv` peint « Mino console » ;
     le banc `BITMAP1.EXE` (scénario `bitmap`) ;
   - [x] la sonde console, étape 6 : le clavier jusqu'aux fenêtres : le pilote `drivers/input/i8042`, le thread
     d'entrée brute (`ntoskrnl::input`), les tables de la disposition (`win32k::kbdtables`), `win32k::input`
     (ProcessKeyEvent, premier plan, activation, SetFocus, TranslateMessage), les touches dans la file
     (`QS_KEY`, état du clavier du thread) ; NtUserGetKeyState, NtUserGetAsyncKeyState, NtUserGetKeyboardState,
     NtUserToUnicodeEx, NtUserTranslateMessage, NtUserSetFocus ; `keys =` dans les scénarios ; le banc
     `KEYS1.EXE` (scénario `keyboard`) ;
   - [x] la sonde console, étape 7 : `cmd.exe` interactif : ReadConsoleW marchait déjà (rien ne manquait au noyau) ;
     NtQueryDirectoryFile (`abi::file` : les entrées des classes 1, 2, 3 et 12 ; `io::directory` : l'expression
     avec les jokers DOS, le tampon ; `io::File::query_directory` : l'état de l'énumération, l'expression de la
     première requête, nom long ou 8.3 ; `io::Volume::entries`) : `dir` et `copy` (FindFirstFile) ; `cmd.exe` sur le
     disque ; `keys =` accepte du texte entre guillemets ; la sonde attend 10 s après la dernière touche ; le banc
     `CONCMD1.EXE` et `READ1.EXE` (scénario `cmd`) ;
   - [x] la sonde console, étape 8 : ce que `dir` affiche autour des noms : FileNameInformation,
     FileFsVolumeInformation, FileFsAttributeInformation, FileFsSizeInformation, FileFsFullSizeInformation (le
     numéro de série du BPB, le nom de l'entrée de volume, les clusters libres comptés dans la FAT) ; les dates de FAT
     (`fat::FatTime`) écrites par Io (création, écriture) et par `tools/mkfat` (2004-08-04 12:00) ;
     NtSetInformationFile(FileBasicInformation) ; NtQueryDefaultLocale (`ex::locale`, `Nls\Language`) ; `xtask`
     attend qu'une touche soit relâchée avant la suivante (QEMU 8.2 perdait des relâchements) ; `hal::ps2` compte ce
     qu'il perd. **Le critère de `cmd.exe` interactif est coché** ;
   - **la suite, côté console** : les outils externes de ReactOS sur le disque (`find`, `sort`, `more`, `tree`,
     `fc`, `xcopy`, `attrib`) et un scénario qui les enchaîne par des tubes et des redirections ; `del`, `ren`, `md`,
     `rd` (suppression et renommage d'Io) ; plus tard `format` et `chkdsk` (`fmifs.dll`, `ufat.dll` : un volume
     ouvert comme périphérique, les IRP) ; les icônes de `consrv`, SetTimer, le défilement et les barres de
     défilement de la console, DestroyWindow ; le dernier critère du M5 : les `rostests` `ntdll` et `kernel32` ;
   - **la suite, côté affichage** (le chemin critique du M5 et du M6) : les contrôles et
     l'entrée ; le chemin de la connexion (avis donné au mainteneur : après ceux-ci) commence par NPFS, les tubes
     nommés d'Io, où s'arrête le vrai `winlogon` ; la fenêtre active et le premier plan, réduire et agrandir (WINDOWPLACEMENT), DestroyWindow,
     les messages envoyés (SendMessage entre threads) et postés aux fenêtres, le thread du bureau ;
     GDI : objets d'un client (CreateSolidBrush, NtGdiGetStockObject), DC en mémoire, BitBlt, texte et polices
     (ADR-013), icônes et curseurs ; l'entrée (i8042, souris, thread d'entrée) ;
   - **la suite, côté `winlogon`** : il démarre son serveur RPC sur le tube nommé `\pipe\winreg` : il faut le système de
     fichiers des tubes nommés d'Io (NPFS, `\Device\NamedPipe` : NtCreateNamedPipeFile, l'ouverture d'un client,
     FSCTL_PIPE_LISTEN, lectures et écritures), hors de USER ; puis `services.exe`, `lsass.exe`, `msgina` ;
   - **USER (option 1, choisie avec le mainteneur : le win32k minimal, début du M6 et du spike S3)** :
     le `consrv` épinglé n'a que son frontal graphique (`winsrv.dll` : `frontends/gui`, pas de `tuiterm`) et `smss`
     lance `winlogon.exe` en dur ; `winlogon` sert donc de guide. Dans l'ordre où il les demande
     (`winlogon.c`) : après le clavier (NtUserLoadKeyboardLayoutEx), le serveur RPC, `services.exe`,
     `lsass.exe`, `msgina`. ReactOS crée aussi la fenêtre du bureau et la fenêtre des messages de chaque bureau
     (classes, fenêtres : plus tard) et, à la première station, le thread du bureau et le thread d'entrée (RIT).

Méthode (celle du M4) : après chaque composant, relancer `cargo xtask test --boot --scenario smss`, lire le journal
`[m4]`, mettre à jour `docs/compat/m5-csrss.md` et les marqueurs du scénario (`expect` de l'endroit où il s'arrête).

Questions ouvertes du M5 :
- ADR-021 (adresses du serveur sur 32 bits pour ce que USER partage) est proposée : à accepter avec le mainteneur,
  ou à revoir après le spike S3.
- NtUserInitialize réussit sans vidéo ni GDI (M6) : la console de `consrv` devra dire si son frontal texte s'en
  passe (ce que fait `consrv` sans `InitVideo`).
- Le contrôle des privilèges s'applique (SeSinglePrivilegeCheck), alors que l'ADR-011 laisse permissif le contrôle
  d'accès : à confirmer avec le mainteneur (une ADR si l'on veut aussi journaliser sans refuser).
- `SystemExtendServiceTableInformation` réussit sans rien charger (win32k fait partie du noyau, ses services rendent
  `STATUS_NOT_IMPLEMENTED`) : à revoir quand win32k sera un module à part (spike S3).
- `ProcessSessionInformation` demande `SeTcbPrivilege` dans ReactOS (NtSetInformationProcess) ; ici, pas encore.
- `ProcessExecuteFlags` : le `ntdll` de ReactOS y passe 0 sous `OptIn` ; la règle du M3
  (`ps::eprocess::changed_execute_options`, exactement `DISABLE` ou `ENABLE`) le refuse. Le service reste à faire,
  après avoir tranché (ADR-020).
- `ProcessUserModeIOPL` : `csrss` demande l'IOPL 3 pour les registres VGA ; le noyau garde IOPL 0 (`hal::ring3`).
  À décider avec la console (frontal texte de `consrv`).

Services vus pendant S1 et encore absents (tolérés par `ntdll`, détail dans `compat/s1-ntdll.md`, étape 3) : la
classe `ProcessExecuteFlags` de NtSetInformationProcess (le service est fait pour d'autres classes),
`NtQueryDefaultLocale`. `ProcessCookie` et `NtFlushInstructionCache` sont faits (M5, étape 5), `NtCreateKeyedEvent`
aussi (étape 8). `NtOpenKey`, `NtQueryValueKey`, `NtOpenDirectoryObject`, `NtOpenFile` et `NtQueryAttributesFile` sont faits.

## Dettes de l'étape 9 du M5 (`winlogon`)

- Classes de fenêtres (M6, [`compat/m6-fenetres.md`](compat/m6-fenetres.md)) : le refus d'un drapeau inconnu par
  NtUserRegisterClassExWOW n'a pas de test (`user32` n'en passe jamais ; une mutation qui le retire survit) ; ni
  curseurs, ni icônes, ni pinceaux, ni désenregistrement, ni procédures d'appel, ni `atomSysClass`.
- Fenêtres (M6, étape 2) : ni DestroyWindow (les fenêtres d'un thread vivent autant que lui), ni ShowWindow à la
  création, ni menus, ni `HWND_MESSAGE`, ni messages à un autre thread, ni crochets ; un texte ANSI n'est pas
  converti par la page de code (ASCII seul).
- DefWindowProc du noyau (M6, étape 3) : WM_NCCALCSIZE seul (les autres messages attendent les contextes de
  périphérique, le positionnement et l'entrée : 0, journalisés une fois) ; les autres types de NtUserMessageCall
  rendent FALSE ; la fenêtre inconnue de NtUserMessageCall n'a pas de test (`user32` valide le handle avant) ; ni
  profil d'utilisateur pour les métriques, ni SystemParametersInfo.
- Sonde console (M5, étape 8) : ni casse des noms 8.3 (octet 12), ni dernier accès à la lecture, ni fuseau horaire
  (les dates de FAT passent pour de l'UTC) ; NtSetDefaultLocale absent (la locale de l'utilisateur est celle du
  système) ; ProcessDeviceMap (NtQueryInformationProcess, classe 0x17) absent ; FileFsVolumeInformation sans date de
  création du volume ; la place libre compte toute la FAT à chaque requête (le secteur FSInfo n'est ni cru ni tenu à
  jour) ; le scénario `cmd` dure 66 s.
- Sonde console (M5, étape 7) : NtQueryDirectoryFile sans les classes à identifiants (37, 38 :
  `STATUS_NOT_IMPLEMENTED`), sans événement ni APC de fin ; une copie vers l'utilisateur qui faute laisse
  l'énumération avancée ; ni noms longs créés ; `dir` sans en-tête du volume, sans place libre ni dates (faits à
  l'étape 8) ; `copy` ne garde pas la date de la source (sa date de création, depuis l'étape 8, comme le `copy` de
  ReactOS) ; le scénario `cmd` dure 45 s (les touches, une à une).
- Sonde console (M5, étape 6) : ni souris, ni WM_NCACTIVATE, ni WM_ACTIVATE inactif à l'ancienne fenêtre active,
  ni messages d'activation à un autre thread (le focus est pris sans eux) ; ni crochets, raccourcis, Alt + pavé
  numérique, Alt + Tab, changement de disposition au clavier, voyants, Impr. écran, SendInput ; pas d'IRP
  (kbdclass : win32k lit le pilote) ; le premier plan garde le thread d'une fenêtre détruite ou d'un thread fini ;
  ToUnicodeEx garde une touche morte pour tous les threads (`wchDead` global, comme ReactOS).
- Sonde console (M5, étape 5) : ni bitmaps compatibles (CreateBitmap, CreateCompatibleBitmap : le motif 8 × 8 de
  `consrv`), ni profondeurs autres que 32 bits, ni section d'une application pour une DIB section, ni palettes,
  GetObject, GetDIBits, SetDIBits, StretchBlt, MaskBlt avec un masque, NtGdiGetDeviceCaps ; un bitmap choisi n'est pas
  supprimé (la documentation ; ReactOS en diffère la suppression) ; les objets GDI d'un processus ne sont pas rendus à
  sa fin (une DIB section garde sa section et sa vue système) ; le défilement de l'écran à travers plusieurs
  rectangles de la région copie l'un après l'autre ; les vues système ne vident pas la TLB des autres processeurs.
- Sonde console (M5, étape 4) : SetWindowLong de GWL_STYLE, GWL_EXSTYLE, GWLP_WNDPROC, GWLP_HWNDPARENT absent
  (journalisé) ; ShowWindowAsync d'une fenêtre d'un autre thread absent (messages envoyés entre threads) ; un message
  posté à la fenêtre du bureau perdu (pas de thread du bureau) ; un chemin de bureau sans station laisse le thread
  converti sans bureau (journalisé) ; DestroyWindow, SetTimer, barres de défilement absents.
- Sonde console (M5, étape 3) : NtYieldExecution (SwitchToThread) absent ; un thread qui cède garde sa priorité et
  reçoit un quantum neuf (pas de décroissance).
- Sonde console (M5, étape 2) : polices bitmap (`.fon`), collections et polices privées absentes ; le jeu de caractères
  d'un substitut (`Nom,jeu`) ignoré ; la correspondance décide par le nom, sans les pénalités de GetFontPenalty ; ni
  gras ni italique synthétiques ; l'énumération donne le LOGFONT de la hauteur par défaut (cellule de 12 pixels).
- Sonde console (M5, étape 1) : SeTokenCanImpersonate absent (tout jeton s'emprunte), pas de DACL pour la copie à
  l'ouverture, OpenAsSelf sans effet, `IsImpersonating` du TEB non écrit ; NtUserResolveDesktop sans la station par
  défaut (`Service-0x0-3e7$`) d'un chemin qui n'en nomme pas ; ConsoleMakePalettePublic et
  ConsoleAcquireDisplayOwnership non faits ; l'assertion des icônes de `consrv` passée (« i ») ; le thread d'entrée
  retrouvé par une seconde console non testé.
- DrawText (M6, étape 13) : GTEF_INDICES (GetTextExtentExPointI) refusé ; ni préfixes soulignés vérifiés (le test
  met DT_NOPREFIX), ni DT_END_ELLIPSIS ou DT_PATH_ELLIPSIS côté client, ni région de méta (METARGN : 0).
- Texte des clients (M6, étape 12) : toute police autre que Marlett donne Tahoma ou Tahoma gras (nom, largeur,
  italique, soulignement et barré ignorés au dessin) ; TA_UPDATECP, ETO_GLYPH_INDEX, ETO_RTLREADING non suivis ;
  NtGdiSelectFont et NtGdiExtTextOutW appelés directement sans test de bout en bout ; NtGdiOpenDCW (`user32`, à la
  création d'une fenêtre) toujours absent.
- Texte du titre (M6, étape 11) : sans hinting (ADR-013 : niveaux de gris à la place) ; avances arrondies au pixel
  par glyphe, sans crénage ; le cache des glyphes se vide en entier au-delà de 1024 ; une police installée est lue
  (`Font::parse`) à chaque texte ; `DFCS_INACTIVE` du bouton fermer (`CS_NOCLOSE`, menu système) non suivi ; le titre
  n'a pas encore d'icône devant lui (il commencera plus à droite avec elle).
- Peinture du cadre (M6, étape 6) : pas de WM_PAINT du client (la zone cliente est effacée : étape 7), ni icône,
  ni barres de défilement ; tout cadre est inactif ; une sœur découverte attend sa prochaine invalidation ; pas de
  copie des bits valides (une fenêtre déplacée est repeinte entière) ; le dégradé n'a de spécification que ses
  bouts (le moteur de ReactOS n'est pas dans les sources épinglées) ; ôter le test de visibilité de WM_NCPAINT ne
  change rien (la région visible d'une fenêtre cachée est vide : mutation équivalente).
- GetDC et les régions de GDI (M6, étape 10) : ni NtGdiSetRectRgn (`gdi32` change lui-même une région qui a ses
  attributs), ni autres formes de région, OffsetRgn, EqualRgn, PtInRegion, RectInRegion, GetRegionData, GetClipRgn,
  ExcludeClipRect, IntersectClipRect, OffsetClipRgn, SetMetaRgn, `DCX_INTERSECTUPDATE` (journalisé) ; ni régions ni
  DC d'un processus rendus à sa fin, ni cache de handles du PEB ; sans test : NtGdiDeleteObjectApp d'un autre objet
  qu'un DC, le refus de rendre le DC d'un autre processus (un seul processus GUI dans `gui`), le libre des attributs
  d'une région supprimée. Écarts voulus avec ReactOS : un DC du cache sans `DCX_CACHE` pour une fenêtre sans DC à
  elle (XP, Wine ; ReactOS rend NULL), seul le preneur d'un DC le rend, `VisRectRegion` écrit à la prise du DC.
  Un `|` dans un marqueur `expect` en fait deux au choix : le marqueur `SEC_BASED | SEC_RESERVE` du scénario
  `smoke` ne vérifie que son début (tâche proposée à part).
- InvalidateRect et RedrawWindow (M6, étape 9) : pas de fond du bureau repeint à la demande (journalisé), ni
  WM_SYNCPAINT, ni `WNDS_SYNCPAINTPENDING` ; sans test : `WNDS_UPDATEDIRTY` (un seul thread GUI dans `gui`) ;
  mutation équivalente : l'effacement oublié quand la validation vide la région.
- WM_PAINT (M6, étape 8) : ni WM_SYNCPAINT ; DispatchMessage d'une procédure de minuterie (WM_TIMER) journalisé ;
  sans test (mutations qui survivent) : une procédure qui ne fait pas BeginPaint (repeinte par IntDispatchMessage),
  le cadre des enfants repeint par BeginPaint, le DC de BeginPaint coupé à la région à mettre à jour (toujours toute
  la zone cliente), WM_PAINT réservé aux fenêtres du thread (un seul thread GUI dans `gui`).
- Zone cliente (M6, étape 7, [`compat/m6-fenetres.md`](compat/m6-fenetres.md)) : ni DC d'une fenêtre ou d'une classe
  (`CS_OWNDC`, `CS_CLASSDC`), ni DC du parent (`CS_PARENTDC`) ; en lot, seuls PatBlt, SelectClipRgn et DeleteObject
  s'exécutent (les autres appels sont sautés, journalisés) ; pas de pinceaux créés par un client, de DC en mémoire,
  de stylos, de transformations, de `DevCaps` (à zéro) ni de ménage à la fin d'un processus (un DC pris par un
  processus qui finit pendant un rappel reste pris). Mutation équivalente :
  ôter `DCX_CLIPSIBLINGS` de la région d'un DC ne change rien tant que `DCX_CLIPSIBLINGS` ne vient que du style
  (VIS_ComputeVisibleRegion coupe déjà les sœurs d'une fenêtre à `WS_CLIPSIBLINGS`) ; le chemin de NtGdiPatBlt qui
  peint n'est pas atteint par `gdi32` (il met PatBlt en lot sauf sur une DIB section) : seul son refus a un test.
- ShowWindow (M6, étape 5) : ni réduire ni agrandir (FALSE, journalisé) ; ni fenêtre active ni focus ; les
  fenêtres possédées ne suivent pas leur propriétaire ; pas de ShowWindowAsync ; le `STARTUPINFO` n'a qu'un test
  hôte.
- SetWindowPos (M6, étape 4) : sans régions, une fenêtre est visible avant si elle et ses parents le sont ; rien
  n'est repeint ; ni activation ni premier plan ; les fenêtres possédées ne sont pas gardées au-dessus de leur
  propriétaire ; `SWP_ASYNCWINDOWPOS` est fait tout de suite ; un seul moniteur, sa zone de travail entière ; le
  `STARTUPINFO` d'une fenêtre recouvrante n'a qu'un test hôte.

- Rappels en mode utilisateur (étape 23) : un thread qui se termine pendant un rappel abandonne les trames des rappels
  en cours (comme NT), sans rendre ce qu'elles possèdent, et rien ne le teste ; `STATUS_CALLBACK_POP_STACK` n'a qu'un
  test hôte (ce que la trame reprend), pas de test de bout en bout ; un APC utilisateur n'est pas livré à l'entrée
  d'un rappel ; les appels GDI en lot du TEB ne sont pas exécutés après un rappel (journalisé une fois) ; un
  ClientThreadSetup qui échoue laisse le thread converti ; la pile noyau ne rapetisse pas. L'auto-test des rappels
  remplace le temps de l'essai le handler de l'`int 2Ah` (sans ntdll, aucun service ne rappelle le mode utilisateur).

- Le processus de logon n'est pas oublié à sa fin (pas de rappel de sortie d'un processus GUI) ; le port d'API de
  `csrss` gardé par win32k ne sert encore à rien (CsrClientCallServer du noyau : plus tard).
- NtUserSetInformationThread ne se teste que depuis `csrss` : le refus d'une longueur autre que 4
  (`STATUS_INFO_LENGTH_MISMATCH`) n'a pas de test (une mutation qui le retire survit).
- Clavier : l'activation d'une disposition (`hKL` et `CodePage` du `CLIENTINFO`) n'a pas de test (une mutation qui
  la retire survit) : il faudrait une station interactive et une vraie disposition, que seul le scénario `smss` a, sans
  rien qui lise ces champs avant le serveur RPC.
- Files de messages : le masque de GetQueueStatus (`QS_ALLINPUT | QS_ALLPOSTMESSAGE | QS_SMRESULT`) ne filtre que des
  bits que la file ne produit pas encore (une mutation qui le retire survit).
- Fenêtres : NtUserSwitchDesktop cache la fenêtre du bureau d'entrée d'avant, ce que rien ne voit (`winlogon` ne
  change de bureau qu'une fois, le scénario `smoke` n'a pas de station interactive) : montrer et cacher ont un test
  direct ; WM_PAINT est envoyé directement (pas de file de messages), la région à mettre à jour est un rectangle,
  WM_ERASEBKGND n'a pas de contexte de périphérique.
- Bureaux : NtUserSwitchDesktop vérifie la session du bureau, que rien ne teste (une seule session) ; un bloc du tas
  rendu puis repris est remis à zéro, ce que rien n'observe encore (aucun bloc rendu ne tient autre chose que des
  zéros) ; le bureau de démarrage n'est donné que par un thread client, absent du scénario `smoke` (sans `csrss`,
  tout thread GUI est un thread de `csrss`) : sa règle a un test hôte. Un thread ou un processus GUI qui finit ne
  quitte pas son bureau (pas de rappel de sortie) : ses vues et son `CLIENTTHREADINFO` partent avec ses objets ;
  les adresses du serveur d'un tas reviennent à sa fin.
- Le port d'exception d'un processus est gardé sans servir (une exception non traitée en seconde chance devrait y
  aller) ; les temps noyau et utilisateur d'un thread restent nuls (Ke ne les compte pas).

## Dettes de Se (l'étape 2 du M5)

- SeAccessCheck et le mode permissif qui journalise les refus (ADR-011) ; le descripteur qu'un objet reçoit à sa
  création (SeAssignSecurity, d'après le jeton de son créateur : propriétaire, groupe, DACL par défaut) ; le
  propriétaire donné à NtSetSecurityObject n'est pas comparé au jeton ; les SACL (aucun handle n'a
  `ACCESS_SYSTEM_SECURITY`).
- L'emprunt d'identité (jetons de thread, NtImpersonate*, NtSetInformationThread(`ThreadImpersonationToken`)),
  NtDuplicateToken, NtAdjustGroupsToken, NtSetInformationToken, NtAccessCheck, NtPrivilegeCheck ; les classes
  `TokenGroupsAndPrivileges`, `TokenAuditPolicy`, `TokenOrigin` (journalisées). Le jeton garde la session de son
  créateur quand celle du processus change.
- Sessions : pas d'espace de session (Mm), ni de compte des processus d'une session ; un identifiant créé reste pris.

## Dettes de l'étape 7 du M5 (LPC)

- Pas encore : la section d'un serveur (`ServerView` de NtAcceptConnectPort, que ReactOS n'a pas non plus), les
  rappels (une requête envoyée en réponse), les données décrites par `DataInfoOffset` (NtReadRequestData,
  NtWriteRequestData), les messages `LPC_PORT_CLOSED` et `LPC_CLIENT_DIED`, les ports attendables
  (NtCreateWaitablePort), les quotas. Un thread qui se termine pendant qu'il attend une réponse laisse son inscription,
  qu'écrase la suivante de son TID ; un serveur qui accepte sans compléter laisse son client en attente.
- NtRaiseHardError manque : le port des erreurs graves est retenu, rien ne l'emploie.
- La sonde rétablit l'arrêt sur la fin d'un objet critique à sa fin ; aucun scénario ne peut le voir (rien de critique
  ne finit après elle).

## Dettes de l'étape 6 du M5 (win32k minimal)

- USER : ni vidéo (InitVideo), ni GDI (`InitializeGreCSRSS`, `GdiSharedHandleTable` nul dans le PEB), ni paramètres
  système, ni pinceau gris, ni stations de fenêtres ou bureaux (seul leur répertoire existe), ni files de messages,
  ni pile noyau agrandie pour les threads GUI, ni disposition du clavier (`hKL`, `CodePage` nuls). Le `SERVERINFO`
  n'est écrit que jusqu'à `cbHandleTable` (le reste reste à zéro). Rien n'est rendu à la fin d'un processus GUI au-delà
  de ce que rend son objet (pas de rappel de sortie de win32k).
- Les refus de NtUserInitialize (USER déjà démarré, autre version : STOP `WIN32K_INIT_OR_RIT_FAILURE`) n'ont pas de
  test : un second appel ou un mauvais `csrss` changerait l'état global de USER pour le scénario `smss`.
- (Levée à l'étape 9 : un service de win32k sans handler qui rend une valeur rend 0 et `ERROR_CALL_NOT_IMPLEMENTED`.)
- Vu une fois, non reproduit (huit lancements ensuite) : le test Ps `process_round` a vu NtReadVirtualMemory (côté
  noyau, `read_memory`) rendre `STATUS_ACCESS_VIOLATION` en lisant `DATA + 8` de `grows.exe` (scénario `smss`, Intel),
  STOP 0x1E. À diagnostiquer s'il revient (une course entre la croissance de la pile et la lecture ?).

## Dettes de l'étape 8 du M5

- Les événements à clé : pas d'alerte par NtAlertThread pendant un rendez-vous (pas encore de service), pas de
  « Waiters » visibles (NtQueryKeyedEvent n'existe pas dans XP). NtSetInformationThread : seule
  `ThreadBreakOnTermination` ; `ThreadZeroTlsCell` (10, `kernel32`, `TlsFree`) est journalisée ;
  NtQueryInformationThread manque. `ProcessBasePriority` ignore la priorité mémoire (pas de pagination) et le quantum
  (KeSetPriorityAndQuantumProcess) ; `SEM_NOALIGNMENTFAULTEXCEPT` ne change pas le contrôle d'alignement.
- Deux chemins de l'arrêt n'ont pas de scénario à eux : NtTerminateThread sur un thread critique (« Terminating
  critical thread ») et la fin du dernier thread d'un processus critique (« Critical process exited ») ; leur code
  est celui des deux autres.
- NtRaiseHardError manque : `csrss` en lève une (`STATUS_IO_PRIVILEGE_FAILED`) et continue.

## Dettes de l'étape 5 du M5

- Le temps : pas de fuseau horaire (le RTC est lu comme UTC, biais nul ; XP le tire du registre,
  `Control\TimeZoneInformation`), pas de NtSetSystemTime ni de NtQueryTimerResolution. NtQueryDebugFilterState laisse
  tout passer ; NtSetDebugFilterState manque. La session d'un répertoire n'est encore lue par rien.

## Dettes de l'étape 4 du M5

- Io : créer un nom long (aujourd'hui `STATUS_OBJECT_NAME_INVALID`). Le disque n'a qu'une page de code de plus (20127) :
  les autres tables NLS (118 dans la version épinglée) viendront quand un programme les demandera.

## Dettes de Mm (l'étape 3 du M5)

- Les pages d'une section `SEC_RESERVE` ne se décommitent pas (NtFreeVirtualMemory sur une vue :
  `STATUS_UNABLE_TO_DELETE_SECTION`) ; pas de compte d'engagement (quota) ; `SEC_BASED` pour un fichier.

## Ensuite (hors jalon)

- Router #DB, #BR, #NP, #SS, #AC du mode utilisateur vers KiDispatchException (aujourd'hui seuls #DE, #BP, #UD,
  #GP, #PF et `int 2Ch`).
- KiDispatchException : si la pile utilisateur ne reçoit pas le contexte, le processus se termine avec le code de
  l'exception d'origine (XP lèverait plutôt l'exception de l'écriture sur la pile).
- Avant de supprimer l'ancien code (Win32 dans `syscall.rs`, stubs de `loader.rs`, `launcher.rs`, `win32/*`,
  `directx/*`), extraire la connaissance utile dans `docs/compat/` (audit §5).
- Idée tracée, pas une décision : réutiliser des pilotes de Linux ou d'un BSD sous une couche d'émulation, pour le
  matériel qu'on n'écrira pas en Rust (Wi-Fi, GPU moderne). Spike S4, optionnel, au M9
  ([05](05-feuille-de-route.md#m9--matériel-réel-et-réseau)) : préalables (ADR-007 tranchée, ADR qui remplace
  l'ADR-008 pour ces pilotes), licence, critères. Rien à faire avant le M9.

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
- ReactOS sert de spécification (ses sources `ntdll`, `smss`, `csrsrv`, en lecture) ; on ne porte pas son code noyau.
  Jamais de code Microsoft. Les sources, hors du dépôt, par le proxy Git (sans l'API de GitHub) :
  `git clone --filter=blob:none --no-checkout --depth 1 --branch 0.4.16 https://github.com/reactos/reactos ../reactos-src`,
  puis `git sparse-checkout set --no-cone base/system/smss dll/ntdll sdk/lib/rtl subsystems/csr` et `git checkout`.
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
