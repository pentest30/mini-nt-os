# Notes de passation

Où en est le travail, ce qui vient ensuite, et comment le reprendre. Ces notes ne font pas foi (les documents 01 à
06 et `docs/compat/` font foi) ; elles servent à reprendre une session, depuis n'importe quel compte. Les mettre à
jour à chaque commit qui change l'état.

## État

- Jalon courant : **M5** ([05](05-feuille-de-route.md#m5--mode-console-puis-spike-s2)) ; **M4 terminé** : ses trois
  critères de sortie sont cochés (`smss` crée ses variables d'environnement et `\KnownDlls` ; un fichier de `C:` et une
  valeur du registre se relisent après un redémarrage, scénarios `persistence` et `registry-persistence`, `fsck.vfat`
  propre). Ce que le M4 laisse à faire est listé ci-dessous (« Dettes du M4 »). Au M5, `smss` crée sa session et
  lance `csrss.exe`, qui protège son processus (Se), crée sa section partagée (Mm), charge `basesrv`, puis ne trouve
  pas une DLL des imports de `winsrv` (`advapi32_vista.dll`) : [`compat/m5-csrss.md`](compat/m5-csrss.md).
- Branches de travail : `claude/m5-se` (l'étape 2 du M5, PR à ouvrir), partie de `main` après la fusion de #35, puis
  `claude/m5-mm` par-dessus (l'étape 3). Les PR se fusionnent dans `main` ; après une fusion, repartir de
  `origin/main` (avance rapide si la branche y est déjà incluse : `git merge-base --is-ancestor HEAD origin/main`).
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
- Disques : virtio-blk, gestionnaire de partitions (le disque système porte un seul volume, sans table), LBA 48 bits,
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
4. [ ] **Le disque de démarrage : la fermeture des imports de `csrss`** (`xtask/src/userland.rs`) : `rpcrt4.dll`
   (atteinte par `user32` puis `advapi32`) importe `advapi32_vista.dll`, `kernel32_vista.dll` et `ws2_32.dll`, absentes.
   Mettre sur le disque la fermeture des imports de `csrss` et de ses DLL serveur (lue dans les PE par `libs/pe`,
   plutôt qu'une liste à la main), puis relancer la sonde. Ensuite, `basesrv` : ses trois assertions tolérées
   (`SystemTimeOfDayInformation`, NtSetInformationObject(`ObjectSessionInformation`),
   `ProcessLUIDDeviceMapsEnabled`), à faire quand elles comptent.
5. [ ] **La connexion LPC** : NtConnectPort et NtSecureConnectPort, NtAcceptConnectPort, NtCompleteConnectPort,
   NtRequestWaitReplyPort, NtReplyPort, NtReplyWaitReceivePort avec réponse, NtListenPort ; puis les sections de
   port (messages volumineux). `csrss` crée son port d'API (`CsrApiPortInitialize`), puis se connecte à `\SmApiPort`
   (`SmConnectToSm`) et `smss` signale son événement.
6. [ ] Les objets d'Ex qui restent : les événements à clé (NtCreateKeyedEvent, pour les sections critiques de
   `ntdll`), `ThreadBreakOnTermination` (avec l'arrêt `CRITICAL_OBJECT_TERMINATION` : la sonde ne devra plus terminer
   `smss`), NtSetInformationProcess(`ProcessBasePriority`, `ProcessDefaultHardErrorMode`).

Méthode (celle du M4) : après chaque composant, relancer `cargo xtask test --boot --scenario smss`, lire le journal
`[m4]`, mettre à jour `docs/compat/m5-csrss.md` et les marqueurs du scénario (`expect` de l'endroit où il s'arrête).

Questions ouvertes du M5 :
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

Services vus pendant S1 et encore absents (tolérés par `ntdll`, détail dans `compat/s1-ntdll.md`, étape 3) : les
classes `ProcessCookie` de NtQueryInformationProcess et `ProcessExecuteFlags` de NtSetInformationProcess (les deux
services sont faits pour d'autres classes), `NtFlushInstructionCache`, `NtQueryDefaultLocale` ; `NtCreateKeyedEvent`
(Ex). `NtOpenKey`, `NtQueryValueKey`, `NtOpenDirectoryObject`, `NtOpenFile` et `NtQueryAttributesFile` sont faits.

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
