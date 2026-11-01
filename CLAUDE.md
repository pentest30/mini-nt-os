# Mino — contexte pour Claude Code

Mino est un système d'exploitation libre, compatible XP. Le noyau NT, `win32k` et les pilotes sont écrits en Rust `no_std` ;
l'espace utilisateur vient d'une version épinglée de ReactOS (binaires i386). La frontière stable du projet est l'interface noyau
de ReactOS : appels système `ntoskrnl` et `win32k`, structures en mode utilisateur, protocoles LPC de CSR.

## Documents (ils font foi)

| Document | Contenu |
|---|---|
| [`docs/01-vision.md`](docs/01-vision.md) | Périmètre, ce qui est exclu |
| [`docs/02-architecture.md`](docs/02-architecture.md) | Architecture cible, organisation du dépôt (§10) |
| [`docs/03-decisions.md`](docs/03-decisions.md) | ADR. Une ADR acceptée ne se modifie pas : une nouvelle ADR la remplace. |
| [`docs/04-audit-reutilisation.md`](docs/04-audit-reutilisation.md) | Verdict par fichier du code existant, défauts connus, corrections immédiates (§7) |
| [`docs/05-feuille-de-route.md`](docs/05-feuille-de-route.md) | Jalons et critères de sortie ; l'état réel s'y suit (cases cochées) |
| [`docs/06-conventions.md`](docs/06-conventions.md) | **Conventions de développement, à appliquer à tout le code** |
| [`docs/compat/`](docs/compat/) | Quirks d'applications, imports observés, couverture des appels système |

## Règles non négociables

Le détail est dans [06 — Conventions](docs/06-conventions.md).

1. **Hygiène juridique** (06 §1) : ne jamais consulter, copier ni paraphraser de code Microsoft, y compris les sources fuitées d'XP
   et de Server 2003 et les WRK. Aucun binaire ni aucune ressource Microsoft. Pas de marque « Windows » : on dit « compatible XP ».
   Le code porté de ReactOS ou de Wine indique en en-tête son origine (fichier, commit) et sa licence. Tant que l'ADR-007 (licence)
   n'est pas tranchée, ReactOS sert de spécification : on ne porte pas son code noyau.
2. **`no_std`** dans les crates noyau et pilotes ; dépendances limitées à la liste de l'ADR-016.
3. **`unsafe`** (06 §3) : `// SAFETY:` qui énonce l'invariant ; `#![deny(unsafe_op_in_unsafe_fn)]`. La mémoire utilisateur ne
   s'atteint que par `ke::usermem` (`UserPtr<T>`, `copy_from_user`, `copy_to_user`, `probe_*`).
4. **IRQL** (06 §4) : chaque fonction publique du noyau documente son IRQL maximal (`/// # IRQL` puis `/// <= APC_LEVEL. Peut bloquer.`).
   À `DISPATCH_LEVEL` ou plus : ni pool paginé, ni faute de page, ni attente. `spin::Mutex` est interdit dans le noyau
   (`KSpinLock`, `KGuardedMutex`, `ERESOURCE`).
5. **Layouts imposés** (PEB, TEB, `KUSER_SHARED_DATA`, `CONTEXT`, `LOADER_BLOCK`…) : uniquement dans la crate `abi`, avec des
   assertions `size_of` et `offset_of` à la compilation.
6. **Appels système** : aucun numéro écrit à la main, aucun appel système privé. Tout est généré par `tools/syscall-gen` (ADR-002).
7. **Erreurs** (06 §5) : `NtStatus(u32)` et `Result<T, NtStatus>`, jamais de `u32` nu ; `panic!` seulement pour un invariant violé.
   Aucune journalisation inconditionnelle dans un chemin chaud (appels système, interruptions, ordonnanceur).
8. **Version affichée** : XP 5.1.2600 SP2 (ADR-003). Ne jamais changer les champs de version du PEB ni de `KUSER_SHARED_DATA`.
9. **Pas de contournement silencieux** : un symptôme contourné est documenté et donne lieu à une tâche de diagnostic (audit §4.2).
   Un bogue corrigé s'accompagne d'un test qui l'aurait détecté.

## Travailler dans ce dépôt

- **Reprendre une session** : [`docs/passation.md`](docs/passation.md) (tâche en cours, prochaines tâches, comment
  reprendre). Le tenir à jour à chaque commit qui change l'état.
- Une session traite **un jalon et un composant**, et se termine en faisant passer `cargo xtask lint` et `cargo xtask test`.
- Commits au format `<composant>: <résumé à l'impératif>`, par exemple `mm: séparer reserve et commit dans la VAD`.
  Déplacements par `git mv`. Une PR traite un seul sujet.
- **Jalon courant : M5 — Mode console, puis spike S2** ([05](docs/05-feuille-de-route.md#m5--mode-console-puis-spike-s2)).
  M0 à M4 sont terminés (spike S1 réussi ; l'ADR-002 attend S2 et S3). Acquis de M1 (Ke) : dispatcher (ADR-005) sur l'ordonnanceur à 32 priorités de
  `kernel/ke/src/sched.rs` (préemption différée sous `DISPATCH_LEVEL`, quantum en tiers de tick, boosts, balance set
  manager `ke::balance`), DPC et APC noyau sans allocation (`ke::dpc`, `ke::apc`), roue de timers, état FPU/SSE par
  thread, IRQL = TPR de l'APIC (CR8), KPCR (`hal::pcr`) puis KPRCB (`ke::prcb`) par GS, écran STOP symbolisé
  (`ke::bugcheck`, `hal::bugcheck`). Scénarios `ke-events`, `fpu`, `ke-starvation`, `bugcheck`. Les APC utilisateur
  viennent au M3.
  Acquis de M2 : base PFN faite (`mm::pfn` au-dessus du buddy : toute page physique y passe, avec son usage ; double libération
  et page réservée arrêtent le système ; cohérence vérifiée en fin de phase 1). Pools faits (`mm::pool`) : non paginé
  (allocateur global) et paginé, qui grandissent à la demande et rendent leurs pages à la base PFN ;
  `ex_allocate_pool_with_tag` et compteurs par étiquette. Une PML4 par processus (`mm::address_space`) : moitié haute
  complétée au démarrage et partagée, CR3 propre à chaque thread et chargé à la commutation, `ke_stack_attach`.
  L'ancien chargeur (`NtCreateProcess` de `syscall.rs`) reste dans l'espace du système (`ps::eprocess::create_legacy`).
  VAD faite
  (`mm::vad`, `mm::virtual_alloc`) : arbre sans limite, état de chaque page (réservée, ou commitée avec sa protection),
  commit dans une réservation, décommit et libération réels, protection et requête, erreurs `NtStatus`, retour arrière
  complet si un commit échoue. Fautes de page faites (`mm::fault`) : chaque `AddressSpace` tient sa VAD et s'enregistre
  par CR3 ; un commit ne projette rien, la première faute donne une page à zéro ; garde levée une fois
  (`STATUS_GUARD_PAGE_VIOLATION`) ; `PAGE_NOACCESS`, page réservée ou libre : `STATUS_ACCESS_VIOLATION` ; une page
  inaccessible garde sa page physique (`PTE_RETAINED`). Faute dans la moitié basse à `DISPATCH_LEVEL` : STOP 0x0A ;
  exception en mode noyau sur une adresse utilisateur : STOP 0x1E (pas de `ke::usermem` avant M3). Scénarios
  `page-fault-irql`, `page-fault-access-violation`. Les mappers de l'ancien code projettent encore au commit.
  Parseur PE dans `libs/pe` (réexporté par `ps::loader`, constructeur de PE de test sous la feature `builder`).
  Sections faites (`mm::section`) : fichier d'échange, fichier de données (octets en mémoire en attendant Io), image
  (disposition et protections tirées du PE) ; vues (`AddressSpace::map_view`, `unmap_view`) qui partagent les pages de
  la section (`PTE_SHARED`, `PageUsage::Section`), copie sur écriture, `STATUS_IMAGE_NOT_AT_BASE` (c'est `ntdll` qui
  reloge). Ob réécrit (`ob`) : `Object<T>` dans un `Arc` (compte de pointeurs), en-tête avec type, nom, compte de
  handles ; types en `static` avec droits valides, correspondance générique, procédures *parse* et de fermeture ;
  espace de noms d'XP (`\ObjectTypes`, `\GLOBAL??` derrière `\??`, lien `\DosDevices`…), noms sans casse, liens
  suivis 32 fois au plus, `OBJ_OPENIF`/`OBJ_OPENLINK`/`OBJ_PERMANENT`, nom retiré au dernier handle ; table de handles
  par processus (multiples de 4, droits vérifiés, héritage, protection, duplication, rundown). Type `Section` dans
  `mm::section`. Ps réécrit (`ps`) : table des CID (PID et TID multiples de 4, System = 4) ; EPROCESS (espace
  d'adresses neuf, image projetée, PEB en `0x7FFDF000`, table de handles, threads vivants, objet attendable) ;
  ETHREAD (TEB sous le PEB, pile noyau, thread Ke 32 bits dans l'espace du processus : `ke::sched::create_user_thread`,
  le descripteur du TEB suit chaque commutation, `hal::gdt::set_teb_base`) ; pile utilisateur avec garde
  (`create_user_stack`). Fin par APC noyau normal (`exit_thread`) : passage dans l'espace du système, rundown des APC
  (`ke_rundown_apcs`) ; le dernier thread ferme les handles et rend l'espace d'adresses, une fois finis les accès
  protégés (`rundown::RundownRef`), puis l'objet processus est signalé ; le *reaper* (thread système) rend piles noyau
  et threads Ke (`ke::sched::delete_thread`). La pile utilisateur grandit par sa garde
  (`AddressSpace::extend_user_stack`, TEB du thread courant dans le KPCR) jusqu'à `STATUS_STACK_OVERFLOW`. Une faute
  utilisateur non résolue termine le processus avec le code de l'exception jusqu'au M3. DEP selon la règle OptIn d'XP
  SP2 (ADR-020) : options d'exécution par processus (`EProcess::set_execute_options`, `MEM_EXECUTE_OPTION_*`), sans
  DEP toute page lisible s'exécute (`AddressSpace::set_execute_enabled`), la VAD garde la protection demandée. Pas
  encore : handles noyau, Se (accès accordés, ADR-011).
  M3 : ReactOS épinglé en 0.4.16 (commit `51bfc703`, i386, version de publication), listes de services copiées dans
  `tools/syscall-gen/reactos/0.4.16/` avec leur origine. `tools/syscall-gen` génère `abi/src/services.rs` (numéro de
  chaque service par son nom NT, tables ntoskrnl et win32k avec octets d'arguments ; `abi::service::lookup`) ;
  `cargo xtask lint` vérifie que le fichier est à jour. Dispatcher des services (`kernel/ntoskrnl/src/sys/`) pour les
  threads de Ps : interruptions actives à PASSIVE_LEVEL, arguments copiés par `ke::usermem`,
  `STATUS_INVALID_SYSTEM_SERVICE` hors des tables, `STATUS_NOT_IMPLEMENTED` (journalisé au premier appel) sans
  handler ; syscall-gen tire de sa liste `IMPLEMENTED` le rapport `docs/compat/syscalls.md`. Services : NtClose,
  NtTerminateProcess (NULL, soi-même, handle), NtAllocateVirtualMemory, NtFreeVirtualMemory. `ke::usermem` (sondes
  sous 0x7FFF0000, `copy_from_user`, `copy_to_user`, `UserPtr<T>`) copie par `hal::usermem`, dont une faute sur une
  adresse utilisateur reprend à sa correction (table des exceptions) au lieu du STOP 0x1E ; une faute du noyau sur la
  garde de la pile du thread l'étend aussi. SYSENTER_ESP suit la pile noyau du thread. Les threads de l'ancien
  chargeur gardent `syscall.rs` et ses numéros. Trame de trap faite (`hal::trap::KTrapFrame`) : les portes `int 2Ah`
  à `2Eh` l'empilent et appellent un handler par vecteur (`sys::gates` : tick count, `STATUS_NO_CALLBACK_ACTIVE`,
  assertion qui termine le processus, `DbgPrint` vers le port série avec le PID et le TID en sautant l'`int 3`,
  KiSystemService) ; GS n'est pas rechargé au retour. `abi::context` (CONTEXT x86) et `ke::context` (conversion,
  assainissement d'EFLAGS et des sélecteurs). Exceptions du mode utilisateur faites (`ke::exception`, `sys::exceptions`) :
  #DE, #BP, #UD, #GP, #PF et `int 2Ch` passent par la trame de trap ; KiDispatchException met `CONTEXT` et
  `EXCEPTION_RECORD` sur la pile du thread, qui reprend dans le répartiteur de ntdll (`set_user_exception_dispatcher` ;
  sans répartiteur, le processus se termine avec le code) ; NtContinue, NtRaiseException (seconde chance : fin du
  processus). Les services qui changent la trame (`Handler::Frame`) reçoivent la trame de trap.
  APC utilisateur faits (`ke::apc`, `sys::apc`) : routine normale du mode utilisateur (`NormalRoutine::User`),
  livrables après une attente alertable ou un test d'alerte (NtTestAlert, TestAlert de NtContinue), livrés au retour
  par la trame de trap (`hal::trap::set_user_return_hook`) au répartiteur de ntdll (`set_user_apc_dispatcher`) ;
  NtQueueApcThread, NtDelayExecution. `KUSER_SHARED_DATA` fait (`abi::shared_data`, `mm::shared_data`) : une page
  remplie au démarrage (version 5.1, racine, fonctions du processeur, DEP), mise à jour par l'horloge, en lecture seule
  en `0x7FFE0000` dans chaque processus. DLL système faite (`ps::system_dll`) : points d'entrée de ntdll résolus à son
  installation, ntdll projetée à sa base dans chaque processus, threads démarrés par `LdrInitializeThunk` (APC
  utilisateur, 8 octets réservés sous le `CONTEXT` pour l'enregistrement SEH du répartiteur de ReactOS) ; `SystemCall`
  désigne `KiFastSystemCall` sur Intel, `KiIntSystemCall` ailleurs (ADR-004). SYSENTER fait pour Ps : la même trame
  de trap que `int 2Eh` (pseudo-vecteur `hal::trap::SYSENTER`, EFLAGS de l'utilisateur gardés), ABI d'XP (arguments
  en EDX + 8, retour par `KiFastSystemCallRet`) ; l'ancien chargeur garde la sienne (EDX + 4, `ret` en `0x7FFE0300`).
  SWAPGS fait (`hal::trap`, `hal::pcr`) : base de GS de l'utilisateur en mode utilisateur, KPCR dans
  `IA32_KERNEL_GS_BASE` ; échange à chaque entrée depuis le mode utilisateur et à chaque retour (trame de trap,
  interruptions par des stubs `trap::entry_stub`, exceptions sans retour, premier passage d'un thread), sélecteur
  `GS` de l'utilisateur rechargé au retour. `cargo xtask fetch-userland` fait (`xtask/src/userland.rs`) : archive
  de publication de ReactOS 0.4.16 (SourceForge, SHA-256 publié vérifié), `/reactos` de son ISO extrait dans
  `third_party/reactos/0.4.16/` (ignoré par Git) par du code std seul (SHA-256, inflate, ZIP, ISO 9660) ; les
  scénarios `requires = userland` reçoivent `NTDLL.DLL`, que le noyau installe comme DLL système à la fin des tests de
  la phase 1 (`ntoskrnl::userland`). Spike S1 fait (`docs/compat/s1-ntdll.md`) : un programme natif
  construit dans le noyau (`pe::builder`, imports de ntdll) démarre sous le vrai ntdll
  (`userland::run_native_probe`) ; le noyau journalise sa fin et les appels système faits, dans l'ordre du premier
  (`sys::service_calls`), le premier appel d'un service sans handler avec son appelant et ses arguments, et
  l'exception qui termine un processus. Paramètres du processus faits (`abi::process_parameters`,
  `ps::process_parameters` : bloc normalisé, environnement à part, adresse dans le PEB). Tables NLS faites
  (`ps::nls` : pages de code ANSI et OEM, casse Unicode, une section en lecture seule projetée dans chaque
  processus). Services : NtQuerySystemInformation (SystemBasicInformation), NtProtectVirtualMemory. La sonde va au
  bout : `LdrInitializeThunk` initialise le processus, lie ses imports et l'appelle, qui écrit par `DbgPrint` et se
  termine. Programme MinGW fait (`tests/native/`, compilé par `xtask/src/native.rs`, lié à `ntdll` par
  `tests/native/ntdll.def`, scénario `native`) : lancé avec le PEB en argument (`ps::create_thread_with_parameter`),
  il écrit par `DbgPrint` et se termine. Test SEH fait (`tests/native/s1seh.c`, clang `i686-pc-windows-msvc` et
  `lld-link`, avec `tests/native/seh3.c`, notre `_except_handler3`) : écriture en 0 attrapée, filtre qui décline,
  `__finally` au déroulement par `RtlUnwind`. Ke publie le TID d'un thread utilisateur avant de le rendre prêt
  (`UserThreadStart::tid`).
  M4 : sonde `smss.exe` faite (`docs/compat/m4-smss.md`, scénario `smss`, feature `test-smss`) : le `smss` de ReactOS
  s'arrête au registre (`Session Manager`), après des échecs tolérés de LPC, d'Ex et de Ps. `DbgPrompt` reçoit `i`
  faute de débogueur ; NtQueryVirtualMemory (MemoryBasicInformation). Registre en lecture fait : `libs/regf`
  (ruches en mémoire, constructeur sous `builder`), `kernel/cm` (type `Key`, `\REGISTRY`, ruches montées en lecture,
  `CurrentControlSet`, `cm::info`), Ob (nom relatif à une racine à procédure *parse*), NtOpenKey, NtQueryKey,
  NtEnumerateKey, NtQueryValueKey, NtEnumerateValueKey ; la ruche SYSTEM de ReactOS épinglé montée au démarrage
  (en attendant `tools/mkhive`). Répertoires d'Ob faits : NtCreateDirectoryObject, NtOpenDirectoryObject,
  NtCreateSymbolicLinkObject, NtOpenSymbolicLinkObject. `smss` lit `Session Manager`, crée ses répertoires et ses
  liens. Io fait (`kernel/io`) : le disque RAM de démarrage tient lieu du volume système (`tools/mkfat` écrit des
  sous-répertoires ; l'espace utilisateur et les 21 KnownDLLs dans `\WINDOWS\SYSTEM32`) ; volume FAT32 en lecture
  (`io::volume`), types `Device` (*parse* : IopParseDevice) et `File` (nom relatif à un répertoire ouvert),
  `\Device\Ramdisk0`, `\??\C:`, `\SystemRoot` ; le noyau lit ntdll, les NLS, la ruche et `smss` par Io. Services :
  NtCreateFile (ouverture), NtOpenFile, NtQueryAttributesFile, NtQueryFullAttributesFile, NtQueryInformationFile,
  NtQueryVolumeInformationFile (FileFsDeviceInformation) ; sections (`sys::section`) : NtCreateSection (fichier
  d'échange, données, image d'un fichier ouvert), NtOpenSection, NtMapViewOfSection, NtUnmapViewOfSection. `smss` met
  21 sections d'image dans `\KnownDlls`. NtQuerySystemInformation(`SystemProcessorInformation`) fait (décodage de
  CPUID dans `hal::cpuid`). Registre en écriture fait, en mémoire : une ruche montée est un arbre de clés
  (`cm::HiveKey`) ; NtCreateKey, NtSetValueKey, NtDeleteValueKey ; la ruche HARDWARE, volatile, bâtie au démarrage
  (`ntoskrnl::hardware`). `smss` écrit ses variables d'environnement, puis ne trouve pas `csrss.exe` (M5) : le premier
  critère du M4 est coché. FAT32 en écriture fait, sur le disque RAM : `tools/mkfat` écrit un vrai volume FAT32
  (`fsck.vfat` l'accepte) ; `FatVolume` écrit, `Volume` et `File` créent et écrivent ; NtCreateFile crée, NtReadFile,
  NtWriteFile, NtSetInformationFile, NtFlushBuffersFile. Disque système ATA fait : `hal::ata` (PIO, lecture,
  écriture, FLUSH CACHE), `io::disk::AtaDisk` ; un disque FAT32 au maître du canal secondaire devient
  `\Device\HarddiskVolume1`, et `C:` (sans lui, le disque RAM). Scénario `persistence` (`disk = system`, `boots = 2`,
  `fsck.vfat` sur l'image) : le critère 3 du M4 est coché. Ruches réécrites sur disque : une ruche
  lue d'un fichier s'y réécrit en entier, sans ses clés volatiles (`cm::HiveFile::flush`, `regf::builder` avec
  classes et dates), NtFlushKey ; scénario `registry-persistence` (une valeur et l'empreinte de la ruche SYSTEM
  relues au second démarrage) : les trois critères sont cochés, **le M4 est terminé**. Ses dettes sont dans la
  passation.
  Suite : [`docs/passation.md`](docs/passation.md).
- Le code actuel suit l'ancienne architecture (Win32 dans le noyau). **Ne pas étendre** : la partie Win32 de `kernel/ntoskrnl/src/syscall.rs`,
  le générateur de stubs de `kernel/ps/src/loader.rs`, `kernel/ntoskrnl/src/launcher.rs`, `win32/*`, `directx/*`.
  Avant de les supprimer, extraire la connaissance utile dans `docs/compat/` (audit §5).

## Commandes

`cargo xtask` (02 §9.2, `xtask/`) :

```bash
cargo xtask lint                                     # cargo fmt --check, clippy -D warnings (hôte et bare-metal)
cargo xtask test                                     # tests hôte, puis scénarios de démarrage QEMU (tests/boot/)
cargo xtask test --boot --scenario smoke --cpu intel # un scénario, un CPU
cargo xtask run [--cpu intel] [--gdb] [--headless]   # démarre dans QEMU, port série sur stdio
cargo xtask build [--features trace-syscalls]        # mino-loader et ntoskrnl
cargo xtask syscall-gen                              # régénère abi/src/services.rs (listes de ReactOS épinglé)
cargo xtask fetch-userland [--archive FICHIER]       # ReactOS épinglé : archive vérifiée, arborescence dans third_party/
cargo xtask help
```

Et directement :

```bash
cargo check --workspace
cargo build -p ntoskrnl --target x86_64-unknown-none --profile kernel [--features trace-syscalls]
cargo build -p mino-loader --target x86_64-unknown-uefi --profile kernel
```

- Un scénario de démarrage est un répertoire de `tests/boot/` dont `scenario.txt` donne les features du noyau, les CPU,
  les marqueurs série attendus et interdits.
  Le run s'arrête dès que le verdict est connu ; journaux dans `target/xtask/boot/<scénario>-<cpu>/`.
- Tout compile sans warning. Sur l'hôte, on peut le vérifier avec `RUSTFLAGS="-D warnings"`, mais pas pour les cibles bare-metal,
  où `RUSTFLAGS` remplacerait les options de `.cargo/config.toml`.
- Les scénarios `requires = userland` demandent `cargo xtask fetch-userland` ; `requires = native` demande MinGW
  (`i686-w64-mingw32-gcc`, paquet `gcc-mingw-w64-i686`), clang, `lld-link` et `llvm-dlltool` (paquets `clang`, `lld`,
  `llvm`). Sans eux, ils sont sautés.
- `disk = system` attache l'image du disque RAM comme disque système ATA (`C:`), `boots = N` démarre QEMU N fois sur
  elle (scénario `persistence`) ; `fsck.vfat` (paquet `dosfstools`) vérifie ensuite l'image.
- `trace-syscalls` active la trace série des appels système, `heartbeat` le battement du timer (`[alive] tick=N`). Le CPU par défaut de QEMU annonce un fabricant AMD (chemin `int 2Eh`) ;
  `--cpu intel` exerce le chemin SYSENTER.
- Formatage : `cargo fmt --all` (rustfmt.toml). Un lint justifié à garder se marque `#[expect(clippy::…, reason = "…")]`.
- La CI (`.github/workflows/ci.yml`) exécute `cargo xtask lint` et `cargo xtask test`, avec les builds bare-metal sans warning.
