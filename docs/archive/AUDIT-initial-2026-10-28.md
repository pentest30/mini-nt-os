# Audit du dépôt `mini-nt-os` (Mino)

*28 octobre 2026. Dépôt audité : `D:\XP clone\mini-nt-os`, branche `main`, commit `6d3e235`.*

---

## 1. Verdict

**Il faut refondre ce code, pas le jeter.** Les couches basses sont saines et se gardent. Le cœur du système (ordonnancement, synchronisation, espace d'adresses, frontière des syscalls) est un échafaudage. Il a permis d'aller vite jusqu'à « le CRT de Ghost Recon s'initialise », mais il ne supportera pas un vrai jeu. La stratégie graphique (DXVK sur un faux `vulkan-1.dll`) est une impasse.

| Verdict | Part du code | Contenu |
|---|---|---|
| ✅ **Garder** (avec correctifs) | ≈ 35 % | bootloader UEFI, `boot-info`, HAL (GDT, TSS, APIC, série, PS/2, framebuffer, ATA), allocateur buddy, wrapper de pagination, parseur PE32 (imports, relocations, exports), lecteur FAT32, outils hôte |
| 🔧 **Refondre** (garder l'API ou l'idée) | ≈ 25 % | VAD, VirtualAlloc, IDT et entrée syscall, scheduler, Ob, PEB/TEB/`setup_process` |
| ❌ **Remplacer** | ≈ 40 % | les handlers Win32 en noyau (`kernel/src/syscall.rs`), le générateur de stubs en code machine (`ps/src/loader.rs`), le faux ICD Vulkan, les crates mortes `win32/*` et `directx/*`, le `KEvent` sans file d'attente |

Le plus urgent n'est pas une fonctionnalité. Ce sont **des symptômes de corruption mémoire contournés au lieu d'être compris** (§4.8) : il faut les élucider avant d'empiler davantage de code.

---

## 2. Méthode et limites

- **Taille** : 21 000 lignes de Rust réparties en 20 crates. Lecture complète de `ke/`, de la HAL (`idt`, `sysenter`, `irql`), de `mm/vad` et `virtual_alloc`, des parties structurantes de `syscall.rs` et `loader.rs`, et de `CLAUDE.md`, `ARCHITECTURE.md` et `tasks.md`. Le reste a été lu par échantillonnage.
- **Compilation** : le nightly épinglé (`nightly-2026-03-10`) n'était pas téléchargeable dans mon environnement. J'ai donc compilé avec rustc 1.97 stable et `RUSTC_BOOTSTRAP=1`, pour la cible hôte. Les résultats sont indicatifs. Je n'ai rien compilé pour `x86_64-unknown-none`.
- **Exécution** : je n'ai pas démarré le système dans QEMU ou VirtualBox. Les comportements au boot sont déduits du code.
- **Historique Git** : 15 commits sur environ 11 heures (18 et 19 mars 2026). L'historique a visiblement été importé ou écrasé, donc il ne renseigne pas sur l'évolution du projet.

### Résultats de build et de tests

| Commande | Résultat |
|---|---|
| `cargo check --workspace` (commande du README) | ❌ échoue : `kernel32`, `dinput8` et les autres crates `cdylib` `no_std` n'ont ni `panic_handler` ni allocateur sur l'hôte |
| `cargo check --workspace --exclude kernel32` | ❌ échoue sur `dinput8` (même cause) |
| `cargo check -p kernel` | ✅ passe, avec 11 warnings (55 au total sur le workspace) |
| `cargo test -p mm` | ✅ 49 tests |
| `cargo test -p ke` | ✅ 29 tests unitaires, ❌ les doctests ne compilent pas (tiret cadratin `—` dans un bloc de code) |
| `cargo test -p bump-alloc` | ✅ 13 tests |
| `cargo test -p io-manager` | ✅ 2 tests |
| `cargo test -p ps` | ❌ **ne compile pas** : les tests sont périmés (`load_image` prend 5 arguments, les tests en passent 4) |
| `ob`, `hal`, `boot-info` | 0 test |

---

## 3. Ce que la documentation dit et ce que fait le code

| Sujet | Documentation | Code |
|---|---|---|
| D3D8 | « D3D8 COM chain works », DXVK chargé | `GetProcAddress` **retombe sur les vtables D3D8 écrites à la main** dans `write_d3d8_page` (`syscall.rs:1707`). DXVK est chargé mais pas réellement utilisé. |
| Vulkan | « `vulkan-1.dll` ~500 lignes » | ~30 syscalls qui renvoient des handles factices (`VK_FAKE_PHYS_DEV = 0xDE001000`). `vkQueuePresentKHR` blitte une zone 800×600 vers le framebuffer. Aucun GPU derrière. |
| Synchronisation | « Ke: KEvent, scheduler, APC/DPC ✅ » | `KEvent` n'a **pas de file d'attente** (`// TODO: wake waiters`). `WaitForSingleObject` et `WaitForMultipleObjects` renvoient `WAIT_OBJECT_0` sans rien attendre. |
| Threads | `CreateThread` | Renvoie le handle factice `0x100`, et le thread **n'est jamais lancé**. |
| Numéros de syscall | `CLAUDE.md` : NtTerminateProcess = `0x101`, NtCreateProcess = `0x4F`, NtReadFile = `0xF6`, NtQueryInformationFile = `0xEF` | Code : `0xC2`, `0x1B`, `0xB7` et `0xB4`. Les deux sources divergent, et une partie des valeurs du code ne correspond pas non plus à XP SP2. |
| PEB/TEB | `CLAUDE.md` : PEB `0x7FFDF000`, TEB `0x7FFDE000` (valeurs d'XP) | `loader.rs:3777` : **c'est l'inverse** (PEB `0x7FFDE000`, TEB `0x7FFDF000`). |
| Chemin des syscalls | « TestRetInstruction, INT 0x2E path, max compat » | Le stub ntdll utilise **SYSENTER en dur** (`USE_SYSENTER_STUB = true`). |
| Crates `win32/*` et `directx/*` | « Win32 stubs (exist) » | **Code mort** : aucune crate ne les référence. La vraie implémentation se trouve dans `syscall.rs` et `loader.rs`. |

---

## 4. Problèmes structurels, par gravité

### 4.1 Un seul espace d'adresses pour tout le système 🔴

- Il n'y a **pas de CR3 par processus**. Tout tourne dans les tables de pages du bootloader.
- `SYSCALL_CTX` (`syscall.rs:210`) contient **une seule** `VadTree` globale. En plus, `install()` jette la VAD reçue en paramètre (`mem::forget(vad)`) et en crée une vide à la place.
- `nt_create_process` charge chaque image dans le même espace. Deux processus finiraient donc tous les deux à `0x400000`.
- Le bootloader mappe 0 à 4 Gio **en identité, en pages superviseur**, ce qui recouvre tout l'espace utilisateur (0 à 2 Gio). Conséquence : quand le noyau déréférence un pointeur utilisateur non mappé côté utilisateur, il **ne fait pas de page fault**. Il lit de la mémoire physique quelconque.

**À faire :** une PML4 par `KPROCESS`, avec la moitié haute (noyau) partagée. Supprimer le mapping identité bas une fois le noyau démarré. Associer une VAD et une table de handles à chaque processus.

### 4.2 Ni vrais threads ni vraie synchronisation 🔴

- Le scheduler est un round-robin limité à `MAX_THREADS = 8`, sans priorités, sans état bloqué ni files d'attente. Un thread ne peut **pas** dormir sur un objet.
- `Sleep` ne fait rien (`syscall.rs:289`).
- `EnterCriticalSection` écrit simplement `LockCount = 0`, et les SRW locks écrivent `1` ou `0`. Ça ne tient qu'en mono-thread, ce qui revient à dire que rien n'est implémenté.
- Les APC et les DPC se résument à des `VecDeque`. Personne ne délivre les APC, et la file des DPC alloue sur le tas, alors que `CLAUDE.md` l'interdit à DISPATCH_LEVEL.

C'est rédhibitoire pour la cible : **DXVK est fortement multithreadé** (thread CS, thread de soumission, workers de compilation de pipelines). La plupart des moteurs de 2001 à 2007 créent eux aussi au moins un thread audio et un thread de chargement.

**À faire :** le dispatcher NT (`KWAIT_BLOCK`, `KiWaitTest`, timeouts, APC) livré plus tôt dans cette conversation (`dispatcher.rs`), un scheduler à 32 niveaux de priorité, et un état `Waiting` réel.

### 4.3 Gestion mémoire utilisateur non viable 🔴

- `MAX_VAD = 64` (`vad.rs`), dans un tableau trié.
- `malloc`, `calloc` et `HeapAlloc` appellent **chacun `VirtualAlloc`**, avec une granularité de 64 Kio. **La 65ᵉ allocation échoue**, et chaque `malloc(16)` consomme une page physique.
- `free` et `HeapFree` ne libèrent rien, `VirtualFree` non plus, et le tas noyau est un bump allocator de 4 Mio qui ne libère jamais.
- **Réserver puis commiter échoue** : le second `VirtualAlloc(addr, MEM_COMMIT)` insère un nouveau nœud VAD qui chevauche la réservation et renvoie `NULL`. Or c'est exactement le schéma du tas MSVC et de la plupart des moteurs.
- `VirtualProtect` renvoie `TRUE` sans rien changer.
- Tout est commité immédiatement : pas de demand paging, pas de pages de garde, pas de croissance de pile.

**À faire :** une VAD en arbre (AVL ou BTreeMap, une fois l'allocateur fiabilisé) qui gère proprement les états reserve, commit et decommit, des fautes de page résolues à la demande, et surtout **un tas en espace utilisateur** (RtlHeap dans ntdll). `malloc` ne doit jamais coûter un syscall.

### 4.4 Win32 réimplémenté dans le noyau avec des stubs en code machine 🔴

- Chaque API Win32 correspond à un **syscall privé** (`0x2000` et suivants). Ça inclut `strlen`, `memcpy`, `memset`, `strcmp`, `wcslen` et les autres fonctions de chaînes : la moindre opération du CRT provoque une transition ring 3 → ring 0.
- Les DLL vues par le jeu sont **générées à la volée en octets x86** : environ 185 `write_unaligned` et plus de 2 000 lignes dans `loader.rs`, avec des offsets codés en dur. La table `StubExport { rva }` et `initialise_stub_module_code` doivent rester synchronisées à la main.
- **Il y a des collisions de numéros en ce moment même** (le compilateur les signale comme `unreachable pattern`) :
  - `0x20B7` = `WIN32_GET_FILE_TYPE` **et** `WIN32_WIDE_TO_MULTI_BYTE` (`syscall.rs:123` et `:131`). **`WideCharToMultiByte` exécute en réalité `GetFileType`.**
  - `0x2033` = `WIN32_CREATE_FILE_A` **et** `WIN32_TIME_GET_DEV_CAPS` (`syscall.rs:141`). **`timeGetDevCaps` exécute en réalité `CreateFileA`.**
- Sur chaque syscall `0x20xx`, une écriture série en ligne s'exécute dans le chemin chaud (`dispatch`, `syscall.rs:270`).

Ce modèle ne passe pas à l'échelle. Ghost Recon importe déjà plusieurs centaines de fonctions, DXVK et le CRT plusieurs centaines d'autres, et chaque jeu supplémentaire en ajoute.

**À faire :** déplacer Win32 en espace utilisateur, dans de vraies DLL PE32 qui ne passent dans le noyau que par des appels `Nt*`. Deux options :

1. **Écrire ses propres DLL en Rust**, compilées pour `i686-pc-windows-msvc` ou `-gnu`. C'est à ça que devaient servir les crates `win32/*`, aujourd'hui mortes.
2. **Réutiliser les DLL utilisateur de ReactOS** (`ntdll`, `kernel32`, `user32`, `msvcrt`). Elles sont déjà écrites contre des syscalls NT : c'est le gain de couverture le plus important possible. Attention, la licence est GPL/LGPL alors que Mino est sous MIT, donc la décision de licence est à prendre avant.

Dans les deux cas, la frontière stable devient la table des syscalls NT, exactement comme sous XP.

### 4.5 Ni exceptions ni SEH 🔴

- Une page fault en mode utilisateur **tue le thread** (`idt.rs`, `USER_FAULT_HOOK`). Rien n'est dispatché vers `KiUserExceptionDispatcher`, et la chaîne `FS:[0]` est initialisée à `0xFFFFFFFF` sans jamais être parcourue.
- Les accès noyau aux pointeurs utilisateur se limitent à `is_user_range` (une vérification d'intervalle), sans vérifier le mapping ni rattraper la faute. Un pointeur invalide provoque une **panique du noyau**, ou, à cause du §4.1, une lecture silencieuse de mémoire physique.

Le CRT MSVC utilise `__try`, beaucoup de jeux de l'époque attrapent des access violations exprès (`IsBadReadPtr`, détection de CPU, protections), et DXVK utilise aussi les exceptions.

**À faire :** une trap frame complète, `KiDispatchException` vers `KiUserExceptionDispatcher` (SEH x86, chaîne `FS:[0]`), et des fonctions `probe_and_copy_from_user` / `copy_to_user` munies d'une table de fixup d'exceptions (sur le modèle de `__ex_table` sous Linux).

### 4.6 Entrée des syscalls et changement de contexte 🟠

- **SYSENTER depuis le mode compatibilité provoque une `#UD` sur les CPU AMD**, où SYSENTER n'est pas valide en long mode. À l'inverse, SYSCALL est invalide en mode compatibilité sur Intel. Or le stub ntdll utilise SYSENTER en dur, donc Mino plante sur un hôte AMD, VirtualBox compris. **À faire :** choisir le chemin au boot via CPUID, comme XP le faisait avec `SharedUserData->SystemCall` (SYSENTER sur Intel, `INT 0x2E` en repli).
- `IA32_SYSENTER_ESP` pointe vers **une seule pile noyau statique** pour tous les threads, et le handler s'exécute entièrement avec `IF=0`. Aucun syscall ne peut donc bloquer ni être préempté, ce qui rend toute attente impossible.
- **L'état FPU, x87 et SSE n'est jamais sauvegardé** (aucun `fxsave` ni `xsave` dans le code). Dès que deux threads utilisateur coexistent, leurs registres flottants se corrompent mutuellement, et les jeux en font un usage intensif.
- `spawn_user_thread` démarre les threads avec **IOPL=3** : le code utilisateur peut faire `cli`, `in` ou `out`. Le retour de SYSENTER utilise IOPL=0, ce qui est incohérent.
- Le changement de contexte a lieu **à l'intérieur** du handler `x86-interrupt` du timer. Ça tient en monoprocesseur, mais il n'existe pas de trap frame unifiée, et la même pile sert à la fois aux interruptions et aux syscalls.

### 4.7 La stratégie DirectX ne peut pas aboutir telle quelle 🟠

DXVK traduit D3D8 et D3D9 vers Vulkan, mais **Vulkan a besoin d'un pilote GPU** (RADV, ANV, NVIDIA…) ou d'une implémentation logicielle (lavapipe). Le « shim de 500 lignes » ne résout que la partie chargeur ICD, pas le pilote. Les options réalistes :

| Option | Coût | Commentaire |
|---|---|---|
| Écrire son propre `d3d8.dll` avec **un rasterizer logiciel** à pipeline fixe, rendu dans le framebuffer GOP | Moyen | Le plus réaliste pour une preuve de concept sur Ghost Recon (D3D8, 2001). Pas de pilote à écrire. |
| Porter **lavapipe** (Mesa + LLVM) en PE32 sous Mino, puis DXVK par-dessus | Très élevé | Exige des threads, de la synchronisation et de la mémoire complets. C'est un aboutissement à long terme, pas une étape. |
| Un pilote **VMSVGA / SVGA3D** ou **virtio-gpu avec virgl** | Élevé | De l'accélération en VM, mais sans Vulkan direct : il faut écrire sa propre traduction D3D8 vers SVGA3D ou Gallium. |
| DXVK sur un vrai pilote GPU constructeur | Hors de portée | — |

**À faire :** abandonner la règle « Do NOT implement D3D8 translation » de `CLAUDE.md` et viser un `d3d8.dll` utilisateur en rendu logiciel. Les vtables écrites à la main dans `write_d3d8_page` montrent déjà quelles méthodes Ghost Recon appelle : ce sont des données utiles, même si le code lui-même est à jeter.

### 4.8 Des corruptions mémoire contournées au lieu d'être diagnostiquées 🟠 (prioritaire)

On trouve dans le code et la documentation trois contournements qui ressemblent à un même bug latent :

- `bump-alloc` : « `linked_list_allocator` corrupts its free-list ». Cette crate est très utilisée, ce diagnostic est peu probable.
- `vad.rs` : « we observed corruption […] BTreeMap ». D'où le tableau fixe de 64 entrées.
- `loader.rs:3543` : « large-struct `Result` return […] unreliable under LTO ». D'où un paramètre de sortie.
- À quoi s'ajoute l'auto-vectorisation désactivée pour des raisons d'alignement des piles d'ISR.

**Hypothèse principale (non vérifiée) :** un **débordement de pile noyau**. La pile idle fait 4 Kio et celle de chaque thread utilisateur 8 Kio, allouée **au milieu du tas bump**, sans page de garde. Les handlers de syscall posent de gros tampons sur la pile (`[0u8; 260]`, lectures FAT, `Vec` de fichiers). Un débordement écrase silencieusement les structures voisines du tas, ce qui produirait exactement les symptômes « l'allocateur corrompt » et « BTreeMap corrompt ».

**À faire avant tout le reste :** des piles noyau de 16 à 24 Kio, allouées hors du tas avec une page de garde non mappée, plus un canari et une vérification de RSP dans le handler de double fault. Ensuite, réactiver BTreeMap et un vrai allocateur, et vérifier que la corruption a disparu.

### 4.9 Hygiène du dépôt 🟡

- 542 occurrences d'`unsafe` pour 187 commentaires `// SAFETY:`, alors que la règle de `CLAUDE.md` est d'en mettre un par bloc. Le pire ratio est dans `loader.rs` : 81 pour 17.
- `kernel/src/syscall.rs` fait 4 646 lignes et `ps/src/loader.rs` 4 304 lignes. Ces deux fichiers concentrent 43 % du code.
- 747 occurrences de `TODO`, `FIXME` ou `stub`.
- `nt_create_process` refuse les exécutables de plus de 256 Kio (`syscall.rs:653`).
- La documentation porte encore des « Phase 2.5 » et « Phase 3 » contradictoires (README, `ARCHITECTURE.md`, `CLAUDE.md`).

---

## 5. Inventaire par composant

| Composant | Lignes | État | Verdict | Action |
|---|---:|---|---|---|
| `bootloader/` | 657 | Fonctionne (UEFI, carte mémoire, paging 4 niveaux, HHDM) | ✅ Garder | Ne plus laisser le mapping identité 0 à 4 Gio en place après le boot |
| `boot-info/` | 226 | ABI `#[repr(C)]` propre | ✅ Garder | — |
| `hal/gdt.rs` | 192 | Segments 32 bits en mode compat, TSS, IST pour le double fault | ✅ Garder | Fournir une API de RSP0 par thread |
| `hal/timer.rs`, `serial`, `ps2`, `ata`, `fb`, `msr` | ~1 100 | Fonctionnels | ✅ Garder | `ata` en PIO convient pour l'instant |
| `hal/irql.rs` | 206 | Correct sur le principe | ✅ Garder | Le relier au dispatcher |
| `hal/idt.rs` | 542 | Handlers d'exception corrects, entrée syscall naïve | 🔧 Refondre | Trap frame unique, sauvegarde FPU, dispatch des exceptions |
| `hal/sysenter.rs`, `ring3.rs` | 211 | Pile unique, `IF=0`, problème AMD | 🔧 Refondre | Choix du chemin par CPUID, pile par thread |
| `bump-alloc/` | 284 | Fonctionne mais ne libère jamais | 🔧 Remplacer | Slab ou `linked_list_allocator` une fois le §4.8 réglé |
| `mm/buddy.rs` | 247 | Testé | ✅ Garder | — |
| `mm/paging.rs` | 349 | Wrapper sur `x86_64` | ✅ Garder | Le rendre paramétrable par CR3 |
| `mm/vad.rs`, `virtual_alloc.rs` | 969 | Bien testés, mauvaise sémantique (§4.3) | 🔧 Refondre | Garder les tests, réécrire reserve/commit, passer à un arbre |
| `ke/scheduler.rs`, `thread.rs` | 1 016 | Round-robin à 8 threads, pas d'attente | 🔧 Refondre | Garder `context_switch_raw` et le `KContext`, réécrire le reste |
| `ke/event.rs`, `apc.rs`, `dpc.rs` | 166 | Coquilles | ❌ Remplacer | Par `dispatcher.rs` |
| `ob/` | 219 | Table de handles en `Vec`, namespace | 🔧 Refondre | En-tête d'objet, comptage de références, types, fermeture effective |
| `ps/loader.rs`, partie parseur PE (~1–380, 3404–3770) | ~1 100 | Correct et testé (tests à réparer) | ✅ Garder | Le sortir dans une crate `pe` |
| `ps/loader.rs`, générateur de stubs (~380–3400) | ~3 000 | Fragile, offsets en dur | ❌ Jeter | En récupérer la liste des imports comme documentation |
| `ps/peb.rs`, `teb.rs`, `setup_process` | ~360 | Layouts XP utiles | ✅ Garder | Rétablir PEB `0x7FFDF000` et TEB `0x7FFDE000` |
| `io/fat.rs`, `io/lib.rs` | 911 | Lecture FAT32 fonctionnelle | ✅ Garder | L'exposer comme pilote derrière des IRP |
| `io/irp.rs`, `driver.rs`, `file.rs` | 124 | Coquilles | 🔧 Développer | — |
| `kernel/syscall.rs`, partie NT (~1–1 370) | ~1 400 | Utile mais sans validation sûre | 🔧 Refondre | Probe et copie depuis l'espace utilisateur, table de syscalls générée |
| `kernel/syscall.rs`, Win32, UCRT, advapi, vk (~1 370–4 646) | ~3 300 | Modèle à abandonner (§4.4, §4.7) | ❌ Remplacer | Par des DLL en espace utilisateur |
| `kernel/main.rs`, `launcher.rs` | 1 551 | Shell, démos, lanceur | 🔧 Nettoyer | Retirer les démos de smoke-test du chemin de boot |
| `win32/*`, `directx/*` | 1 060 | **Mort**, et casse `cargo check --workspace` | ❌ Retirer ou recycler | Ou en faire les vraies DLL PE32 |
| `tools/mkfat`, `pe-loader`, scripts QEMU et VBox | 1 228 + scripts | Utiles | ✅ Garder | — |

---

## 6. Plan de refonte proposé

L'ordre est imposé par les dépendances. Chaque étape a un critère de sortie vérifiable.

**Étape 0. Assainir (avant toute nouvelle fonctionnalité)**
- Piles noyau avec page de garde (§4.8). Réactiver BTreeMap et un allocateur qui libère.
- Corriger les collisions `0x20B7` et `0x2033`, retirer les crates mortes du workspace, réparer les tests de `ps` et les doctests de `ke`.
- Ajouter un smoke test QEMU sans affichage qui lit la sortie série, lancé en CI.
- *Critère de sortie :* `cargo check` et `cargo test` passent sur tout le workspace, et le smoke test boote.

**Étape 1. Ke**
- Intégrer le dispatcher (`dispatcher.rs`), un scheduler à 32 priorités, l'état `Waiting`, les timers, `KeDelayExecutionThread`.
- Sauvegarder l'état FPU (`fxsave`/`fxrstor`, ou `xsave`) à chaque changement de contexte.
- *Critère de sortie :* tests hôte du dispatcher (WaitAll partiel, mutant abandonné, timeout échu), et deux threads utilisateur qui se synchronisent par un événement en VM.

**Étape 2. Processus et mémoire**
- Une PML4 par processus, une VAD par processus, la sémantique reserve/commit/decommit, des fautes de page à la demande, des pages de garde de pile.
- *Critère de sortie :* deux processus PE chargés à `0x400000` simultanément.

**Étape 3. Frontière syscall NT**
- Une seule table `KiServiceTable` aux numéros XP SP2 vérifiés, générée depuis une source unique.
- Probe et copie depuis l'espace utilisateur avec fixup, choix SYSENTER ou `INT 0x2E` selon CPUID, IRQL passive pendant les syscalls.
- *Critère de sortie :* un `ntdll` de test qui appelle `NtCreateEvent`, `NtWaitForSingleObject` et `NtSetEvent` entre deux threads.

**Étape 4. Exceptions**
- `KiDispatchException`, `KiUserExceptionDispatcher`, SEH x86.
- *Critère de sortie :* un `__try { *(int*)0 = 0; } __except` compilé avec MSVC qui s'exécute correctement.

**Étape 5. Win32 en espace utilisateur**
- Trancher entre les DLL Rust maison et les DLL ReactOS (question de licence).
- `ntdll` avec RtlHeap, puis `kernel32`, `user32`, `msvcrt` ou ucrt.
- *Critère de sortie :* le CRT de Ghost Recon s'initialise **sans aucun syscall privé `0x20xx`**.

**Étape 6. Graphisme**
- Un `d3d8.dll` utilisateur avec rasterizer logiciel à pipeline fixe, présenté via un mapping du framebuffer fourni par le serveur d'affichage.
- *Critère de sortie :* Ghost Recon affiche son menu principal.

---

## 7. Corrections immédiates à faible coût

| # | Fichier | Correction |
|---|---|---|
| 1 | `kernel/src/syscall.rs:123` et `:141` | Renuméroter `WIN32_GET_FILE_TYPE` (ou `WIDE_TO_MULTI_BYTE`) et `WIN32_TIME_GET_DEV_CAPS`, puis passer `#![deny(unreachable_patterns)]` |
| 2 | `executive/ps/src/loader.rs:3777` | Rétablir PEB `0x7FFDF000` et TEB `0x7FFDE000` |
| 3 | `executive/ke/src/scheduler.rs:377` | RFLAGS des threads utilisateur avec IOPL=0 (`0x202`) |
| 4 | `executive/ps/src/loader.rs:1286` | Repli sur `INT 0x2E` si le CPU n'est pas Intel |
| 5 | `Cargo.toml` | Retirer `win32/*` et `directx/*` des `members`, ou les compiler seulement pour une cible i686-windows |
| 6 | `kernel/src/syscall.rs:270` | Placer la trace série par syscall derrière une feature `trace-syscalls` |
| 7 | `CLAUDE.md` | Aligner les numéros de syscall et les adresses sur le code, après vérification contre XP SP2, et retirer la règle « Do NOT implement D3D8 translation » |
