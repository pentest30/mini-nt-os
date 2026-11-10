# 04 — Audit du code existant et plan de réutilisation

*Audit du commit `6d3e235`, 28 octobre 2026, réévalué au regard de l'objectif « clone XP » décrit dans [01 — Vision](01-vision.md) et de l'architecture de [02 — Architecture](02-architecture.md). Ce document remplace `AUDIT-2026-10-28.md`.*

---

## 1. Résumé

| | Lignes de Rust | Part |
|---|---:|---:|
| Code repris tel quel ou avec adaptations mineures | ~7 200 | 34 % |
| Code repris après refonte (API ou tests conservés, implémentation réécrite) | ~4 600 | 22 % |
| Code abandonné ou conservé seulement comme référence | ~9 200 | 44 % |
| **Total** | **~21 000** | |

**Verdict.** Les couches matérielles (chargeur, HAL, mémoire physique), le parseur PE, le pilote FAT et les outils sont de bonne facture et se réutilisent.

Tout ce qui imite Windows **dans le noyau**, c'est-à-dire les ~3 300 lignes de handlers Win32 et les ~3 000 lignes de stubs en code machine, disparaît. Ce rôle revient désormais à l'espace utilisateur ReactOS (ADR-002).

Le cœur du noyau (Ke, Ob, Ps, VAD) doit être réécrit pour suivre le modèle NT, mais ses tests et une partie de ses interfaces servent de base.

**Ce qui bloque la suite**, dans l'ordre :

1. le noyau est lié en bas de l'espace d'adresses (§4.1) ;
2. il n'existe qu'un seul espace d'adresses ;
3. des corruptions mémoire ont été contournées au lieu d'être comprises (§4.2).

---

## 2. Méthode et limites

- **Lecture** : `ke/`, la HAL (`idt`, `sysenter`, `irql`, `gdt`), `mm/vad` et `virtual_alloc`, `bootloader`, `kernel.ld`, les parties structurantes de `syscall.rs` et `loader.rs`, et les documents `CLAUDE.md`, `ARCHITECTURE.md` et `tasks.md`.
- **Compilation et tests** : avec rustc 1.97 stable et `RUSTC_BOOTSTRAP=1`, pour la cible hôte, faute d'avoir pu télécharger le nightly épinglé. **Je n'ai pas démarré le système dans QEMU.**
- **Historique Git** : 15 commits sur environ 11 heures, sans valeur pour juger l'évolution du code.

| Commande | Résultat |
|---|---|
| `cargo check --workspace` | ❌ Les crates `cdylib` `no_std` (`win32/*`, `directx/*`) n'ont pas de `panic_handler` sur l'hôte |
| `cargo check -p kernel` | ✅ 11 warnings (55 sur le workspace) |
| `cargo test -p mm` / `ke` / `bump-alloc` / `io-manager` | ✅ 49 / 29 / 13 / 2 tests. ❌ Les doctests de `ke` ne compilent pas. |
| `cargo test -p ps` | ❌ Les tests sont périmés (`load_image` a changé de signature) |

---

## 3. Table de réutilisation, fichier par fichier

Légende :

- ✅ **Reprendre** : déplacer avec `git mv`, corriger à la marge.
- 🔧 **Refondre** : garder l'API et les tests, réécrire l'implémentation.
- 📚 **Référence** : ne pas reprendre le code, mais en extraire la connaissance.
- ❌ **Abandonner**.

### 3.1 Démarrage et HAL

| Source | Lignes | Verdict | Destination | Travail |
|---|---:|---|---|---|
| `bootloader/src/main.rs`, `memory.rs` | 349 | ✅ | `boot/loader/` | Charger un **ELF** au lieu d'un binaire plat (ADR-014), lire le hive `SYSTEM`, remplir `LOADER_BLOCK` |
| `bootloader/src/paging.rs` | 177 | ✅ | `boot/loader/` | Mapper le noyau en haut de l'espace, et ne garder le mapping identité que pendant la transition |
| `bootloader/src/loader.rs` | 131 | 🔧 | `boot/loader/` | Remplacer par un chargeur ELF, en reprenant la lecture de fichier UEFI |
| `boot-info/` | 226 | ✅ | `abi/src/loader_block.rs` | Ajouter un champ de version, le hive, la ligne de commande, le RSDP |
| `hal/src/gdt.rs` | 192 | ✅ | `kernel/hal/` | Une GDT et un TSS par CPU, un descripteur TEB mis à jour à chaque commutation, RSP0 par thread |
| `hal/src/timer.rs` | 326 | ✅ | `kernel/hal/` | Calibrage APIC/PIT conservé. Brancher `KeUpdateSystemTime` et la mise à jour de `KUSER_SHARED_DATA` |
| `hal/src/serial.rs`, `msr.rs` | 189 | ✅ | `kernel/hal/`, `drivers/misc/serial` | — |
| `hal/src/irql.rs` | 206 | ✅ | `kernel/hal/` | Garder le type `Irql` et l'implémentation par TPR. Retirer l'abus de `spin::Mutex` comme substitut d'IRQL. |
| `hal/src/fb.rs` | 557 | ✅ | `drivers/video/gopfb` | En faire l'implémentation du trait `DisplayDriver`. Garder la console texte pour l'écran de démarrage et l'écran d'erreur fatale. |
| `hal/src/ps2.rs` | 190 | ✅ | `drivers/input/i8042` | Brancher sur le modèle IRP et ajouter la souris |
| `hal/src/ata.rs` | 99 | ✅ | `drivers/storage/ata` | Ajouter l'écriture et un IRP par requête |
| `hal/src/idt.rs` | 542 | 🔧 | `kernel/hal/` et `kernel/ke/trap.rs` | Garder les handlers d'exception et le diagnostic de faute de page (`pf_dump_pte`). Réécrire l'entrée syscall, la trame et le dispatch des exceptions. |
| `hal/src/sysenter.rs`, `ring3.rs` | 211 | 🔧 | `kernel/ke/trap.rs` | Pile par thread, IF=1, sélection par CPUID (ADR-004) |

### 3.2 Exécutif

| Source | Lignes | Verdict | Destination | Travail |
|---|---:|---|---|---|
| `bump-alloc/` | 284 | 🔧 | `kernel/mm/pool.rs` | Remplacer par un allocateur à dalles. Les tests deviennent des tests de non-régression. |
| `mm/src/buddy.rs` | 247 | ✅ | `kernel/mm/` | Ajouter la base PFN par-dessus |
| `mm/src/paging.rs` | 349 | ✅ | `kernel/mm/` | Rendre paramétrable par PML4 (une par processus) |
| `mm/src/vad.rs` | 480 | 🔧 | `kernel/mm/vad.rs` | **Garder les 23 tests.** Passer du tableau de 64 entrées à un arbre AVL, et ajouter les états réservé et commité par page. |
| `mm/src/virtual_alloc.rs` | 489 | 🔧 | `kernel/mm/virtual.rs` | Garder les 22 tests. Réécrire réservation et commit séparés, la libération réelle, `NtProtectVirtualMemory` et `NtQueryVirtualMemory`. |
| `ke/src/thread.rs` | 298 | ✅ partiel | `kernel/ke/` | Garder `KContext` et `context_switch_raw` (assembleur). Ajouter la zone FPU. |
| `ke/src/scheduler.rs` | 718 | 🔧 | `kernel/ke/sched.rs` | Garder la `ReadyQueue` en anneau et ses tests. Réécrire le reste : 32 priorités, état `Waiting`, piles avec page de garde. |
| `ke/src/event.rs`, `apc.rs`, `dpc.rs` | 166 | ❌ | — | Remplacés par `dispatcher.rs` (ADR-005), et par des APC et DPC sans allocation |
| `ob/` | 219 | 🔧 | `kernel/ob/` | Garder la numérotation des handles (multiples de 4). Réécrire l'en-tête d'objet, les types, les répertoires, les liens symboliques et le *parse*. |
| `ps/src/eprocess.rs`, `ethread.rs` | 94 | ❌ | `kernel/ps/` | À réécrire (aucun espace d'adresses, aucun thread rattaché) |
| `ps/src/peb.rs`, `teb.rs` | 202 | ✅ | `abi/src/peb32.rs`, `teb32.rs` | Layouts XP utiles. Ajouter des assertions de taille et d'offset. |
| `ps/src/loader.rs`, parseur PE (~l. 1–380 et 3404–3770) | ~1 100 | ✅ | `libs/pe/` | Sert aux sections d'image (Mm), à la résolution des exports de `ntdll` par le noyau, et à `pe-inspect` |
| `ps/src/loader.rs`, `setup_process` (~l. 3773–3936) | ~160 | 📚 | — | Référence pour remplir PEB et TEB. Le travail revient à `ntdll!LdrInitializeThunk`. |
| `ps/src/loader.rs`, générateur de stubs (~l. 377–3400) | ~3 000 | 📚 → ❌ | — | Extraire la liste des imports rencontrés (`STUB_EXPORTS_*`) dans `docs/compat/` comme référence de couverture, puis supprimer le code |
| `io/src/fat.rs`, `lib.rs` | 911 | ✅ | `drivers/fs/fat` | Brancher derrière Io (IRP_MJ_CREATE, READ, QUERY_INFORMATION…), puis ajouter l'écriture (ADR-017) |
| `io/src/irp.rs`, `driver.rs`, `file.rs` | 124 | 🔧 | `kernel/io/` | Partir de ces squelettes |

### 3.3 Binaire noyau, Win32, DirectX, outils

| Source | Lignes | Verdict | Destination | Travail |
|---|---:|---|---|---|
| `kernel/kernel.ld`, `build.rs` | — | 🔧 | `kernel/ntoskrnl/` | Lier en haut de l'espace (ADR-014) |
| `kernel/src/main.rs` (init) | ~400 | ✅ partiel | `kernel/ntoskrnl/init.rs` | Garder l'ordre d'initialisation et le mapping du tas. Sortir le shell et les démos du chemin de démarrage. |
| `kernel/src/main.rs` (shell, démos, `build_test_pe32`) | ~700 | 📚 | `tests/boot/` | `build_test_pe32` est utile comme générateur de PE de test pour les scénarios QEMU |
| `kernel/src/syscall.rs`, partie NT (~l. 1–1 370) | ~1 400 | 🔧 | `kernel/{ps,io,mm}/` | La logique de `nt_create_file`, `nt_read_file` et `nt_allocate_virtual_memory` sert de base. Les handlers sont réécrits sur les primitives de sonde et la table générée. |
| `kernel/src/syscall.rs`, Win32, UCRT, advapi, registre factice, vk (~l. 1 370–4 646) | ~3 300 | ❌ | — | Remplacés par les DLL ReactOS. Les **quirks** sont reportés dans `docs/compat/ghost-recon.md`. |
| `kernel/src/launcher.rs` | 423 | ❌ | — | Le lanceur natif n'a plus de raison d'être (ADR-019) |
| `win32/*`, `directx/*` | 1 060 | ❌ | — | Code mort qui casse `cargo check --workspace`. À retirer du workspace dès maintenant. |
| `tools/mkfat` | 1 133 | ✅ | `tools/mkimage` | L'étendre à GPT, ESP et volume système |
| `tools/pe-loader` | 95 | ✅ | `tools/pe-inspect` | Basculer sur `libs/pe` |
| `tools/*.ps1`, `*.sh` | — | 📚 | `xtask/` | Reprendre les options QEMU et VBox qui marchent |
| `docs/mino-nt-expert-skill.skill` | — | ✅ | `docs/` | Le mettre à jour avec la nouvelle architecture |
| `dispatcher.rs` (produit le 28/10) | 666 | ✅ | `kernel/ke/dispatcher.rs` | Point de départ du jalon M1 |

---

## 4. Défauts à corriger pendant la migration

### 4.1 🔴 Le noyau est lié en bas de l'espace d'adresses

`kernel/kernel.ld` fixe `. = 0x00100000`, et le chargeur saute à `HHDM + 0x100000`. Toutes les adresses absolues du noyau (variables statiques, tables de fonctions, vtables) valent donc environ `0x001xxxxx` : elles se trouvent **dans la plage utilisateur**, et ne fonctionnent que grâce au mapping identité 0–4 Gio du chargeur.

Conséquences :

- impossible d'avoir des espaces d'adresses par processus propres ;
- l'image `.exe` en `0x400000` entre en collision avec le noyau si celui-ci dépasse 3 Mio.

→ ADR-014.

### 4.2 🔴 Des corruptions mémoire contournées au lieu d'être diagnostiquées

Trois contournements portent la même signature :

- « `linked_list_allocator` corrompt » (`bump-alloc`) ;
- « BTreeMap corrompt » (`vad.rs`) ;
- « un gros `Result` est peu fiable sous LTO » (`loader.rs:3543`).

**Hypothèse principale :** un débordement de pile noyau. La pile idle fait 4 Kio et chaque thread utilisateur a 8 Kio **alloués dans le tas**, sans page de garde, alors que les handlers posent de gros tampons sur la pile. Corriger ce point est un prérequis du jalon M0.

### 4.3 🔴 Un seul espace d'adresses

- Il n'y a pas de CR3 par processus, et une seule `VadTree` globale (`SYSCALL_CTX`).
- `install()` jette la VAD qu'on lui passe.
- Le mapping identité superviseur recouvre l'espace utilisateur : un pointeur utilisateur invalide **lit de la mémoire physique** au lieu de provoquer une faute.

→ §4 de l'architecture.

### 4.4 🔴 Ni threads ni synchronisation réels

- `KEvent` n'a pas de file d'attente.
- `WaitForSingleObject` et `WaitForMultipleObjects` renvoient `WAIT_OBJECT_0` sans attendre.
- `CreateThread` renvoie un handle factice (`0x100`) et le thread ne s'exécute jamais.
- `Sleep` ne fait rien.
- Les sections critiques écrivent `LockCount` sans rien verrouiller.
- Le scheduler gère 8 threads au maximum, sans priorités.

→ ADR-005.

### 4.5 🔴 Mémoire utilisateur

- La VAD est limitée à 64 entrées, et `malloc` et `HeapAlloc` appellent chacun `VirtualAlloc` (avec une granularité de 64 Kio) : **la 65ᵉ allocation échoue**.
- Réserver puis commiter échoue : la seconde insertion chevauche la réservation.
- `free`, `VirtualFree` et `VirtualProtect` ne font rien.

→ §5.3 de l'architecture. Le tas utilisateur vient de `ntdll` (RtlHeap).

### 4.6 🔴 Pas d'exceptions

- Une faute en mode utilisateur tue le thread.
- Le noyau accède aux pointeurs utilisateur avec une simple vérification d'intervalle, sans récupération de faute.

→ §6.4 et §6.5 de l'architecture.

### 4.7 🟠 Entrée des appels système

- SYSENTER est codé en dur, et il **provoque une `#UD` sur AMD**.
- Le handler utilise une seule pile `SYSENTER_ESP` partagée par tous les threads, et s'exécute avec IF=0 pendant tout l'appel.
- Les threads utilisateur démarrent avec **IOPL=3** (`scheduler.rs:377`).
- L'état FPU/SSE n'est jamais sauvegardé.

→ ADR-004, ADR-009.

### 4.8 🟠 Des collisions de numéros d'appel en ce moment même

- `0x20B7` = `GetFileType` **et** `WideCharToMultiByte` (`syscall.rs:123` et `:131`).
- `0x2033` = `CreateFileA` **et** `timeGetDevCaps` (`syscall.rs:141`).

Ce code est voué à disparaître, mais tant qu'il sert, il faut corriger ces collisions.

### 4.9 🟡 Divergences et hygiène

- **PEB et TEB inversés** par rapport à XP (`loader.rs:3777`).
- Les numéros d'appel de `CLAUDE.md` ne correspondent pas à ceux du code.
- 542 `unsafe` pour 187 `// SAFETY:`.
- 55 warnings.
- Les tests de `ps` ne compilent plus.
- Une trace série s'exécute à chaque appel système `0x20xx` (`syscall.rs:270`).

---

## 5. La connaissance à conserver (sans le code)

Le code Win32 dans le noyau disparaît, mais il contient des informations acquises sur Ghost Recon qu'il faut garder dans `docs/compat/` :

| Fichier à créer | Source | Contenu |
|---|---|---|
| `docs/compat/ghost-recon.md` | `CLAUDE.md` (« Known GR quirks »), handlers `win32_*` | Clés de registre lues, `QueryPerformanceFrequency`, `timeBeginPeriod(1)`, mutex nommé `DirectDrawDeviceHandle`, conflit avec `dbghelp.dll`, option `-nointro` |
| `docs/compat/imports-observes.md` | Tables `STUB_EXPORTS_*` de `loader.rs` | Liste des DLL et fonctions importées par Ghost Recon, son CRT, DXVK et les programmes de test : une première carte de couverture |
| `docs/compat/d3d8-appels.md` | `write_d3d8_page` | Méthodes `IDirect3D8` et `IDirect3DDevice8` effectivement appelées pendant l'initialisation |
| `tests/native/` | `build_test_pe32`, `HELLO.EXE` | Programmes PE de test pour les scénarios QEMU |

---

## 6. Procédure de migration

1. **Créer l'arborescence cible** ([02 — Architecture §10](02-architecture.md#10-organisation-du-dépôt-cible)) avec des crates vides qui compilent.
2. **Déplacer avec `git mv`** les éléments ✅, un composant par commit, pour garder l'historique.
3. **Retirer du workspace** `win32/*`, `directx/*` et `kernel/src/launcher.rs`. Les supprimer après extraction de la connaissance (§5).
4. **Séparer** le parseur PE de `ps/src/loader.rs` dans `libs/pe`, puis archiver le reste du fichier dans `docs/archive/` (comme référence, sans le compiler).
5. **Ne pas** faire de compatibilité avec l'ancien `syscall.rs`. Le nouveau chemin (table générée et `ntdll` ReactOS) se construit à côté, jusqu'au spike S1, puis l'ancien est supprimé d'un bloc.
6. Les tests existants (`mm`, `ke`, `bump-alloc`, `io`) doivent passer à chaque étape. Ceux de `ps` sont réparés ou supprimés avec le code qu'ils testent.

---

## 7. Corrections à faire tout de suite (avant le jalon M0)

| # | Fichier | Correction |
|---|---|---|
| 1 | `Cargo.toml` | Retirer `win32/*` et `directx/*` de `members` |
| 2 | `kernel/src/syscall.rs:123`, `:141` | Supprimer les deux collisions et ajouter `#![deny(unreachable_patterns)]` |
| 3 | `executive/ke/src/scheduler.rs:377` | RFLAGS utilisateur à `0x202` (IOPL=0) |
| 4 | `executive/ps/src/loader.rs:1286` | Repli sur `int 2Eh` si le CPU n'est pas Intel |
| 5 | `executive/ke/src/*.rs` | Remplacer le tiret cadratin dans les blocs de doc pour réparer les doctests |
| 6 | `executive/ps/src/loader.rs` (tests) | Adapter les tests à la signature à 5 arguments de `load_image` |
| 7 | `kernel/src/syscall.rs:270` | Placer la trace série derrière une feature `trace-syscalls` |
