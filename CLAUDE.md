# Mino — contexte pour Claude Code

## Objectif

**Mino est un système d'exploitation libre, compatible Windows XP, dont le noyau est écrit en Rust.**
On démarre sur un bureau de style XP et on y lance, sans les modifier, des applications et des jeux 32 bits de l'ère XP (2001–2008).

- **Mino écrit en Rust tout le code privilégié** : `ntoskrnl`, la partie noyau de Win32 (`win32k`), les pilotes.
- **Mino réutilise l'espace utilisateur de ReactOS** (`ntdll`, `kernel32`, `user32`, `csrss`, `explorer`…), en binaires i386 d'une version épinglée.
- **La frontière stable du projet est l'interface noyau de ReactOS** : numéros et signatures des appels système `ntoskrnl` et `win32k`, structures en mode utilisateur, protocoles LPC de CSR.

---

## Documents de référence

Ces documents **font foi**. En cas de désaccord avec ce fichier, ce sont eux qui ont raison.

| Document | À lire quand |
|---|---|
| [`docs/01-vision.md`](docs/01-vision.md) | On se demande si quelque chose est dans le périmètre |
| [`docs/02-architecture.md`](docs/02-architecture.md) | On touche à un composant : rôle, interfaces, organisation cible du dépôt (§10) |
| [`docs/03-decisions.md`](docs/03-decisions.md) | On fait un choix structurant. Une ADR acceptée ne se modifie pas : on écrit une nouvelle ADR qui la remplace. |
| [`docs/04-audit-reutilisation.md`](docs/04-audit-reutilisation.md) | On travaille sur du code existant : verdict par fichier (reprendre, refondre, référence, abandonner) |
| [`docs/05-feuille-de-route.md`](docs/05-feuille-de-route.md) | On choisit quoi faire ensuite. Les jalons sont séquentiels. |
| [`docs/compat/`](docs/compat/) | On travaille sur la compatibilité d'une application (Ghost Recon : `ghost-recon.md`) |

`docs/06-conventions.md` est référencé mais pas encore rédigé. Les règles ci-dessous en tiennent lieu.

---

## Décisions structurantes (résumé)

| ADR | Décision |
|---|---|
| 001 | Noyau x86-64. Processus i386 **natifs** en mode compatibilité, sans WoW64 ni `ntdll` 64 bits. |
| 002 | Espace utilisateur ReactOS épinglé. Numéros d'appel système **générés** (`tools/syscall-gen`). *Proposée : spikes S1–S3.* |
| 003 | Version affichée : XP 5.1.2600 SP2 (`OSCSDVersion = 0x0200`). Le noyau sert aussi les appels NT 5.2 dont ReactOS a besoin. |
| 004 | `int 2Eh` partout ; SYSENTER sur Intel uniquement, choisi par CPUID via `SharedUserData->SystemCall` (offset `0x300`). |
| 005 | Dispatcher NT fidèle (`DISPATCHER_HEADER`, `KWAIT_BLOCK`, `KiWaitTest`), verrou global à `DISPATCH_LEVEL`. Base : `dispatcher.rs`. |
| 006 | 3D entièrement en mode utilisateur : `d3d8`/`d3d9`/`ddraw` (Wine) → wined3d → `opengl32` Mesa logiciel → GDI. **Aucun code 3D dans le noyau.** |
| 007 | Licence : **à décider** (GPL-2.0-or-later recommandée, ou MIT). |
| 008 | Pilotes en Rust, liés statiquement, modèle IRP. Jamais de `.sys` Windows. |
| 009 | `FXSAVE`/`XSAVE` à chaque commutation de thread utilisateur, pas de commutation paresseuse. Noyau compilé sans SSE. |
| 010 | Pas de fichier d'échange avant M10 (états PFN/PTE réservés). |
| 011 | Sécurité réelle (jetons, SID, ACL, `SeAccessCheck`), en mode permissif journalisé jusqu'à M10. |
| 012 | Registre au format `regf` (`libs/regf`), ruches générées par `tools/mkhive`. |
| 013 | Polices : `ttf-parser` + rastériseur Rust dans win32k. *Proposée.* |
| 014 | `ntoskrnl` en ELF64 lié à `0xFFFFFFFF80000000`, W^X, sans mapping identité après la phase 0. |
| 015 | Un seul CPU d'abord, structures prêtes pour le SMP (`KPRCB` par CPU via `GS`). |
| 016 | Nightly épinglé (`rust-toolchain.toml`). Dépendances noyau `no_std`, auditées, justifiées dans la PR. |
| 017 | `C:` en FAT32 (lecture et écriture) tant que NTFS n'est pas en écriture. |
| 018 | Conformance : tests hôte, scénarios QEMU à marqueurs série, `rostests`. |
| 019 | Les décisions de l'ancien `CLAUDE.md` sont remplacées (pas de « display server », pas de lanceur egui, pas de DXVK, pas de Win32 dans le noyau). |

### Espace d'adresses utilisateur (vue 32 bits, fixe, sans ASLR)

| Adresse | Contenu |
|---|---|
| `0x00000000–0x0000FFFF` | Interdite (piège à pointeurs nuls) |
| `0x00400000` | Base usuelle des `.exe` |
| `0x7FFDE000` | TEB du premier thread |
| `0x7FFDF000` | PEB |
| `0x7FFE0000` | `KUSER_SHARED_DATA` (lecture seule pour le mode utilisateur) |
| `0x80000000–0xFFFFFFFF` | Réservée, sauf images `LARGE_ADDRESS_AWARE` |

Le détail de l'espace noyau est au §4.2 de l'architecture.

---

## Règles à respecter dans tout le code

- **`no_std`** dans toutes les crates noyau et pilotes. Les outils hôte (`tools/*`, `xtask`) sont en `std`.
- **Dépendances** (ADR-016) : seulement `x86_64`, `bitflags`, `log`, `ttf-parser` côté noyau ; `spin` est réservé aux outils.
  Le code existant qui utilise `spin` dans le noyau est à migrer : ne pas en ajouter.
- **`unsafe`** : chaque bloc porte un commentaire `// SAFETY:` qui justifie l'invariant. Vérifier les bornes avant toute arithmétique de pointeur.
- **IRQL** :
  - documenter chaque fonction avec `/// # IRQL: PASSIVE` (ou `APC`, `DISPATCH`, `DIRQL`) ;
  - aucune allocation à `IRQL >= DISPATCH_LEVEL`, et les DPC n'allouent jamais ;
  - aucune faute de page à `IRQL >= DISPATCH_LEVEL` ;
  - un verrou doit élever l'IRQL ; `spin::Mutex` n'est pas un substitut d'IRQL ;
  - attendre via les objets du dispatcher, jamais par attente active à `PASSIVE_LEVEL`.
- **Mémoire utilisateur** : le noyau n'y accède que par `probe_for_read`, `probe_for_write`, `copy_from_user`, `copy_to_user` et `UserPtr<T>`
  (`kernel/ke/src/usermem.rs`, jalon M3), avec récupération des fautes. Aucun déréférencement direct de pointeur utilisateur dans le nouveau code.
- **Appels système** : aucun numéro écrit à la main, aucun appel système privé. Les tables sont générées depuis la version épinglée de ReactOS.
- **Version de Windows** : ne jamais changer `OSMajorVersion = 5`, `OSMinorVersion = 1`, `OSBuildNumber = 2600`, `OSCSDVersion = 0x0200`.
- **Hygiène juridique** :
  - aucun code, binaire ou ressource Microsoft (DLL, thème Luna, Bliss, polices, sons) ;
  - **interdiction de consulter le code source d'XP qui a fuité** ;
  - tant que l'ADR-007 n'est pas tranchée, ReactOS sert de **spécification** : on ne traduit pas son code noyau en Rust.
- **Bogues mémoire** : on diagnostique la cause, on ne contourne pas (audit §4.2).
- **Tests** : toute logique pure a des tests hôte (`cargo test`) ; chaque jalon ajoute ses scénarios QEMU.

---

## État du code : transition depuis l'ancienne architecture

Le code actuel (commit `6d3e235`) suit l'ancienne architecture : Win32 réimplémenté **dans le noyau**, appels système privés `0x2000+`,
stubs en code machine, lanceur natif. L'audit ([`docs/04-audit-reutilisation.md`](docs/04-audit-reutilisation.md)) donne le verdict fichier par fichier.

**À ne pas étendre** (voués à disparaître, à ne corriger que si ça bloque un test ou le jalon M0) :

- `kernel/src/syscall.rs`, partie Win32/UCRT/advapi/registre/vk (~l. 1 370–4 646) ;
- `executive/ps/src/loader.rs`, générateur de stubs (~l. 377–3 400) ;
- `kernel/src/launcher.rs` ;
- `win32/*` et `directx/*`.

**Défauts structurants connus** (audit §4) : noyau lié à `0x00100000` et dépendant du mapping identité, un seul espace d'adresses,
corruptions mémoire contournées (hypothèse : débordement de pile noyau), pas de vraies attentes ni de vrais threads utilisateur,
VAD limitée à 64 entrées, pas d'exceptions, SYSENTER en dur (`#UD` sur AMD), IOPL=3 pour les threads utilisateur, pas de sauvegarde FPU.

Avant de supprimer du code Win32, en extraire la connaissance utile dans `docs/compat/` (audit §5).

---

## Jalon courant : M0 — Assainir

Détail et critères de sortie : [`docs/05-feuille-de-route.md`](docs/05-feuille-de-route.md#m0--assainir).

### Corrections immédiates (audit §7)

- [ ] `Cargo.toml` : retirer `win32/*` et `directx/*` de `members`
- [ ] `kernel/src/syscall.rs:123`, `:141` : supprimer les collisions `0x20B7` et `0x2033`, ajouter `#![deny(unreachable_patterns)]`
- [ ] `executive/ke/src/scheduler.rs:377` : RFLAGS utilisateur à `0x202` (IOPL=0)
- [ ] `executive/ps/src/loader.rs:1286` : repli sur `int 2Eh` si le CPU n'est pas Intel
- [ ] `executive/ke/src/*.rs` : remplacer le tiret cadratin dans les blocs de doc (doctests)
- [ ] `executive/ps/src/loader.rs` (tests) : adapter à la signature à 5 arguments de `load_image`
- [ ] `kernel/src/syscall.rs:270` : trace série derrière une feature `trace-syscalls`

### Reste du jalon

- [ ] Piles noyau de 24 Kio hors du tas, avec page de garde ; diagnostic du débordement dans le handler de double fault
- [ ] Noyau en ELF lié en haut de l'espace, mapping identité supprimé après la phase 0 (ADR-014)
- [ ] Réactiver `BTreeMap` et un vrai allocateur, confirmer la disparition des corruptions
- [ ] Nouvelle arborescence (`abi/`, `boot/`, `kernel/*`, `drivers/*`, `libs/*`, `tools/*`, `xtask/`) et `git mv` des composants ✅ de l'audit
- [ ] `cargo xtask run` et `cargo xtask test` (QEMU sans affichage, marqueurs série) en CI

**Sortie de M0** : `cargo check --workspace` et `cargo test --workspace` sans warning ; le smoke test QEMU atteint `kernel: phase 1 done` ;
un débordement de pile noyau provoqué donne un écran d'erreur fatale lisible, pas un *triple fault*.

Ensuite : M1 (Ke) → M2 (Mm/Ob/Ps) → M3 (frontière NT, spike S1) → M4 (Io/Cm/FS) → M5 (console, spike S2) → M6 (win32k, spike S3) → M7 → M8–M10.

---

## Commandes

Tant que `xtask` n'existe pas, on utilise les commandes de l'ancienne arborescence.

```bash
cargo check -p kernel
cargo test -p mm
cargo test -p ke
cargo test -p bump-alloc
cargo test -p io-manager
cargo build -p kernel --target x86_64-unknown-none --profile kernel
cargo build -p bootloader --target x86_64-unknown-uefi --profile kernel
cargo run -p pe-loader -- /chemin/vers/programme.exe
tools/qemu-run.sh          # construit le noyau et lance QEMU (OVMF, série sur stdio)
```

`cargo check --workspace` échoue tant que `win32/*` et `directx/*` sont membres du workspace (pas de `panic_handler` sur l'hôte),
et `cargo test -p ps` ne compile pas (tests périmés). Les deux sont des corrections immédiates de M0.

Commandes cibles (02 §9.2) : `cargo xtask build`, `cargo xtask fetch-userland`, `cargo xtask image`, `cargo xtask run [--gdb] [--smp N]`, `cargo xtask test`.

---

## Références

| Sujet | Source | Usage |
|---|---|---|
| Contrat noyau, structures | ReactOS (`ntoskrnl/`, `win32ss/`, `sdk/include/`) de la version épinglée | Spécification (voir ADR-007 pour le portage) |
| Comportement des API Win32 | Wine (`dlls/`) et ses tests de conformance | Spécification |
| Conception NT (IRQL, dispatcher, Mm, Io) | *Windows Internals*, 7ᵉ édition | Référence |
| Structures non documentées (PEB, TEB, `KUSER_SHARED_DATA`) | Site de Geoff Chappell | Offsets |
| SYSENTER/SYSCALL en mode compatibilité | OSDev ; `arch/x86/entry/entry_64_compat.S` (Linux) | ADR-004 |
| Noyau Rust `no_std` (paging, IDT, tas) | os.phil-opp.com ([`docs/references/`](docs/references/)) | Patrons |

**Jamais** : le code source d'XP qui a fuité, ni aucun binaire Microsoft.

---

## Ce qu'il ne faut pas faire

- Réimplémenter du Win32 dans le noyau ou ajouter des appels système privés : l'espace utilisateur vient de ReactOS (ADR-002).
- Écrire du code 3D dans le noyau, ou un shim `vulkan-1.dll` / DXVK (ADR-006).
- Charger des pilotes `.sys` Windows (ADR-008).
- Viser les programmes 16 bits (NTVDM), les applications 64 bits, les DRM (SafeDisc, StarForce) ou l'activation (01 — Vision).
- Écrire des numéros d'appel système à la main.
- Modifier une ADR acceptée au lieu d'en écrire une nouvelle.
- Ajouter une dépendance noyau sans vérifier qu'elle est `no_std`, sans `build.rs` réseau, et sans la justifier.
- Allouer ou fauter à `IRQL >= DISPATCH_LEVEL`.
- Déréférencer un pointeur utilisateur hors des primitives de sonde et de copie.
- Contourner une corruption mémoire sans en trouver la cause.
- Changer les champs de version du PEB ou de `KUSER_SHARED_DATA`.
