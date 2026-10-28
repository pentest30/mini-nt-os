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

- Une session traite **un jalon et un composant**, et se termine en faisant passer `cargo xtask test`.
- Commits au format `<composant>: <résumé à l'impératif>`, par exemple `mm: séparer reserve et commit dans la VAD`.
  Déplacements par `git mv`. Une PR traite un seul sujet.
- **Jalon courant : M0 — Assainir** ([05](docs/05-feuille-de-route.md#m0--assainir)), en commençant par les corrections
  immédiates de l'[audit §7](docs/04-audit-reutilisation.md#7-corrections-à-faire-tout-de-suite-avant-le-jalon-m0).
- Le code actuel suit l'ancienne architecture (Win32 dans le noyau). **Ne pas étendre** : la partie Win32 de `kernel/ntoskrnl/src/syscall.rs`,
  le générateur de stubs de `kernel/ps/src/loader.rs`, `kernel/ntoskrnl/src/launcher.rs`, `win32/*`, `directx/*`.
  Avant de les supprimer, extraire la connaissance utile dans `docs/compat/` (audit §5).

## Commandes

`cargo xtask` (02 §9.2, `xtask/`) :

```bash
cargo xtask test                                     # tests hôte, puis scénarios de démarrage QEMU (tests/boot/)
cargo xtask test --boot --scenario smoke --cpu intel # un scénario, un CPU
cargo xtask run [--cpu intel] [--gdb] [--headless]   # démarre dans QEMU, port série sur stdio
cargo xtask build [--features trace-syscalls]        # mino-loader et ntoskrnl
cargo xtask help
```

Et directement :

```bash
cargo check --workspace
cargo build -p ntoskrnl --target x86_64-unknown-none --profile kernel [--features trace-syscalls]
cargo build -p mino-loader --target x86_64-unknown-uefi --profile kernel
```

- Un scénario de démarrage est un fichier de `tests/boot/` : features du noyau, CPU, marqueurs série attendus et interdits.
  Le run s'arrête dès que le verdict est connu ; journaux dans `target/xtask/boot/<scénario>-<cpu>/`.
- Tout compile sans warning. Sur l'hôte, on peut le vérifier avec `RUSTFLAGS="-D warnings"`, mais pas pour les cibles bare-metal,
  où `RUSTFLAGS` remplacerait les options de `.cargo/config.toml`.
- `trace-syscalls` active la trace série des appels système. Le CPU par défaut de QEMU annonce un fabricant AMD (chemin `int 2Eh`) ;
  `--cpu intel` exerce le chemin SYSENTER.
- La CI (`.github/workflows/ci.yml`) exécute `cargo xtask test`, avec les builds bare-metal sans warning. `cargo fmt --check` et
  `cargo clippy -D warnings` (06 §6) restent à activer.
