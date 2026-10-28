# Mino (mini-nt-os)

**Mino est un système d'exploitation libre, compatible XP, dont le noyau est écrit en Rust.**

On démarre sur un bureau de style XP (barre des tâches, menu Démarrer, explorateur, panneau de configuration),
puis on y lance des applications et des jeux 32 bits de l'ère XP (2001–2008) sans les modifier.

- **Écrit en Rust** : tout le code privilégié (noyau NT, partie noyau de Win32, pilotes).
- **Réutilisé** : l'espace utilisateur de ReactOS (`ntdll`, `kernel32`, `user32`, `csrss`, `explorer`…), en binaires épinglés à une version.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Applications PE32 i386 : explorer, notepad, jeux D3D8/9…     │
├──────────────────────────────────────────────────────────────┤
│ DLL Win32 et processus système (ReactOS, épinglés)           │
│ d3d8/d3d9/ddraw → wined3d → opengl32 (Mesa, rendu logiciel)  │
├══════════════════════════════════════════════════════════════┤  ← ring 3 / ring 0
│ win32k (Rust) : USER · GDI · polices                         │
│ Exécutif NT (Rust) : Ob · Ps · Mm · Io · Cm · Se · Lpc · Ex  │
│ Ke (Rust) : dispatcher, ordonnanceur, IRQL, APC, DPC         │
│ HAL et pilotes (Rust)                                        │
├──────────────────────────────────────────────────────────────┤
│ Chargeur UEFI (Rust) → ntoskrnl ELF64                        │
└──────────────────────────────────────────────────────────────┘
```

## Documentation

| Document | Contenu |
|---|---|
| [01 — Vision et périmètre](docs/01-vision.md) | Objectif, périmètre, jalons visibles |
| [02 — Architecture](docs/02-architecture.md) | Architecture cible, composant par composant |
| [03 — Décisions](docs/03-decisions.md) | Décisions d'architecture (ADR) |
| [04 — Audit et réutilisation](docs/04-audit-reutilisation.md) | État du code existant et plan de migration |
| [05 — Feuille de route](docs/05-feuille-de-route.md) | Jalons M0 à M10 et critères de sortie |
| [06 — Conventions](docs/06-conventions.md) | Règles de développement (hygiène juridique, `unsafe`, IRQL, tests, Git) |

**Jalon en cours : M0 — Assainir.** Le code actuel suit encore l'ancienne architecture (Win32 réimplémenté dans le noyau) ;
sa migration est décrite dans l'audit.

## Démarrage rapide

```bash
rustup toolchain install        # installe le nightly épinglé de rust-toolchain.toml
cargo check -p ntoskrnl
cargo test -p mm
bash tools/qemu-run.sh          # construit, démarre QEMU et vérifie les marqueurs série
```

Les commandes `cargo xtask` (build, image, run, test) remplaceront les scripts de `tools/` pendant le jalon M0.

## Plateformes

QEMU (OVMF, q35) est la plateforme de référence ; VirtualBox (EFI) sert de seconde plateforme.
Les machines réelles x86-64 UEFI arrivent au jalon M9.

## Contribuer, avec ou sans Claude Code

Toute contribution suit [06 — Conventions](docs/06-conventions.md), à commencer par l'hygiène juridique : aucun code,
binaire ou ressource Microsoft, et interdiction de consulter les sources fuitées d'XP ou de Server 2003.
[`CLAUDE.md`](CLAUDE.md) résume le contexte et les règles non négociables pour les sessions Claude Code.

## Licence

MIT pour l'instant. Le choix définitif est ouvert (ADR-007).
