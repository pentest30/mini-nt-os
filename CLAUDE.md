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

- Une session traite **un jalon et un composant**, et se termine en faisant passer `cargo xtask lint` et `cargo xtask test`.
- Commits au format `<composant>: <résumé à l'impératif>`, par exemple `mm: séparer reserve et commit dans la VAD`.
  Déplacements par `git mv`. Une PR traite un seul sujet.
- **Jalon courant : M2 — Mémoire, objets, processus** ([05](docs/05-feuille-de-route.md#m2--mémoire-objets-processus)).
  M0 et M1 sont terminés. Acquis de M1 (Ke) : dispatcher (ADR-005) sur l'ordonnanceur à 32 priorités de
  `kernel/ke/src/sched.rs` (préemption différée sous `DISPATCH_LEVEL`, quantum en tiers de tick, boosts, balance set
  manager `ke::balance`), DPC et APC noyau sans allocation (`ke::dpc`, `ke::apc`), roue de timers, état FPU/SSE par
  thread, IRQL = TPR de l'APIC (CR8), KPCR (`hal::pcr`) puis KPRCB (`ke::prcb`) par GS, écran STOP symbolisé
  (`ke::bugcheck`, `hal::bugcheck`). Scénarios `ke-events`, `fpu`, `ke-starvation`, `bugcheck`. Les APC utilisateur
  viennent au M3, le rundown des APC d'un thread qui se termine avec Ps.
  M2 : base PFN faite (`mm::pfn` au-dessus du buddy : toute page physique y passe, avec son usage ; double libération
  et page réservée arrêtent le système ; cohérence vérifiée en fin de phase 1). Pools faits (`mm::pool`) : non paginé
  (allocateur global) et paginé, qui grandissent à la demande et rendent leurs pages à la base PFN ;
  `ex_allocate_pool_with_tag` et compteurs par étiquette. Une PML4 par processus (`mm::address_space`) : moitié haute
  complétée au démarrage et partagée, CR3 propre à chaque thread et chargé à la commutation, `ke_stack_attach`.
  L'ancien chargeur (`NtCreateProcess`) reste dans l'espace du système jusqu'à la réécriture de Ps. VAD faite
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
  `mm::section`. Pas encore : handles noyau, Se (accès accordés, ADR-011). À venir : Ps (EPROCESS/ETHREAD, avec la
  croissance de la pile utilisateur par sa garde et la politique DEP).
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
- `trace-syscalls` active la trace série des appels système, `heartbeat` le battement du timer (`[alive] tick=N`). Le CPU par défaut de QEMU annonce un fabricant AMD (chemin `int 2Eh`) ;
  `--cpu intel` exerce le chemin SYSENTER.
- Formatage : `cargo fmt --all` (rustfmt.toml). Un lint justifié à garder se marque `#[expect(clippy::…, reason = "…")]`.
- La CI (`.github/workflows/ci.yml`) exécute `cargo xtask lint` et `cargo xtask test`, avec les builds bare-metal sans warning.
