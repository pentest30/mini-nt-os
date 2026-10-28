# 06 — Conventions de développement

Ces règles s'appliquent à tout le code, qu'il soit écrit à la main ou avec Claude Code. Une PR qui ne les respecte pas n'est pas fusionnée.

---

## 1. Hygiène juridique (non négociable)

- **Interdiction de consulter, copier ou paraphraser du code Microsoft**, y compris le code source d'XP et de Server 2003 qui a fuité, ainsi que les WRK. Quiconque a lu ce code ne contribue pas aux composants correspondants.
- **Aucun binaire ni aucune ressource Microsoft** dans le dépôt ni dans l'image : DLL, polices, thème Luna, sons, fonds d'écran, logos.
- **Sources autorisées** : la documentation publique (MSDN, Learn), *Windows Internals*, les sites de Geoff Chappell, le code de ReactOS et de Wine (dans le respect de l'ADR-007), et l'observation du comportement d'un vrai XP par des programmes de test.
- **Pas de marque « Windows »** dans le nom du produit, l'interface ou la communication. On dit « compatible XP ».
- Tout code porté depuis ReactOS ou Wine porte en en-tête son origine (fichier et commit) et la licence correspondante.

## 2. Organisation du code

- **Une crate par composant** (§10 de l'architecture). L'API publique est minimale et documentée.
- **Seule la crate `abi`** contient des structures dont le layout est imposé par l'extérieur (PEB, TEB, `KUSER_SHARED_DATA`, `CONTEXT`, `LOADER_BLOCK`…). Chacune a des assertions de compilation :
  ```rust
  const _: () = assert!(core::mem::size_of::<Teb32>() == 0xFB8);
  const _: () = assert!(core::mem::offset_of!(Teb32, nt_tib.self_) == 0x18);
  ```
  (Les valeurs ci-dessus sont des exemples, à vérifier contre la référence.)
- **Pas d'accès aux internes d'un autre composant.** Mm n'écrit pas dans un `EPROCESS` : il expose une fonction que Ps appelle.
- **Aucun numéro d'appel système écrit à la main** : ils sont tous générés par `tools/syscall-gen` (ADR-002).
- La taille d'un fichier est un signal d'alerte : au-delà d'environ 1 500 lignes, on découpe.

## 3. `unsafe`

- **Chaque bloc `unsafe`** porte un commentaire `// SAFETY:` qui énonce l'invariant qui le rend correct, et pas seulement ce que fait le code.
- `#![deny(unsafe_op_in_unsafe_fn)]` dans toutes les crates noyau.
- Le code `unsafe` est concentré dans `hal`, `mm` (pagination), `ke` (trap, commutation de contexte, `usermem`) et les pilotes (MMIO). Partout ailleurs, il doit être justifié en revue.
- **Mémoire utilisateur** : uniquement via `ke::usermem` (`UserPtr<T>`, `copy_from_user`, `copy_to_user`, `probe_*`). Un déréférencement direct d'une adresse utilisateur bloque la revue.

## 4. IRQL et concurrence

- **Chaque fonction publique du noyau** documente l'IRQL maximal auquel on peut l'appeler :
  ```rust
  /// # IRQL
  /// <= APC_LEVEL. Peut bloquer.
  ```
- **À `DISPATCH_LEVEL` ou plus** : ni allocation dans le pool paginé, ni faute de page, ni attente.
  - L'allocation dans le pool non paginé est permise jusqu'à `DISPATCH_LEVEL`.
  - En version debug, `hal::irql::assert_alloc_safe()` vérifie ces règles.
- **Verrous** : `KSpinLock` élève l'IRQL à `DISPATCH`, `KGuardedMutex` et `ERESOURCE` sont utilisés à `PASSIVE`. `spin::Mutex` est **interdit** dans le noyau, car il ne gère pas l'IRQL et provoque des interblocages avec les ISR.
- **Pas de variables globales mutables** hors de structures protégées et documentées. Tout état par CPU passe par `KPRCB`.

## 5. Erreurs et journalisation

- **Côté NT**, les erreurs sont un newtype `NtStatus(u32)` avec des constantes nommées (`STATUS_*`). Ne jamais renvoyer un `u32` nu.
- **En interne**, on utilise `Result<T, NtStatus>`. `panic!` est réservé aux invariants violés, et passe par `KeBugCheckEx` avec un code.
- **Journalisation** :

  | Macro | Usage |
  |---|---|
  | `kd_trace!` | Bruit de mise au point. Compilé seulement avec une feature (`trace-<composant>`). |
  | `kd_info!` | Événements de cycle de vie |
  | `kd_warn!` | Écart toléré, par exemple un appel système non implémenté |
  | `kd_error!` | Panne |

  **Jamais de journalisation inconditionnelle dans un chemin chaud** (appels système, interruptions, ordonnanceur).
- Un appel système non implémenté renvoie `STATUS_NOT_IMPLEMENTED` et journalise **une seule fois** par numéro.

## 6. Tests

| Niveau | Où | Obligatoire pour |
|---|---|---|
| Unitaire hôte | `#[cfg(test)]` dans la crate | Toute logique pure : dispatcher, VAD, pools, ruches, PE, FAT, GDI (rastérisation), parsers |
| Intégration hôte | `tests/host/` | Formats de fichiers (images FAT, ruches) aller-retour avec les outils |
| Démarrage QEMU | `tests/boot/<scénario>/` | Chaque critère de sortie de jalon automatisable : un scénario déclare ses marqueurs série attendus et son délai maximal |
| Conformance | `rostests` dans l'image | À partir de M5, avec un taux de réussite suivi |

- Un bogue corrigé s'accompagne d'un test qui l'aurait détecté.
- La CI exécute `cargo fmt --check`, `cargo clippy -D warnings`, les tests hôte et les scénarios QEMU de base.

## 7. Git et revues

- **Branches** : `main` est toujours vert. Le travail se fait dans `feat/<composant>-<sujet>` ou `fix/…`.
- **Commits** : messages au format `<composant>: <résumé à l'impératif>`, par exemple `mm: séparer reserve et commit dans la VAD`.
- **Taille** : une PR traite un seul sujet. Une PR qui touche une ADR acceptée doit d'abord ajouter une nouvelle ADR.
- **Déplacements** : `git mv` pour conserver l'historique.

## 8. Documentation

- Toute décision structurante passe par une ADR (`03-decisions.md`) : contexte, décision, conséquences, alternatives.
- `02-architecture.md` décrit l'état **cible**. L'état réel par jalon se suit dans `05-feuille-de-route.md` (cases cochées).
- La connaissance de compatibilité (quirks d'applications, imports observés, couverture des appels système) va dans `docs/compat/`.
- Une fonction publique sans doc ne passe pas la revue (`#![warn(missing_docs)]` dans les crates noyau).

## 9. Travailler avec Claude Code

- `CLAUDE.md` à la racine reste **court**. Il renvoie vers ces documents et liste les règles qui ne se négocient pas.
- Une session de Claude Code travaille sur **un seul jalon et un seul composant**, et elle termine en faisant passer `cargo xtask test`.
- Il est interdit de contourner un symptôme sans le documenter et ouvrir une tâche de diagnostic. C'est la leçon du §4.2 de l'audit.
