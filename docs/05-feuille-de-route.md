# 05 — Feuille de route

Les jalons sont **séquentiels**. Un jalon est terminé quand **tous** ses critères de sortie passent en CI, ou par une recette documentée pour ceux qui ne s'automatisent pas. Il n'y a pas de dates : l'ordre est imposé par les dépendances techniques, pas par un calendrier.

```
M0 Assainir ─► M1 Ke ─► M2 Mm/Ob/Ps ─► M3 Frontière NT ─► M4 Io/Cm/FS ─► M5 Console
                                            │ (spike S1)                    │ (spike S2)
                                            ▼                               ▼
                                     M6 win32k (spike S3 d'abord) ─► M7 Bureau & applications
                                                                       │
                                     M8 Multimédia & jeux ◄────────────┤
                                     M9 Matériel réel & réseau ◄───────┤
                                     M10 Maturité (SMP, sécurité, swap)┘
```

---

## M0 — Assainir

**But :** une base saine sur laquelle construire.

- Corrections immédiates de l'audit ([04 §7](04-audit-reutilisation.md#7-corrections-à-faire-tout-de-suite-avant-le-jalon-m0)).
- Piles noyau de 24 Kio hors du tas, avec page de garde. Diagnostic du débordement de pile dans le handler de double fault.
- Noyau en ELF lié en haut de l'espace et mapping identité supprimé après la phase 0 (ADR-014).
- Réactivation de `BTreeMap` et d'un vrai allocateur. Confirmation que la corruption a disparu (§4.2 de l'audit).
- Nouvelle arborescence (`abi/`, `boot/`, `kernel/*`, `drivers/*`, `libs/*`, `tools/*`, `xtask/`) et `git mv` des composants ✅.
- `cargo xtask run` et `cargo xtask test` (QEMU sans affichage, marqueurs série) en CI.

**Critères de sortie**
- [x] `cargo check --workspace` et `cargo test --workspace` passent sans warning (`-D warnings` en CI).
- [x] Le smoke test QEMU démarre jusqu'à `kernel: phase 1 done`.
- [x] Un débordement de pile noyau provoqué volontairement produit un écran d'erreur fatale lisible, pas un *triple fault*.

## M1 — Noyau Ke

**But :** de vrais threads.

- Intégration de `dispatcher.rs` (événements, sémaphores, mutants, timers, attente sur plusieurs objets, timeouts).
- Ordonnanceur à 32 priorités, état `Waiting`, quantum, boosts, `KeDelayExecutionThread`.
- APC (noyau et utilisateur) et DPC sans allocation, IRQL via le TPR.
- Sauvegarde FPU/SSE (ADR-009). Un `KPRCB` par CPU via `GS` (ADR-015).
- Écran d'erreur fatale (`KeBugCheckEx`) symbolisé.

**Critères de sortie**
- [x] Tests hôte du dispatcher : WaitAny, WaitAll partiel, mutant récursif puis abandonné, timeout déjà échu, APC pendant une attente alertable.
- [x] Scénario QEMU : 2 threads noyau échangent 10 000 signaux via deux événements, sans perte ni blocage.
- [x] Scénario QEMU : 4 threads qui font du calcul flottant en parallèle obtiennent des résultats identiques à ceux de l'hôte.

## M2 — Mémoire, objets, processus

**But :** de vrais processus.

- Base PFN et pools à dalles. Une PML4 par processus. VAD en arbre, réservation et commit, fautes de page à la demande, pages de garde.
- Sections : adossées au fichier d'échange, fichier de données, **image** (via `libs/pe`, copie sur écriture ; relocations par `ntdll` sur `STATUS_IMAGE_NOT_AT_BASE`).
- Ob complet : types, répertoires, liens symboliques, *parse*, comptes de références, table de handles par processus.
- Ps : `EPROCESS` et `ETHREAD`, création et terminaison avec *rundown*, PEB32 et TEB32 (crate `abi`).

**Critères de sortie**
- [x] Deux processus chargent chacun une image différente en `0x400000` et s'exécutent en même temps.
- [x] Un processus qui réserve 256 Mio puis commite page par page n'utilise de mémoire physique que pour les pages touchées.
- [x] Après la fin d'un processus, toute sa mémoire et tous ses handles sont libérés (compteurs de pool revenus à leur valeur initiale).

## M3 — Frontière NT, puis spike S1

**But :** faire tourner le `ntdll` de ReactOS.

- `tools/syscall-gen` : génération des tables `ntoskrnl` à partir de la version épinglée de ReactOS.
- `KTRAP_FRAME`, portes `int 2Ah` à `2Eh`, SYSENTER sur Intel (ADR-004), IF=1 pendant les appels système.
- SWAPGS à chaque entrée et sortie du mode utilisateur (interruptions, exceptions, appels système) : jusque-là, la base de GS
  (le KPCR) n'est protégée que par le fait que le code utilisateur XP ne charge pas GS.
- Primitives de sonde et de copie avec table de correction des fautes (§6.4 de l'architecture).
- `KiDispatchException` vers `KiUserExceptionDispatcher`, livraison des APC utilisateur, `NtContinue`, `NtRaiseException`.
- Le noyau mappe `ntdll`, résout ses points d'entrée et remplit `KUSER_SHARED_DATA`.
- `cargo xtask fetch-userland` : ISO ReactOS épinglée, vérifiée par SHA-256.

**Critères de sortie (spike S1)**
- [x] Un programme natif (sous-système NATIVE) compilé avec MinGW et lié à `ntdll` ReactOS affiche via `DbgPrint` et se termine.
- [x] Un test SEH (`__try`/`__except` sur une écriture à l'adresse 0) passe.
- [x] Le rapport de couverture des appels système est publié (`docs/compat/syscalls.md`).

## M4 — E/S, registre, systèmes de fichiers

**But :** lancer `smss.exe`.

- Io : IRP, piles de périphériques, objets fichier, E/S synchrones et asynchrones, ports de complétion.
- Pilotes : ATA, virtio-blk, gestionnaire de partitions, FAT32 en lecture et écriture (ADR-017).
- Cm et `libs/regf`. `tools/mkhive` génère les ruches (ADR-012).
- `\??\C:`, `\SystemRoot`, `\KnownDlls`.

**Critères de sortie**
- [x] `smss.exe` (ReactOS) démarre, lit `Session Manager`, crée les variables d'environnement et `\KnownDlls`.
- [ ] Une valeur écrite dans le registre persiste après un redémarrage.
- [ ] Un fichier créé sur `C:` reste lisible après un redémarrage, et `fsck.vfat` ne signale aucune erreur sur l'image.

## M5 — Mode console, puis spike S2

**But :** un `cmd.exe` interactif.

- Lpc complet. Se (jetons, mode permissif, ADR-011). Objets Ex (événements à clé, etc.).
- `csrss` (`csrsrv`, `basesrv`, `consrv`) et `kernel32`.
- Une console texte : frontal texte de `consrv` si la version épinglée en a un, sinon ce jalon dépend de la partie minimale de M6.

**Critères de sortie (spike S2)**
- [ ] `cmd.exe` est interactif : `dir`, `copy`, `type`, `set`, et des scripts `.bat`.
- [ ] Un programme console C (MSVC ou MinGW) qui crée 8 threads synchronisés par des sections critiques se termine correctement.
- [ ] Les `rostests` `ntdll` et `kernel32` (apitests) dépassent un seuil de réussite fixé au moment du jalon, puis suivi dans le temps.

## M6 — win32k, avec le spike S3 en premier

**But :** des fenêtres.

- **S3 d'abord** : `user32` s'initialise sur un win32k minimal. C'est le point qui confirme l'ADR-002 ou déclenche son repli.
- USER : stations de fenêtres, bureaux, fenêtres, classes, files de messages, `SendMessage` entre threads, thread d'entrée, focus, crochets, timers, curseurs, presse-papiers.
- GDI : contextes de périphérique, moteur DIB, régions, palettes, texte (ADR-013).
- `KeUserModeCallback` et `int 2Bh`.
- Pilotes `gopfb`, puis `bochs-dispi` (changement de résolution), et i8042 souris.

**Critères de sortie**
- [ ] `winlogon` (ouverture de session automatique), `userinit` et `explorer` affichent le bureau, la barre des tâches et le menu Démarrer.
- [ ] Bloc-notes s'ouvre, on y tape du texte, on l'enregistre puis on le rouvre.
- [ ] La résolution se change depuis le panneau Affichage (QEMU).

## M7 — Bureau et applications

**But :** un système qu'on peut utiliser au quotidien en machine virtuelle.

- Explorateur de fichiers, panneau de configuration, éditeur de registre, gestionnaire des tâches, Paint, calculatrice.
- Installeurs : MSI (`msiexec` ReactOS), InstallShield et NSIS. Ce jalon remplace la stratégie `mino-pack`.
- Ports de complétion, notifications de répertoire et `NtNotifyChangeKey` (utilisés par l'explorateur).
- Un thème libre de style XP (aucune ressource Microsoft).

**Critères de sortie**
- [ ] Une liste de 10 applications libres de l'ère XP (à définir dans `docs/compat/applications.md`) s'installe et s'exécute.
- [ ] Une session complète (ouverture, travail, arrêt) se déroule sans erreur fatale ni fuite de pool mesurable.

## M8 — Multimédia et jeux

**But :** faire tourner le jeu de référence.

- Pile Direct3D : wined3d puis Mesa en rendu logiciel (ADR-006). Optimisation du moteur DIB et de `StretchDIBits`.
- Son : pilote HDA, et ADR à rédiger sur l'interface `winmm` et `dsound` (*kernel streaming* ou interface simplifiée).
- DirectInput, timers haute résolution (`timeBeginPeriod(1)` réel).

**Critères de sortie**
- [ ] *Ghost Recon* (GOG) atteint le menu principal, puis une mission jouable (`docs/compat/ghost-recon.md`).
- [ ] Un jeu D3D9 libre de référence affiche au moins 20 images par seconde en 800×600 sous QEMU, sur 4 cœurs de l'hôte.

## M9 — Matériel réel et réseau

- Stockage AHCI et NVMe, USB xHCI avec claviers et souris HID, ACPI pour l'arrêt.
- Réseau : virtio-net et e1000, pile TCP/IP en Rust, AFD. `ws2_32` et `msafd` de ReactOS.
- NTFS en lecture seule, ISO9660.

**Critères de sortie**
- [ ] Démarrage sur au moins deux machines physiques UEFI de référence (listées dans `docs/compat/materiel.md`).
- [ ] Navigation HTTP avec un navigateur de l'époque, et téléchargement d'un fichier de 100 Mio avec vérification de son SHA-256.

## M10 — Maturité

- SMP : démarrage des processeurs secondaires, IPI, *TLB shootdown*, verrous par objet si les mesures l'exigent.
- Sécurité appliquée (ADR-011), plusieurs comptes utilisateur.
- Fichier d'échange (ADR-010), NTFS en écriture.
- Installeur graphique.
- Remplacement progressif de DLL ReactOS par du Rust (`userland/`), au cas par cas et seulement si la mesure le justifie.
