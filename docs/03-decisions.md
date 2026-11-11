# 03 — Décisions d'architecture (ADR)

Chaque décision précise son **statut** :

- **Acceptée** : on construit dessus.
- **Proposée** : on construit dessus, mais un spike doit la confirmer.
- **À décider** : le choix revient au mainteneur.
- **Remplacée** : abandonnée, avec un renvoi vers la décision qui la remplace.

Pour changer une décision acceptée, on écrit une nouvelle ADR qui la remplace. On ne réécrit pas l'ancienne.

| # | Décision | Statut |
|---|---|---|
| 001 | Noyau x86-64, mode utilisateur i386 natif sans WoW64 | Acceptée |
| 002 | Espace utilisateur ReactOS épinglé ; la frontière est l'ABI noyau de ReactOS | **Proposée** (S1 réussi ; spikes S2–S3) |
| 003 | Version affichée : Windows XP 5.1.2600 SP2 | Acceptée |
| 004 | Appels système : `int 2Eh` partout, SYSENTER sur Intel | Acceptée |
| 005 | Dispatcher NT fidèle, verrou global puis par objet | Acceptée |
| 006 | Graphisme 3D entièrement en mode utilisateur : wined3d et Mesa | Acceptée |
| 007 | Licence du projet | **À décider** |
| 008 | Pilotes en Rust, liés statiquement, modèle IRP, sans compatibilité binaire | Acceptée |
| 009 | État FPU/SSE sauvegardé à chaque commutation | Acceptée |
| 010 | Pas de fichier d'échange au début | Acceptée |
| 011 | Sécurité : structures complètes, application permissive au début | Acceptée |
| 012 | Registre au format `regf`, ruches générées par `mkhive` | Acceptée |
| 013 | Polices : rastériseur TrueType en Rust dans win32k | Acceptée |
| 014 | Noyau en ELF lié dans les 2 Gio supérieurs, sans mapping identité | Acceptée |
| 015 | Un seul CPU d'abord, mais conçu pour le SMP | Acceptée |
| 016 | Chaîne Rust : nightly épinglé, dépendances `no_std` auditées | Acceptée |
| 017 | Volume système en FAT32 tant que NTFS n'est pas en écriture | Acceptée |
| 018 | Conformance : `rostests` et scénarios QEMU | Acceptée |
| 019 | Décisions de l'ancien `CLAUDE.md` | Remplacées |
| 020 | DEP : règle OptIn d'XP SP2, exécution permise par défaut | Acceptée |
| 021 | win32k : ce que USER partage avec ses clients, à des adresses du serveur sur 32 bits | **Proposée** (spike S3) |
| 022 | FAT32 : crate partagée `fatfs` ; formatage et partitions servis par le noyau | **Proposée** (chantier d'installation) |
| 023 | Premier démarrage en mode installation : couche Mino des ruches (`mino.inf`) et fin d'installation par un programme Mino | **Proposée** (scénario `logon`) |

---

## ADR-001 — Noyau x86-64, mode utilisateur i386 natif sans WoW64

**Contexte.** XP x86 est un système 32 bits. Le code existant (chargeur UEFI, HAL, pagination) est en x86-64 et exécute déjà du code 32 bits en mode compatibilité. Les machines UEFI récentes ne démarrent qu'en 64 bits.

**Décision.** Le noyau est en x86-64. Les processus sont des processus i386 natifs, exécutés en mode compatibilité. Le noyau sert directement l'ABI 32 bits d'XP (structures, trames, `CONTEXT` x86), sans `ntdll` 64 bits ni couche WoW64.

**Conséquences.**
- ✅ Le code existant de démarrage et de la HAL est conservé.
- ✅ Les images `LARGE_ADDRESS_AWARE` obtiennent jusqu'à 4 Gio d'espace utilisateur.
- ✅ Des processus 64 bits pourront être ajoutés plus tard.
- ❌ Les pilotes binaires d'XP ne peuvent pas être chargés. Ils étaient de toute façon hors périmètre.
- ❌ Le noyau convertit lui-même les structures 32 et 64 bits (`CONTEXT`, `EXCEPTION_RECORD`, trames de callback).
- ⚠️ SYSENTER et SYSCALL ne sont pas disponibles de la même façon selon le fabricant du CPU, d'où l'ADR-004.

**Alternatives écartées.**
- *Noyau i386 avec PAE* : il faudrait réécrire le chargeur, la HAL et la pagination, et accepter la limite de 4 Gio pour le noyau.
- *WoW64 à la Microsoft* : on aurait deux `ntdll` et une couche de traduction de plus, sans aucun bénéfice puisque Mino ne vise pas d'applications 64 bits.

---

## ADR-002 — Espace utilisateur ReactOS épinglé ; la frontière est l'ABI noyau de ReactOS

**Contexte.** Un clone d'XP exige `ntdll`, `kernel32`, `user32`, `gdi32`, `shell32`, `comctl32`, `ole32`, `explorer`, `csrss`, `winlogon`, `services` et des centaines d'autres composants. Les réécrire n'est pas faisable. Le code actuel essaie de réimplémenter Win32 **dans le noyau**, via des appels système privés et des stubs écrits en code machine, et cette approche ne passe pas à l'échelle (voir l'audit).

ReactOS fournit tout cet espace utilisateur, écrit contre l'ABI d'un noyau NT. Le projet vise le noyau NT 5.2, celui de Server 2003 ([OSNews](https://www.osnews.com/story/21087/reactos-targets-windows-2003-vista/)). Sa dernière version publiée est la 0.4.15, sortie le 21 mars 2025 ([Phoronix](https://www.phoronix.com/news/ReactOS-0.4.15-Released)). Depuis, sa pile DirectX a été alignée sur Wine 10 ([Phoronix](https://www.phoronix.com/news/ReactOS-Updated-Wine-DirectX)).

**Décision.**
- On utilise les binaires i386 **d'une version épinglée de ReactOS** pour tout l'espace utilisateur.
- Le noyau Mino implémente **l'interface noyau de cette version** :
  - les tables `ntoskrnl` et `win32k` (numéros et signatures) ;
  - les structures en mode utilisateur ;
  - les protocoles LPC de CSR ;
  - les objets partagés de win32k.
- Les numéros d'appel sont **générés** à partir des listes de services de ReactOS (`tools/syscall-gen`).
- Changer de version de ReactOS est un chantier explicite : on régénère les tables et on repasse toute la suite de tests.

**Spikes de validation** (à faire avant tout investissement lourd dans win32k) :

| Spike | Objectif | Critère de réussite |
|---|---|---|
| S1 | `ntdll` ReactOS et un programme natif | `LdrInitializeThunk` va au bout, le programme écrit sur la console de debug via `DbgPrint` ou `NtDisplayString` puis se termine. On produit la liste des appels système rencontrés. |
| S2 | `smss`, `csrss`, puis un programme console | `CsrClientConnectToServer` réussit et un programme console `kernel32` affiche « hello » |
| S3 | `user32` sur un win32k minimal | L'initialisation de `user32` (connexion au processus, mapping des informations partagées), puis `CreateWindowEx` et une boucle de messages, avec une fenêtre peinte par GDI sur le framebuffer |

**Repli si S3 échoue** (si l'interface win32k de ReactOS est trop couplée à ses structures internes) : prendre `user32` et `gdi32` chez Wine, compilés en PE, et fournir un `win32u.dll` Mino. Ce `win32u.dll` exposerait les appels `NtUser*` et `NtGdi*` tels que Wine les définit, et le noyau Mino les servirait. On garderait `ntdll`, `kernel32`, `csrss` et le shell de ReactOS.

**Conséquences.**
- ✅ Des centaines de milliers de lignes d'espace utilisateur sont disponibles immédiatement, avec leurs suites de tests (`rostests`).
- ✅ La qualité du noyau se mesure objectivement : un binaire ReactOS fonctionne ou non.
- ❌ On hérite des bogues de ReactOS dans l'espace utilisateur.
- ❌ win32k est couplé aux en-têtes internes de la version épinglée.
- ⚠️ La licence est à traiter (ADR-007).
- ⚠️ Il faut mettre en place une mise à jour contrôlée de ReactOS (la version est épinglée par un hash d'ISO).

**Alternatives écartées.**
- *DLL entièrement écrites en Rust* : irréaliste pour atteindre un bureau. Elles restent possibles une par une, plus tard (`userland/`).
- *Win32 dans le noyau* (l'approche actuelle) : elle est abandonnée.

---

## ADR-003 — Version affichée : Windows XP 5.1.2600 SP2

**Décision.**
- Le PEB affiche `OSMajorVersion = 5`, `OSMinorVersion = 1`, `OSBuildNumber = 2600`, `OSCSDVersion = 0x0200`.
- `KUSER_SHARED_DATA` affiche `NtMajorVersion = 5` et `NtMinorVersion = 1`.
- La clé `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` est cohérente avec ces valeurs.
- Le noyau implémente toutefois les appels et classes d'information de NT 5.2 dont les DLL ReactOS ont besoin, puisque les classes 5.2 sont un sur-ensemble des classes 5.1.

**Conséquence.** Les applications qui vérifient la version voient XP SP2. La configuration ReactOS fournie est ajustée par `mkhive`.

---

## ADR-004 — Appels système : `int 2Eh` partout, SYSENTER sur Intel

**Contexte.** En long mode, AMD ne prend en charge que SYSCALL/SYSRET ([OSDev](https://wiki.osdev.org/SYSENTER)). Intel, lui, ne prend pas en charge le SYSCALL 32 bits depuis le mode compatibilité, et Linux utilise SYSENTER sur Intel et SYSCALL sur AMD pour ses processus 32 bits ([`entry_64_compat.S`](https://tomoyo.sourceforge.net/cgi-bin/lxr/source/arch/x86/entry/entry_64_compat.S)). Le stub actuel, qui utilise SYSENTER en dur, plante donc sur AMD.

**Décision.**
- `int 2Eh` est toujours disponible.
- Sur Intel, le chemin rapide est SYSENTER, et `SharedUserData->SystemCall` (offset `0x300`) pointe vers `ntdll!KiFastSystemCall`.
- Sur tous les autres processeurs, ce pointeur désigne `ntdll!KiIntSystemCall`.
- Un SYSCALL en mode compatibilité sur AMD est une optimisation possible plus tard, mais il exigerait un stub `ntdll` différent. On ne le fait pas.

---

## ADR-005 — Dispatcher NT fidèle, verrou global puis par objet

**Décision.**
- On reproduit le modèle NT : `DISPATCHER_HEADER` intégré dans chaque objet attendable, `KWAIT_BLOCK`, et consommation de l'objet par le signaleur (`KiWaitTest`).
- Le timeout est un wait block supplémentaire.
- Les APC noyau défont l'attente, puis l'attente est relancée. Les APC utilisateur ne sont prises en compte que pendant une attente *alertable* en mode utilisateur.
- On commence avec un verrou dispatcher global à `DISPATCH_LEVEL`, comme XP. Le passage à un verrou par objet ne se fera qu'avec le SMP (ADR-015) et après mesure.
- Le point de départ est le fichier `dispatcher.rs`, déjà rédigé.

---

## ADR-006 — Graphisme 3D entièrement en mode utilisateur : wined3d et Mesa

**Contexte.** La règle précédente était « DXVK + `vulkan-1.dll` de 500 lignes ». Mais Vulkan exige un pilote GPU ou une implémentation logicielle, et la « couche » actuelle ne fait que renvoyer des handles factices. ReactOS utilise wined3d (pile DirectX alignée sur Wine 10), qui passe par OpenGL ou Vulkan, et son OpenGL est un rendu logiciel fourni par Mesa ([ros-dev](https://reactos.org/archives/public/ros-dev/2020-January/019111.html), [Phoronix](https://www.phoronix.com/news/ReactOS-Updated-Wine-DirectX)).

**Décision.**
- On utilise la pile de la version épinglée : `d3d8`, `d3d9` et `ddraw`, puis wined3d, puis `opengl32` de Mesa en rendu logiciel, puis GDI.
- Le noyau ne contient aucun code 3D.
- Le seul travail côté Mino porte sur la performance des blits du moteur DIB, du multithreading et de la mémoire.
- L'accélération matérielle (pilote Gallium en mode utilisateur plus miniport Rust) est une évolution prévue, mais pas planifiée.

**Remplace :** la règle « use DXVK prebuilt / write only `vulkan-1.dll` », et la piste d'un `d3d8.dll` logiciel maison évoquée dans l'audit précédent.

---

## ADR-007 — Licence du projet (À DÉCIDER)

**Contexte.** Mino est aujourd'hui sous MIT. Les binaires ReactOS distribués avec l'image sont majoritairement sous GPL-2.0-or-later ou LGPL-2.1-or-later (à vérifier composant par composant). Surtout, **traduire en Rust du code noyau de ReactOS** produirait une œuvre dérivée, donc sous GPL.

**Options.**

| Option | Ce qu'elle permet | Ce qu'elle impose |
|---|---|---|
| **A. GPL-2.0-or-later pour tout Mino** | Lire et porter librement le code ReactOS, noyau compris | Pas de réutilisation propriétaire du noyau Mino |
| **B. Rester en MIT** | Licence permissive | ReactOS ne peut servir que de *spécification* : pas de traduction de code. Il faut documenter cette discipline. Les binaires ReactOS sont distribués comme un agrégat séparé, avec leurs sources. |

**Recommandation : A.** Pour un clone d'XP construit autour de ReactOS, la cohérence de licence évite un risque juridique permanent et autorise le portage d'algorithmes éprouvés (gestionnaire de mémoire, Cm, LPC).

**Dans les deux cas :** il faut fournir les sources correspondant aux binaires ReactOS distribués (lien vers le tag et l'archive), et appliquer la règle d'hygiène de [06 — Conventions](06-conventions.md) (aucun code Microsoft, y compris fuité).

---

## ADR-008 — Pilotes en Rust, liés statiquement, modèle IRP, sans compatibilité binaire

**Décision.**
- Chaque pilote est une crate qui implémente le trait `Driver`.
- Le noyau les lie statiquement et les instancie au moment de l'énumération (table : identifiant PCI ou ACPI → pilote).
- Le modèle d'E/S est celui de NT (IRP, piles de périphériques) pour garder la sémantique d'XP vue depuis le mode utilisateur (`NtCreateFile`, `DeviceIoControl`, E/S asynchrones).
- Le chargement dynamique de modules Rust est repoussé à plus tard.
- Il n'y aura **jamais de chargement de `.sys` Windows** sans une ADR dédiée.

---

## ADR-009 — État FPU/SSE sauvegardé à chaque commutation

**Décision.**
- `FXSAVE`/`FXRSTOR` (ou `XSAVE`/`XRSTOR` selon CPUID) à chaque commutation entre threads qui ont un contexte utilisateur.
- Pas de commutation paresseuse, qui est sujette à la faille LazyFP et complique le SMP.
- Le noyau reste compilé sans SSE (`-sse` dans `rustflags`). Un code noyau qui aurait besoin de la FPU devra l'encadrer explicitement (`KeSaveFloatingPointState`).

---

## ADR-010 — Pas de fichier d'échange au début

**Décision.**
- Le pool paginé et les pages privées restent en mémoire.
- On réserve néanmoins dans la base PFN et dans les PTE les états *transition* et *paginé*, pour pouvoir ajouter le fichier d'échange sans tout refaire.
- Le fichier d'échange arrivera au jalon M10, ou avant si les tests révèlent une pression mémoire.

---

## ADR-011 — Sécurité : structures complètes, application permissive au début

**Contexte.** Les DLL ReactOS manipulent des jetons, des SID et des descripteurs de sécurité, et `lsass` et `winlogon` en dépendent.

**Décision.**
- Les objets `Token`, les SID, les ACL et `SeAccessCheck` sont implémentés réellement.
- Au début, un mode `SecurityEnforcement = Log` accorde l'accès mais journalise les refus qui auraient eu lieu.
- On passe en mode appliqué au jalon M10.

---

## ADR-012 — Registre au format `regf`, ruches générées par `mkhive`

**Décision.**
- Le format sur disque est `regf`, celui de Windows.
- La crate `libs/regf` est partagée entre le noyau (Cm) et les outils hôte.
- `tools/mkhive` génère les ruches initiales à partir des `.inf` de ReactOS (`hivesys`, `hivesft`, `hivedef`…), plus une couche Mino (version XP, pilotes intégrés, auto-ouverture de session).

---

## ADR-013 — Polices : rastériseur TrueType en Rust dans win32k

**Statut.** Acceptée par le mainteneur le 2026-11-04, avec les précisions ci-dessous.

**Décision.**
- On parse les polices avec `ttf-parser` (`no_std`, déjà autorisée par l'ADR-016).
- On les rastérise avec un rastériseur maison, en virgule fixe, avec antialiasing en niveaux de gris et mise en cache
  des glyphes. Il ne demande aucune nouvelle dépendance. La cible du noyau calcule les flottants en logiciel : les
  coordonnées `f32` que donne `ttf-parser` sont converties une fois, et le cache évite d'y revenir. Le rastériseur vit
  dans une bibliothèque `no_std` testée sur l'hôte (rendus de référence).
- Pas de hinting TrueType au début : son interpréteur de bytecode est un projet à lui seul. L'antialiasing en niveaux de
  gris le remplace. ClearType et un rendu monochrome (`NONANTIALIASED_QUALITY`) viendront si nécessaire.
- Les polices sont celles de ReactOS épinglé (`\SystemRoot\Fonts`). Ce sont des substituts libres qui portent les noms
  d'XP, vérifiés un par un : Tahoma de Wine (LGPL) ; Arial et Times New Roman de Liberation (OFL) ; Courier New de
  GNU FreeFont ; Verdana et Lucida Console de DejaVu ; Marlett de Wine et ReactOS. Aucune ressource Microsoft.

**Alternatives écartées.**
- FreeType en C lié au noyau, comme ReactOS : c'est du C non sûr en ring 0.
- `ab_glyph_rasterizer` : une dépendance de plus (ADR-016), en flottants, pour quelques centaines de lignes.

**À valider** à l'étape du texte, par des tests et des scénarios : le rendu de Tahoma et de ses substituts libres aux
petites tailles, sans hinting ; la métrique exacte de `GetTextExtentPoint32` et de `GetTextMetrics` (les unités des
boîtes de dialogue en dépendent).

---

## ADR-014 — Noyau en ELF lié dans les 2 Gio supérieurs, sans mapping identité

**Contexte.** Le noyau actuel est un binaire plat lié à `0x00100000` et exécuté via l'alias HHDM. Ses adresses absolues (variables statiques, pointeurs de fonctions) tombent donc dans **la plage utilisateur**, et il dépend du mapping identité 0–4 Gio, qui recouvre l'espace des processus.

**Décision.**
- `ntoskrnl` est un ELF64 lié à `0xFFFFFFFF80000000` avec `code-model=kernel`, chargé segment par segment par le chargeur, avec les bonnes permissions (W^X).
- Le mapping identité n'existe que pendant la transition du chargeur, et il est supprimé en phase 0.
- Les symboles sont conservés pour le débogage via gdb et pour symboliser les écrans d'erreur fatale.

---

## ADR-015 — Un seul CPU d'abord, mais conçu pour le SMP

**Décision.**
- Dès maintenant : un `KPRCB` par CPU via `GS`, des files DPC et des files de threads prêts par CPU, et des verrous qui élèvent l'IRQL.
- Seul le BSP (processeur d'amorçage) est démarré. L'activation des AP (INIT-SIPI-SIPI), les IPI et le *TLB shootdown* sont prévus au jalon M10.

---

## ADR-016 — Chaîne Rust : nightly épinglé, dépendances `no_std` auditées

**Décision.**
- On garde un nightly épinglé dans `rust-toolchain.toml` (nécessaire pour `abi_x86_interrupt` et `naked`), mis à jour au plus une fois par trimestre, avec un passage complet de la CI.
- Toute dépendance ajoutée à une crate noyau doit être `no_std`, sans `build.rs` réseau, et doit être justifiée dans sa PR.
- Dépendances autorisées : `x86_64`, `bitflags`, `spin` (outils seulement), `log`, `ttf-parser`.

---

## ADR-017 — Volume système en FAT32 tant que NTFS n'est pas en écriture

**Décision.**
- `C:` est en FAT32 : XP s'installait aussi sur FAT32. Le pilote FAT existant (aujourd'hui en lecture seule) passe en lecture et écriture.
- NTFS arrive en lecture seule au jalon M9, puis en écriture.
- Le chargeur lit le noyau sur l'ESP et le hive `SYSTEM` sur `C:`, via les protocoles de fichiers UEFI (le firmware sait lire le FAT).

---

## ADR-018 — Conformance : `rostests` et scénarios QEMU

**Décision.** La compatibilité se mesure par :

1. les tests unitaires hôte (`cargo test`) pour toute logique pure (dispatcher, VAD, ruches, PE, FAT, GDI) ;
2. des scénarios de démarrage QEMU sans affichage, avec des marqueurs série attendus ;
3. les `rostests` de ReactOS (apitests et winetests) exécutés dans Mino. Le taux de réussite par module est suivi dans le temps.

---

## ADR-019 — Décisions de l'ancien `CLAUDE.md` (remplacées)

| Ancienne règle | Statut | Remplacée par |
|---|---|---|
| « No Win32 desktop / no Win32k GDI / no window manager » | ❌ Abandonnée | Objectif clone XP, §7 de l'architecture |
| « Mino Display Server » et lanceur egui natif | ❌ Abandonnée | `winlogon` et `explorer` |
| « DXVK prebuilt + `vulkan-1.dll` shim only » | ❌ Abandonnée | ADR-006 |
| « Do NOT implement COM fully » | ❌ Caduque | `ole32` de ReactOS |
| Win32 implémenté en appels système privés `0x2000+` | ❌ Abandonnée | ADR-002 |
| `mino-pack` (installer sous Windows puis copier) | ⚠️ Optionnelle | Les installeurs (MSI, InstallShield, NSIS) deviennent une cible du jalon M7 |
| « Monolithic kernel with NT Executive layering » | ✅ Conservée | §5 |
| « `no_std` in all kernel crates » | ✅ Conservée | ADR-016 |
| « PEB OS version 5.1.2600 » | ✅ Conservée | ADR-003 |
| « Every `unsafe` needs `// SAFETY:` » et la discipline d'IRQL | ✅ Conservées et renforcées | [06 — Conventions](06-conventions.md) |

---

## ADR-020 — DEP : règle OptIn d'XP SP2, exécution permise par défaut

**Contexte.** Le noyau tourne en mode long et pose le bit NX sur toute page utilisateur dont la protection n'est pas `PAGE_EXECUTE*`. C'est un DEP actif pour tous les processus. XP SP2 a introduit DEP avec quatre politiques système :
- `OptIn` : le défaut d'un poste client ;
- `OptOut` ;
- `AlwaysOn` ;
- `AlwaysOff`.

Sous `OptIn`, un programme qui ne l'a pas demandé tourne sans DEP. Or beaucoup de jeux de l'époque exécutent des pages de données : compilateurs à la volée, packers, code qui se modifie. Sous Mino, ils plantent, alors qu'ils tournent sur un XP SP2 par défaut.

**Décision.**
- La politique du système est `OptIn`. Les trois autres sont nommées (`ps::eprocess::DepPolicy`), et une option de démarrage les choisira plus tard.
- Chaque processus porte ses options d'exécution, avec les valeurs `MEM_EXECUTE_OPTION_*` de l'ABI (`abi::process`). Elles sont fixées à sa création d'après la politique :
  - `OptIn` : DEP coupé ;
  - `OptOut` : DEP actif ;
  - `AlwaysOn` : DEP actif, de façon permanente ;
  - `AlwaysOff` : DEP coupé, de façon permanente.
- Il n'y a pas de liste de binaires système. Sous `OptIn`, tous les processus commencent sans DEP, ceux de ReactOS compris. Un processus active DEP par `NtSetInformationProcess(ProcessExecuteFlags)` (appel système au M3, `EProcess::set_execute_options` dans le noyau) ; avec `PERMANENT`, son choix ne change plus.
- **Sans DEP**, toute page utilisateur lisible s'exécute, comme sur XP sans NX. **Avec DEP**, seules les protections `PAGE_EXECUTE*` s'exécutent.
- La VAD garde la protection demandée : `NtQueryVirtualMemory` la rend telle quelle. Seuls les droits des pages en dépendent (`AddressSpace::set_execute_enabled`), et un changement s'applique aussitôt aux pages présentes.
- Le noyau garde NX pour ses propres pages, quelle que soit la politique (W^X, ADR-014).

**Conséquences.**
- Les programmes qui exécutent leurs données tournent par défaut, comme sur XP SP2.
- Pas encore : l'émulation des thunks ATL d'XP SP2 pour les processus sous DEP (`MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION` est accepté, sans effet), ni la liste d'exceptions d'`OptOut`.

---

## ADR-021 — win32k : ce que USER partage avec ses clients, à des adresses du serveur sur 32 bits

**Contexte.** Le `user32` de ReactOS épinglé (ADR-002) lit en lecture seule ce que win32k partage avec lui : le `SERVERINFO`, la table des handles USER, plus tard les tas de bureau et le `DISPLAYINFO`. Sur un noyau 32 bits, ces structures contiennent des pointeurs du noyau : le client y retrouve un octet en ôtant un écart (`ulSharedDelta` pour la section partagée, `ulClientDelta` pour un tas de bureau : `SharedPtrToUser`, `DesktopPtrToUser`), et il compare sans les suivre ceux d'un `PROCESSINFO` ou d'un `THREADINFO` (`CLIENTINFO.ppi`, propriétaires des handles). Le noyau de Mino est en 64 bits (ADR-001) : ses adresses n'entrent pas dans ces champs de 32 bits, dont le format est imposé par `user32`.

**Décision.**
- Tout pointeur que win32k met dans une structure vue d'un client est une **adresse du serveur** sur 32 bits, dans la moitié haute des 4 Gio, où un client 32 bits ne peut rien lire : un client qui suit un tel pointeur sans l'écart fait une faute, comme sur XP.
- La section partagée de USER est en `0xBC000000` dans cet espace (`win32k::shared::SERVER_BASE`) ; l'écart d'un client est cette adresse moins celle de sa vue, modulo 2^32. `NtUserProcessConnect` rend le `SERVERINFO` et la table des handles déjà dans la vue du client, comme ReactOS (`SERVER_TO_CLIENT`) ; les pointeurs rangés *dans* la section restent des adresses du serveur.
- Un `PROCESSINFO` ou un `THREADINFO` a pour adresse du serveur une valeur tirée de son PID ou de son TID (`0x80000000 | (PID / 4) << 4`, `0x90000000 | (TID / 4) << 4`), unique tant que l'objet vit, jamais suivie par un client.
- Le noyau n'emploie pas ces adresses pour lui-même : il écrit la section par l'alias de ses pages (`mm::section::Section::write_kernel`). Chaque zone partagée à venir (tas de bureau, `DISPLAYINFO`) aura sa plage d'adresses du serveur, documentée avec le module qui la crée, entre `0xA0000000` et `0xFFFFFFFF` hors de celles déjà prises.

**Conséquences.**
- ✅ Les structures partagées gardent le format exact de la version épinglée (ADR-002), sans couche de traduction côté client.
- ✅ Un pointeur du serveur suivi par erreur fait une faute au lieu de lire n'importe quoi.
- ❌ win32k traduit lui-même ses adresses du serveur en positions dans ses zones partagées ; les plages limitent la taille de chaque zone.
- La décision suit le spike S3 : si `user32` de ReactOS s'avère trop couplé à win32k (repli de l'ADR-002, `user32` de Wine), elle ne vaudra que pour ce que ce repli partagera encore.

---

## ADR-022 — FAT32 : la crate partagée `fatfs` ; formatage et partitions servis par le noyau

**Contexte.** Le volume système est en FAT32 (ADR-017), construit à l'avance par `tools/mkfat` : le noyau monte et écrit du FAT32 (`kernel/io`), mais ne sait ni lire une table de partitions (le disque de test porte un volume brut) ni formater un volume. Le chantier « installation et formatage » doit partitionner un disque vierge, le formater et y copier le système. Sous XP, la création de partitions passe par un IOCTL du noyau (`IOCTL_DISK_SET_DRIVE_LAYOUT`, ce qu'emploie `diskpart`) ; le formatage, lui, se fait en mode utilisateur : `format.com` délègue à `fmifs.dll`, qui écrit les secteurs bruts du volume démonté.

**Décision.**
- Une crate `libs/fatfs`, `no_std` avec `alloc`, sur le pattern de `regf` (ADR-012) : la **seule source de vérité** de l'écriture FAT32. Elle tient aujourd'hui la construction d'une image entière, déplacée de `tools/mkfat` sans un changement d'octet (l'image produite est la même, test de non-régression à l'appui) ; le formatage incrémental d'un volume monté (un trait `WriteSectors`, secteur par secteur, sans tampon de la taille du disque) s'y ajoutera, partageant la géométrie et les entrées de répertoires. `tools/mkfat` ne garde que ses arguments et ses programmes de test.
- Le formatage et les partitions sont **servis par le noyau**, derrière `NtDeviceIoControlFile` (numéro déjà généré par `syscall-gen`, ADR-002) : la création de partitions par `IOCTL_DISK_SET_DRIVE_LAYOUT`, comme `diskpart` ; le formatage par un IOCTL propre à Mino (`IOCTL_MINO_FORMAT_VOLUME`, un `CTL_CODE` de la plage privée de `FILE_DEVICE_DISK_FILE_SYSTEM`, documenté dans `docs/compat/io-install.md`). Le programme d'installation (natif, lié à `ntdll`) ne fait qu'appeler ces IOCTL : aucune logique de formatage en mode utilisateur.
- Les tables de partitions : **GPT d'abord**, avec son MBR protecteur — l'image cible est GPT (02 §9.1) ; le MBR réel des disques d'XP attend le matériel (M9).
- Les tests croisés suivent l'image : `fatfs` construit, `io-manager` (le lecteur FAT du noyau) relit, `fsck.vfat` valide. Les images de test et les volumes formatés sont identiques par construction.

**Conséquences.**
- ✅ Une seule implémentation de l'écriture FAT32, partagée par l'outil hôte, le noyau et les tests : `mkfat` et le formatage ne peuvent pas diverger.
- ✅ L'énumération (`NtQueryDirectoryFile`) et le formatage ne dépendent pas du sous-système graphique : le chantier se mène en parallèle de la ligne win32k, crates disjointes.
- ❌ Un IOCTL de formatage est un écart avec XP, où `fmifs` formate côté utilisateur ; le repli (un `fmifs` en mode utilisateur au-dessus de la même crate) reste ouvert, la crate s'y prêtant.
- ❌ Un code d'IOCTL hors des numéros ReactOS : les codes d'IOCTL ne sont pas des appels système — la règle des numéros générés (06 §2) ne s'y applique pas — mais la plage privée reste à documenter là où elle sert.
- **Statut proposé** : la partie crate est acquise par construction (le repli `fmifs` l'emploierait aussi) ; c'est le service par le noyau que le mainteneur tranche.

---

## ADR-023 — Premier démarrage en mode installation : couche Mino des ruches (`mino.inf`) et fin d'installation par un programme Mino

**Contexte.** L'ADR-012 (acceptée) veut des ruches générées par `tools/mkhive` depuis les `.inf` de ReactOS, plus une
couche Mino (version XP, pilotes intégrés, ouverture de session automatique). En attendant `mkhive`, le disque porte
les ruches de la version épinglée, celles de son LiveCD : `Setup\SetupType` = 1 et `CmdLine` = `setup -mini`.
`winlogon` lance donc l'installation au lieu de l'ouverture de session (`compat/m5-csrss.md`, étape 26), ce qui
arrête le premier critère du M6 (`winlogon`, `userinit`, `explorer`). Mettre `SetupType` à 0 ne suffit pas : la ruche
SAM épinglée est vide, et `samsrv` ne crée les comptes (`Administrator`, `Guest`) qu'en mode installation
(SampIsSetupRunning lit le même `SetupType`) ; l'ouverture de session demande aussi les profils (`ProfileList`, le
profil `Default User` et son `NTUSER.DAT`), que la seconde étape de l'installation de ReactOS (`syssetup`,
InstallReactOS) crée. Le mainteneur a choisi le chemin le 2026-11-10 : le même enchaînement que ReactOS, en deux
démarrages.

**Décision.**
- La couche Mino est un fichier `.inf` (`tools/mkhive/mino.inf`), dans la syntaxe des couches de ReactOS
  (`boot/bootdata/livecd.inf` : sections `[AddReg]` et `[DelReg]`), appliqué par `tools/mkhive` aux ruches de base
  quand `xtask` construit le disque. Aujourd'hui la base est celle des ruches épinglées ; quand `mkhive` les générera
  des `.inf` de ReactOS (ADR-012), la même couche s'y appliquera.
- La couche met le système en **mode installation au premier démarrage** : `SetupType` = 1, `CmdLine` = le programme
  de fin d'installation de Mino (`%SystemRoot%\system32\minoinit.exe`). Elle porte aussi ce qu'un système installé
  a de fixe : le nom de la machine (`MINO`), l'ouverture de session automatique d'`Administrator` sans mot de passe
  (`AutoAdminLogon`, `DefaultUserName`, `DefaultDomainName`, `DefaultPassword`), le répertoire des profils et les
  dossiers du shell d'un système installé (ceux de `hivesft.inf` et `hivedef.inf`, que le LiveCD avait changés).
- Au premier démarrage, `samsrv` remplit la SAM lui-même ; `winlogon` lance `minoinit.exe` (un programme Mino,
  sous-système WINDOWS, `tests/native/minoinit.c`), qui fait la part d'InstallReactOS dont dépend l'ouverture de
  session : les profils (InitializeProfiles de `userenv`), le `NTUSER.DAT` du profil `Default User` (une copie de la
  ruche `DEFAULT`), puis `SetupType` = 0, `SystemSetupInProgress` = 0, `CmdLine` vide, les ruches réécrites sur le
  disque (NtFlushKey), et le redémarrage (NtShutdownSystem).
- Au second démarrage, `winlogon` va au logon : `msgina` ouvre la session d'`Administrator`.

**Conséquences.**
- ✅ L'enchaînement est celui de ReactOS : `samsrv`, `lsasrv` et `userenv` créent eux-mêmes leurs données, dans leurs
  formats ; Mino n'écrit pas le format interne de la SAM.
- ✅ La couche est un `.inf` lisible, qui survivra au passage à `mkhive` ; l'installateur de Mino (ADR-022) y trouve sa
  suite : le système qu'il copie finit son installation à son premier démarrage.
- ❌ Deux démarrages avant le bureau, et des écritures du registre qui persistent entre eux : le premier démarrage
  dépend de la SAM et des profils en mode utilisateur (registre, création de répertoires, copie de fichiers,
  NtFlushKey). Le scénario de bout en bout démarre deux fois sur le disque système (`disk = system`).
- ❌ Un compte `Administrator` sans mot de passe ouvert automatiquement : acceptable pour un système de développement ;
  le choix d'un mot de passe viendra avec une vraie fin d'installation.
- ⚠️ `minoinit.exe` est une partie réduite de `syssetup` ; ce qu'il ne fait pas (enregistrement des DLL, raccourcis,
  thèmes, assistant) reste à faire, par lui ou par le vrai `syssetup` quand Mino pourra l'exécuter.

**Alternatives écartées.**
- *Tout générer à la construction de l'image* (la SAM, ses comptes et ses alias, et les profils, écrits par `xtask`) :
  un seul démarrage, déterministe, mais il faudrait reproduire sur l'hôte le format interne de `samsrv`, et suivre la
  version épinglée.
- *La vraie seconde étape de ReactOS* (`setup -newsetup`, `syssetup`) : la plus fidèle, mais elle demande le
  traitement des `.inf` par `setupapi`, l'enregistrement des DLL, COM et l'assistant ; hors de portée aujourd'hui.
- *Changer `SetupType` dans le noyau au démarrage* : un contournement silencieux, et la SAM resterait vide.

**À valider.** Le scénario `logon` (`disk = system`, deux démarrages) : au premier, `samsrv` crée `Administrator` et
`minoinit.exe` va au bout ; au second, `winlogon` va au logon au lieu de l'installation, et `msgina` tente l'ouverture
de session automatique d'`Administrator`. Jusqu'où elle va est suivi dans `docs/compat/m5-csrss.md`.
