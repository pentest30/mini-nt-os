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
| 002 | Espace utilisateur ReactOS épinglé ; la frontière est l'ABI noyau de ReactOS | **Proposée** (spikes S1–S3) |
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
| 013 | Polices : rastériseur TrueType en Rust dans win32k | Proposée |
| 014 | Noyau en ELF lié dans les 2 Gio supérieurs, sans mapping identité | Acceptée |
| 015 | Un seul CPU d'abord, mais conçu pour le SMP | Acceptée |
| 016 | Chaîne Rust : nightly épinglé, dépendances `no_std` auditées | Acceptée |
| 017 | Volume système en FAT32 tant que NTFS n'est pas en écriture | Acceptée |
| 018 | Conformance : `rostests` et scénarios QEMU | Acceptée |
| 019 | Décisions de l'ancien `CLAUDE.md` | Remplacées |

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

## ADR-013 — Polices : rastériseur TrueType en Rust dans win32k (proposée)

**Décision.** On parse les polices avec `ttf-parser` (`no_std`) et on les rastérise avec un rastériseur Rust (`ab_glyph_rasterizer` ou un rastériseur maison), avec mise en cache des glyphes. Le hinting est remplacé par un antialiasing en niveaux de gris, puis ClearType si nécessaire.

**Alternative.** FreeType en C lié au noyau, comme ReactOS. On l'écarte : c'est du C non sûr en ring 0.

**À valider :** le rendu de Tahoma et de ses substituts libres, ainsi que la métrique exacte de `GetTextExtentPoint32` (des boîtes de dialogue en dépendent).

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
