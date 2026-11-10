# 01 — Vision et périmètre

## L'objectif

**Mino est un système d'exploitation libre, compatible Windows XP, dont le noyau est écrit en Rust.**

Le résultat attendu se décrit simplement : on démarre la machine, on arrive sur un bureau de style XP (barre des tâches, menu Démarrer, explorateur de fichiers, panneau de configuration), puis on y lance des applications et des jeux 32 bits de l'ère XP (2001–2008) sans les modifier.

C'est le même objectif que ReactOS. La différence tient à la répartition du travail :

- **Mino écrit en Rust tout le code privilégié** : le noyau (`ntoskrnl`), la partie noyau du sous-système Win32 (`win32k`) et les pilotes.
- **Mino réutilise l'espace utilisateur existant**, c'est-à-dire les DLL, services et applications de ReactOS et Wine, en binaires épinglés à une version. Ces composants peuvent ensuite être remplacés un par un par du Rust, quand c'est utile.

L'espace utilisateur de Windows représente des millions de lignes, et ReactOS comme Wine y ont consacré plus de vingt ans. Le refaire seul n'est pas réaliste. En revanche, un noyau NT sûr et lisible en Rust est un objectif atteignable, et c'est là que Rust apporte le plus.

## Ce que veut dire « compatible XP »

| Niveau | Contrat | Comment on le vérifie |
|---|---|---|
| **ABI utilisateur** | Les exécutables PE32 i386 tournent sans modification. On fournit les structures visibles en mode utilisateur (PEB, TEB, `KUSER_SHARED_DATA`), les conventions d'appel système, la gestion des exceptions (SEH) et les callbacks noyau → utilisateur. | Les suites de tests ReactOS (`rostests` : apitests et winetests) |
| **API Win32** | Le comportement d'API des DLL ReactOS et Wine, puisqu'on les réutilise | Tests de conformance Wine |
| **Expérience utilisateur** | Bureau, shell, panneau de configuration et outils dans l'esprit d'XP | Recette manuelle à chaque jalon |
| **Pilotes** | **Aucune compatibilité binaire** avec les `.sys` d'XP. Les pilotes sont écrits en Rust sur le modèle IRP de NT. | — |

On vise la version **NT 5.1 (XP) telle que les applications la perçoivent**. Les DLL ReactOS ciblent quant à elles le noyau NT 5.2 (Server 2003). Le noyau Mino implémente donc les interfaces dont ces DLL ont besoin, tout en se présentant aux applications comme XP (5.1.2600). Voir l'ADR-003.

## Ce qui n'est pas dans le périmètre

- **Le code, les binaires et les ressources de Microsoft** : ni DLL, ni thème Luna, ni fond d'écran Bliss, ni polices, ni sons. Ni, surtout, le code source d'XP qui a fuité : **il est interdit de le consulter** (voir [06 — Conventions](06-conventions.md)).
- **La compatibilité binaire avec les pilotes noyau d'XP**, qu'ils soient WDM, NDIS ou miniport.
- **Les programmes 16 bits** (DOS et Win16 via NTVDM). On pourra les envisager plus tard, mais rien n'est prévu.
- **L'activation, WGA, DRM, SafeDisc et StarForce.** Les jeux qui en dépendent sont hors périmètre.
- **Le multi-utilisateur réel et la sécurité de niveau serveur** avant la fin de la feuille de route. Les structures de sécurité existent dès le départ, mais leur application est assouplie au début (voir ADR-011).
- **Les applications 64 bits.** L'architecture leur laisse une place (ADR-001), mais elles ne sont pas planifiées.

## Les jalons visibles

Le détail se trouve dans [05 — Feuille de route](05-feuille-de-route.md). Vu de l'extérieur, le projet passe par ces étapes :

1. **Noyau sain** : threads, synchronisation, espaces d'adresses séparés, exceptions.
2. **Mode natif** : `ntdll` (ReactOS) et `smss.exe` tournent sur le noyau Mino.
3. **Mode console** : `csrss` est opérationnel et `cmd.exe` est interactif.
4. **Bureau** : `winlogon` et `explorer` affichent le bureau et la barre des tâches.
5. **Applications** : Bloc-notes, Paint, éditeur de registre, panneau de configuration, installeurs.
6. **Multimédia et jeux** : Direct3D 8/9 en rendu logiciel, son, DirectInput. Le jeu de référence est *Ghost Recon* (2001), version GOG.
7. **Matériel réel et réseau** : AHCI, NVMe, USB, réseau, NTFS.
8. **Maturité** : multiprocesseur (SMP), sécurité réelle, installeur, remplacement progressif de composants par du Rust.

## Les plateformes cibles

| Plateforme | Statut |
|---|---|
| QEMU (OVMF, q35) | Plateforme de référence. Les tests automatisés et la CI tournent dessus. |
| VirtualBox (EFI) | Seconde plateforme de test |
| Machines réelles x86-64 avec UEFI | À partir du jalon « matériel réel » |
| BIOS sans UEFI, CPU 32 bits | Hors périmètre (ADR-001) |
