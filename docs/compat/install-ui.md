# Interface de l'installateur

État de l'interface native et de son premier contrat noyau, au-dessus du constructeur
d'image GPT/FAT décrit dans [`io-install.md`](io-install.md). Le brief visuel
reste [`../design/installer-ui-prompt.md`](../design/installer-ui-prompt.md).

## Architecture retenue

L'installateur est un programme Win32 natif, lié aux `user32`, `gdi32`,
`kernel32` et `ntdll` de ReactOS épinglé. Il utilise donc les fenêtres, GDI,
les polices, les files de messages et l'entrée de `win32k` ; il n'introduit
pas une seconde boîte à outils qui dessinerait directement dans le
framebuffer.

`tests/native/setup1.c` est la sonde exécutable de ce choix. Le scénario
`installer-ui` la met à la place de `winlogon.exe`, comme les autres bancs
d'essai de USER. Elle ouvre une fenêtre à 760 × 520, qui tient dans un écran
de 800 × 600, et dessine ses contrôles avec GDI. C'est encore une sonde : le
programme définitif quittera `tests/native/` quand le chemin d'exécution du
moteur sera fixé.

## Aperçu privilégié en lecture seule

`NtDeviceIoControlFile`, avec `IOCTL_MINO_SETUP_QUERY`, donne à l'UI une
`abi::setup::SetupPreview` de 68 octets composée uniquement de mots 32 bits.
Elle contient la cible ATA, sa capacité, les deux plages de partitions et un
jeton stable calculé sur le plan. Cette première commande n'a aucun chemin
d'écriture.

`io_manager::install::Plan::guided` vérifie tout avant de rendre le plan :

- partitions alignées à 1 Mio et bornées par la plage GPT utilisable ;
- ESP FAT32 de 40 Mio et volume système FAT32 dans l'espace restant ;
- géométries acceptées par le même `fatfs::format` que le futur moteur ;
- média de démarrage primaire protégé ;
- disque qui porte `C:` protégé ;
- seul un maître secondaire présent, non monté et distinct du système peut
  porter le drapeau `SETUP_DISK_CANDIDATE`.

Le scénario `disk = target` crée un disque ATA secondaire vierge de 96 Mio.
L'UI ouvre la racine courante avec `FILE_READ_ATTRIBUTES`, demande l'aperçu
et affiche la capacité réelle. Pour ce disque, le plan rendu réserve 40 Mio
à l'ESP et 54 Mio au système. Sans cible sûre, Continuer reste bloqué.

## Machine d'états

| Écran | Entrée | Action primaire | Retour permis |
|---|---|---|---|
| Accueil | aucune | choisir le disque | non |
| Disque | cible de développement unique | revoir les changements | Tab puis Retour, ou Échap |
| Revue | cible, suppression, GPT, ESP et système | commencer l'installation | Tab puis Retour, ou Échap |
| Installation | cinq étapes et progression mesurable | aucune pendant la sonde synchrone | non après la limite d'écriture |
| Terminé | vérification réussie | demander le redémarrage | non |

Tab déplace le choix entre Retour et l'action primaire ; Retour ou Espace
l'active ; Échap revient en arrière tant qu'aucune écriture n'a commencé.
La fenêtre garde une position des actions constante, un focus visible, des
couleurs contrastées et les cinq étapes dans un rail latéral.

## Limite de sécurité actuelle

L'installation est simulée. L'activation d'« Install » journalise
`simulated write boundary`, montre les étapes préparer, partitionner,
copier, configurer et vérifier, puis une réussite explicitement qualifiée de
simulation. `SETUP1.EXE` ouvre seulement un répertoire de `C:` comme ancrage
du contrôle en lecture ; il ne reçoit aucun handle de disque brut. Le noyau
ne publie pas encore de contrôle de préparation ou d'exécution. Le
constructeur `cargo xtask image` reste le seul chemin qui crée une image
complète.

Le scénario `installer-ui` injecte les touches par le moniteur de QEMU,
exerce Tab, Retour et Échap, attend les cinq progressions et vérifie des
pixels de l'écran final. Il tourne avec les modèles de processeur AMD et
Intel :

```bash
cargo xtask test --boot --scenario installer-ui
```

## Suite

1. Ajouter au contrat privilégié le verrou exclusif et le démontage de la
   cible, puis une commande d'exécution qui exige le jeton du plan et revalide
   l'identité et la capacité avant la première écriture.
2. Écrire GPT, formater les deux vues bornées, copier les fichiers et rendre
   des événements de progression ; la revue reste la dernière étape
   réversible.
3. Ajouter la souris PS/2, le ciblage par fenêtre, les messages `WM_MOUSE*`
   et le curseur dans `win32k`; la navigation clavier reste complète.
4. Ajouter les erreurs récupérables, le journal détaillé, la reprise sûre et
   le redémarrage seulement après relecture de GPT et vérification des
   fichiers copiés.

