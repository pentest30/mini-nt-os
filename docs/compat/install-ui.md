# Interface de l'installateur

État de l'interface native et de son premier contrat noyau, au-dessus du constructeur
d'image GPT/FAT décrit dans [`io-install.md`](io-install.md). Le brief visuel
reste [`../design/installer-ui-prompt.md`](../design/installer-ui-prompt.md).

![Écran final de l'installateur Mino](../images/installer-ui-backend.png)

La présentation suit le langage visuel des assistants ReactOS et Windows XP :
rail bleu à cinq étapes, contenu blanc, barre d'actions beige et boutons en
relief. Les couleurs, le nom et les éléments graphiques restent propres à
Mino ; aucune ressource Microsoft n'est intégrée.

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

La préparation est réelle dans l'UI. À l'activation d'« Install »,
`SETUP1.EXE` renvoie le jeton de l'aperçu au noyau par
`IOCTL_MINO_SETUP_PREPARE` : celui-ci revalide le disque, écrit le MBR
protecteur et les deux copies GPT, puis les relit — et journalise le refus,
le cas échéant (`[setup] prepare failed: …`, l'écran d'installation reste
affiché, rien n'avance). Les étapes copier et configurer restent
simulées ; l'écran final le dit (« Partition tables written and reread;
file copy comes later »). Le handle d'ancrage reste un répertoire de `C:`
ouvert avec `FILE_READ_ATTRIBUTES` ; l'autorité d'écrire vient du jeton. Le
constructeur `cargo xtask image` reste le seul chemin qui crée une image
complète.

Le self-test noyau de la préparation est derrière la feature `test-install`
(scénarios `installer-prepare` et `persistence`) : les autres scénarios
gardent le disque cible vierge pour la préparation réelle de l'UI. Le
moteur tient en outre un **verrou exclusif** (`io_manager::install`) :
une seule préparation à la fois, `STATUS_DEVICE_BUSY` sinon. Chaque
marqueur `[setup] screen …` part **après** le paint de l'écran qu'il
nomme : le screendump du scénario ne prend plus une fenêtre à moitié
peinte (vu sur le chemin SYSENTER, où tout va plus vite).

Le scénario `installer-ui` injecte les touches par le moniteur de QEMU,
exerce Tab, Retour et Échap, attend les cinq progressions, la préparation
réelle et vérifie des pixels de l'écran final. Il tourne avec les modèles
de processeur AMD et Intel :

```bash
cargo xtask test --boot --scenario installer-ui
```

## Suite

1. Ajouter au contrat le démontage formel de la cible pendant l'écriture
   (la cible n'est pas montée : le verrou exclusif la couvre déjà), puis
   formater les deux vues bornées (`fatfs::format` est prêt), copier les
   fichiers et rendre des événements de progression ; la revue reste la
   dernière étape réversible.
2. Ajouter la souris PS/2, le ciblage par fenêtre, les messages `WM_MOUSE*`
   et le curseur dans `win32k`; la navigation clavier reste complète.
3. Ajouter les erreurs récupérables, le journal détaillé, la reprise sûre et
   le redémarrage seulement après relecture de GPT et vérification des
   fichiers copiés.

