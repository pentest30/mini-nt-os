# Interface de l'installateur

État du premier jalon de l'interface native, au-dessus du constructeur
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
programme définitif quittera `tests/native/` quand son interface privilégiée
avec le moteur d'installation sera fixée.

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

## Limite de sécurité du premier jalon

L'installation est simulée. L'activation d'« Install » journalise
`simulated write boundary`, montre les étapes préparer, partitionner,
copier, configurer et vérifier, puis une réussite explicitement qualifiée de
simulation. `SETUP1.EXE` n'ouvre aucun disque et ne peut en modifier un. Le
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

1. Définir l'interface privilégiée du moteur : énumérer les disques,
   produire un plan immuable, verrouiller et démonter la cible, puis lancer
   l'écriture avec des événements de progression.
2. Brancher l'interface sur ce moteur tout en gardant la revue comme dernière
   étape réversible et en refusant le disque qui porte le système courant.
3. Ajouter la souris PS/2, le ciblage par fenêtre, les messages `WM_MOUSE*`
   et le curseur dans `win32k`; la navigation clavier reste complète.
4. Ajouter les erreurs récupérables, le journal détaillé, la reprise sûre et
   le redémarrage seulement après relecture de GPT et vérification des
   fichiers copiés.

