# Applications Win32 x86 : validation fonctionnelle

Branche `feat/m7-classic-apps`, base main `abfe106`, suite de la PR #127.
Les exécutables de référence sont ceux de ReactOS 0.4.16 (`51bfc703`), déjà
épinglés et vérifiés par `xtask fetch-userland`. Aucun binaire Microsoft.

| Application | Parcours à vérifier | État de cette campagne |
|---|---|---|
| Bloc-notes | Nouveau document, saisie au clavier, Enregistrer sous, contenu exact sur disque, fermeture normale, réouverture et rendu | PASS QEMU AMD et Intel |
| Calculatrice | Lancer, `12 + 30 = 42`, fermer, relancer, `6 × 7 = 42`, rendu du résultat | PASS QEMU AMD et Intel (`calculator`) |
| Démineur | Drapeau au clic droit, F2, fermeture, relance | PASS QEMU AMD et Intel (`minesweeper`) |
| Gestionnaire des tâches | Fermer, relancer, naviguer entre Applications et Processus | PASS QEMU AMD et Intel (`desktop-launch`) |

## Bloc-notes

`tests/boot/notepad-save` lance `NOTEPAD2.EXE`, une sonde qui démarre le vrai
Bloc-notes. QEMU tape `Hello, Mino!`, une nouvelle ligne, puis `Line 2`, Ctrl+S
et le chemin `C:\MINO-NOTE.TXT`. Seul le Bloc-notes écrit le fichier ; la sonde
vérifie ses 20 octets, attend sa fermeture normale, lance un nouveau processus
sur ce fichier et les vérifications d'écran contrôlent le texte relu.

La sonde vérifie aussi le remplacement/restauration d'une procédure de fenêtre
Unicode (GWLP_WNDPROC), nécessaire aux fenêtres ATL utilisées par le shell.
Elle ne remplace ni `comdlg32`, ni `shell32`, et ne désactive pas l'autocomplétion.

Reproduction sur main : fenêtre Save As visible, puis assertion
`atlwin.h:1118`, `::IsWindow(m_hWnd)`. Le fichier n'est pas créé et le nouveau
scénario échoue sur `[apps] FAIL: saved file contents`. L'ancien scénario
`notepad` valide uniquement la saisie et Ctrl+G, pas l'enregistrement.

Correctifs : GWLP_WNDPROC remplace/restaure une procédure cliente dans le
processus propriétaire, publie le nouveau pointeur dans WND et rend l'ancien.
Les conversions ANSI/Unicode et les procédures serveur nécessitent encore
des thunks ; ces cas rendent explicitement ERROR_CALL_NOT_IMPLEMENTED.
Alt+F4 poste SC_CLOSE à la fenêtre de premier niveau (sauf CS_NOCLOSE), puis
laisse l'application traiter normalement WM_CLOSE. Aucun processus n'est tué.

Validation : `notepad-save` passe sur AMD (`int 2Eh`) et Intel (`SYSENTER`) ;
322 tests hôte de win32k passent. Le fichier est sur le volume de démarrage
en RAM de ce scénario : ce test ne prouve pas la persistance après reboot.
Reprise : `cargo xtask test --boot --scenario notepad-save`.

## Calculatrice

`CALC1.EXE` lance `calc.exe` ; les touches viennent de QEMU. Le contrôle
statique de sortie doit contenir exactement `42.` après chaque calcul. La
capture vérifie les glyphes `42.` du second processus. Le premier processus
doit avoir quitté normalement, code 0, avant la relance.

Cause de l'échec initial (affichage bloqué à `0.`) : `post_key_press` appelle
GetClassName avant de transmettre un clic au bouton ; le service absent
renvoyait 0. NtUserGetClassName lit maintenant le nom non versionné de la
classe dans la table des atomes, respecte la capacité en UTF-16, termine par
NUL et rend le nombre d'unités copiées. Les accès passent par les helpers de
mémoire utilisateur. La sonde couvre GetClassNameW/A, troncature sans écrire
au-delà, capacité d'un seul NUL, pointeur et HWND invalides. La résolution des
superclasses de RealGetWindowClass reste à faire.

MapVirtualKeyEx reste absent ; ce n'est pas le blocage observé ici : ToAsciiEx
peut encore traduire ces touches par la disposition chargée. Pas de
validation des fonctions scientifiques, de l'aide HTML ou du presse-papiers.

## Démineur

`MINE1.EXE` lance `winmine.exe` (titre WineMine). La sonde lit les 256 pixels
de la première case, sans écrire dans le jeu. Un clic droit PS/2 doit faire
apparaître le rouge du drapeau et changer la case. F2 doit restituer les
256 pixels de la case couverte. Alt+F4 doit terminer le processus normalement ;
la relance doit afficher une case identique. La capture contrôle le relief
de la case et le visage. La souris est déplacée hors de la case après le
clic. Une partie gagnée/perdue et le son ne sont pas validés.

## Portée

Ces parcours portent sur les binaires x86 épinglés, pas sur toute application
XP. Les images de test incluent désormais `calc.exe`, `winmine.exe` et leurs
imports. La CI exécute les trois nouveaux scénarios et `desktop-launch` sur
les deux chemins d'appels système. Commande de la campagne :

```sh
cargo xtask test --boot --scenario notepad-save --scenario calculator --scenario minesweeper --scenario desktop-launch
```

Bilan de la campagne : 8 démarrages sur 8 réussis, 1 090 tests hôte réussis,
`cargo xtask lint` propre. Ce bilan porte sur la base initiale `3942dd5` ; revalidation sur `abfe106` en cours.
Pas de validation VirtualBox dans cette campagne.

Captures QEMU réelles : [Bloc-notes rouvert](../images/notepad-save.png),
[Calculatrice après relance](../images/calculator.png),
[Démineur après relance](../images/minesweeper.png).
