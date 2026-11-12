# Applications Win32 x86 : validation fonctionnelle

Branche `feat/m7-notepad-app-validation`, base main `3942dd5`.
Les exécutables de référence sont ceux de ReactOS 0.4.16 (`51bfc703`), déjà
épinglés et vérifiés par `xtask fetch-userland`. Aucun binaire Microsoft.

| Application | Parcours à vérifier | État de cette campagne |
|---|---|---|
| Bloc-notes | Nouveau document, saisie au clavier, Enregistrer sous, contenu exact sur disque, fermeture normale, réouverture et rendu | PASS QEMU AMD et Intel |
| Calculatrice | Lancer, calculer une expression, vérifier le résultat, fermer | À exécuter |
| Démineur | Lancer, interaction avec une case, nouvelle partie, fermer | À exécuter |
| Gestionnaire des tâches | Fermer, relancer, naviguer entre Applications et Processus | Scénario existant `desktop-launch`, régression à relancer |

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
