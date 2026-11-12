# Applications Win32 x86 : validation fonctionnelle

Branche `feat/m7-notepad-app-validation`, base main `3942dd5`.
Les exécutables de référence sont ceux de ReactOS 0.4.16 (`51bfc703`), déjà
épinglés et vérifiés par `xtask fetch-userland`. Aucun binaire Microsoft.

| Application | Parcours à vérifier | État de cette campagne |
|---|---|---|
| Bloc-notes | Nouveau document, saisie au clavier, Enregistrer sous, contenu exact sur disque, fermeture normale, réouverture et rendu | Échec reproduit sur main ; correction en cours |
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

Reprise : `cargo xtask test --boot --scenario notepad-save --cpu default`.
Ne cocher le critère M6 qu'après succès du parcours complet sur AMD et Intel.
