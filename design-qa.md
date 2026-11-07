# Revue visuelle du redesign

Référence : `mino-installer-mockups.html`, fournie avec la demande de
redesign. Les captures de référence ont été comparées aux rendus QEMU des
scénarios `installer-ui` et `desktop-ui` en 1280 × 800.

| Surface | Vérification | Résultat |
|---|---|---|
| Installateur | Rail bleu, cinq étapes, en-tête blanc, contenu beige, cartes d'état et barre d'actions fixe | Conforme |
| Installateur | Hiérarchie des actions, focus clavier et texte honnête sur GPT, FAT32 et copie future | Conforme |
| Bureau | Fond beige, barre des tâches, menu Démarrer et fenêtre Files | Conforme |
| Bureau | Contraste, zones sélectionnées et alignement sur la grille compacte de la maquette | Conforme |
| Tests | Rendu et marqueurs après paint sur CPU par défaut et Intel | Conforme |

Les pictogrammes utilisent encore des formes et glyphes GDI simples. Une
bibliothèque d'icônes pourra les remplacer lorsque le shell et Files
quitteront les sondes natives. Cela ne bloque ni la navigation ni la lecture
des états.

Final result: passed.
