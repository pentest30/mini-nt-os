# Revue visuelle du redesign bleu

Demande : un design « totalement bleu XP » pour l'installateur et le bureau, à
la place de la version beige. Les rendus QEMU des scénarios `installer-ui` et
`desktop-ui` en 1280 × 800 ont été relus image par image.

| Surface | Vérification | Résultat |
|---|---|---|
| Installateur | Plein écran bleu : bandeaux bleu nuit, champ en dégradé, étapes et disque cible à gauche | Conforme |
| Installateur | Assistant dans une fenêtre à barre de titre bleue arrondie, en-tête blanc, cartes d'état, boutons brillants et focus visible | Conforme |
| Installateur | Texte honnête sur GPT, FAT32 et la copie à venir ; navigation clavier inchangée | Conforme |
| Bureau | Ciel bleu, icônes, barre des tâches bleue, bouton Start vert, zone de notification | Conforme |
| Bureau | Menu Démarrer en deux colonnes, fenêtre Files avec volet de tâches bleu | Conforme |
| Légal | Formes dessinées par le programme, police Tahoma de ReactOS, aucune ressource ni marque Microsoft | Conforme |

Le thème vit dans `tests/native/theme.c` : un canevas (DIB section de
32 bits), des primitives anticrénelées (dégradés, coins arrondis, disques,
traits) et les widgets (cadre de fenêtre, boutons, barre de progression,
cartes, icônes). Les pictogrammes restent des formes simples ; une
bibliothèque d'icônes pourra les remplacer quand le shell quittera les sondes
natives.
