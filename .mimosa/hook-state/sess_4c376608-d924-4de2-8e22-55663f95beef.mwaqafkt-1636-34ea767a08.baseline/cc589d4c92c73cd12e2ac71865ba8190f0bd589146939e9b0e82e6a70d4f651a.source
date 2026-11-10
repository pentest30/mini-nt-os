---
name: mino-adr
description: Écrire, proposer, faire accepter, remplacer ou relire une décision d'architecture (ADR) de Mino, dans docs/03-decisions.md. À utiliser quand un choix structurant se présente (dépendance, frontière d'ABI avec ReactOS, format sur disque, licence, écart voulu avec ReactOS qui engage plusieurs composants), quand le mainteneur accepte ou tranche une ADR, ou pour savoir si un choix mérite une ADR.
---

# Les décisions d'architecture de Mino

Les règles viennent de `docs/03-decisions.md` (son en-tête), de `docs/06-conventions.md` (§7 et §8) et de
`CLAUDE.md`. En cas de doute, ces documents font foi.

## 1. Faut-il une ADR ?

Oui pour une décision **structurante** (06 §8) : elle engage plusieurs crates ou la frontière avec l'espace
utilisateur, on la défera difficilement, ou on en aura besoin pour comprendre le code dans un an. Les ADR existantes
donnent la mesure : une dépendance (ADR-016, ADR-013), la frontière d'ABI et ses formats (ADR-002, ADR-021), un format
sur disque (ADR-012, ADR-017), une politique du système (ADR-020), la licence (ADR-007).

Non pour :
- un détail d'un module : il va dans l'en-tête du module (`//!`) ;
- un écart avec ReactOS limité à une étape : il va dans `docs/compat/` (paragraphe « Écarts avec ReactOS » de
  l'étape) ;
- une règle de code : elle va dans `docs/06-conventions.md` ;
- un contournement provisoire : il est documenté et ouvre une tâche de diagnostic (règle 9 de `CLAUDE.md`).

## 2. Où et sous quel numéro

- **Un seul fichier** : `docs/03-decisions.md`. Pas de fichier par ADR, pas de répertoire `adr/` ni `decisions/`.
- Le **tableau** en tête liste chaque ADR : numéro sur trois chiffres, titre, statut. La **section** de chaque ADR suit,
  après un `---`, avec un titre `## ADR-0NN — Titre`.
- Le numéro est le plus grand du tableau plus un. Il ne sert jamais deux fois, même pour une ADR remplacée.

## 3. Les statuts

| Statut | Sens | Qui le donne |
|---|---|---|
| **Acceptée** | On construit dessus. | Le mainteneur seul. |
| **Proposée** | On construit dessus, mais un spike doit la confirmer : le nommer (« spike S3 »). | Claude peut proposer. |
| **À décider** | Le choix revient au mainteneur : options, conséquences, recommandation. | Claude prépare. |
| **Remplacée** | Abandonnée, avec un renvoi vers l'ADR qui la remplace. | Avec la nouvelle ADR. |

Claude n'accepte jamais une ADR de lui-même : il la propose, ou la met « À décider », et demande au mainteneur. Quand
le mainteneur accepte, la section le dit avec la date : `**Statut.** Acceptée par le mainteneur le AAAA-MM-JJ`, et
les précisions qu'il a données (voir l'ADR-013).

## 4. La forme d'une section

```md
## ADR-0NN — La décision elle-même, pas son sujet

**Contexte.** La situation et ses contraintes (ReactOS épinglé, `no_std`, les ADR déjà prises), et ce qui oblige à
choisir maintenant. Les chiffres qui vieillissent (tailles, versions, coûts) sont datés.

**Décision.** Ce qu'on fait, à l'indicatif, sans conditionnel. Une liste si la décision a plusieurs points. Les
modules, types et fichiers entre accents graves (`win32k::gdi::rgnobj`).

**Conséquences.**
- ✅ Ce qui devient plus simple.
- ❌ Ce que cela coûte.
- ⚠️ Ce qui reste à surveiller, et les décisions qui en découlent.

**Alternatives écartées.**
- *L'option* : pourquoi on ne la prend pas.

**À valider.** Le spike, le test ou le scénario qui confirmera la décision (pour une ADR proposée, ou acceptée avec
des réserves).
```

Pour une ADR « À décider », la décision laisse place à un tableau **Options** (option, ce qu'elle permet, ce qu'elle
impose) et à une **Recommandation** argumentée (voir l'ADR-007).

Style : en français, des phrases courtes, comme le reste de `docs/`. Une ADR, une décision : deux choix
indépendants font deux ADR. Le titre affirme la décision (« Polices : rastériseur TrueType en Rust dans win32k »).
Respecter la règle 1 de `CLAUDE.md` (pas de marque « Windows » hors des noms de version imposés, aucun code
Microsoft cité).

## 5. Changer une décision

- Une ADR **proposée** ou **à décider** se précise librement jusqu'à son acceptation.
- Une ADR **acceptée** ne se réécrit pas. Pour la changer :
  1. écrire une nouvelle ADR, dont le contexte cite l'ancienne et dit ce qui a changé ;
  2. dans l'ancienne, ne changer que le statut : « Remplacée par l'ADR-0NN » dans le tableau, et le même renvoi en
     tête de sa section ; son texte reste tel quel ;
  3. la PR ajoute la nouvelle ADR avant tout changement du code qui dépendait de l'ancienne (06 §7).

## 6. Après l'ADR

- Mettre à jour ce qui y renvoie : `CLAUDE.md` (règles, liste des acquis), `docs/passation.md` (questions ouvertes,
  suite), `docs/05-feuille-de-route.md` si un jalon en dépend, `docs/02-architecture.md` si l'état cible change.
- Un commit à part, au format de la maison, par exemple `docs: ADR-022, <sujet>` pour une nouvelle ADR,
  `docs: accepter l'ADR-013 (polices)` pour une acceptation.

## 7. Avant de proposer, vérifier

- Le contexte suffit à quelqu'un qui n'a pas suivi la discussion.
- La décision est nette, et les alternatives écartées sont nommées avec leur raison.
- Les conséquences disent aussi ce que la décision coûte.
- Ce qui reste à prouver est écrit dans « À valider », avec le test ou le scénario qui le prouvera.
- Le tableau, la section et les renvois (`CLAUDE.md`, passation) disent le même statut.
