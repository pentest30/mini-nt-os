# Revues de mergestorm-vortex

Le bot [mergestorm-vortex](https://github.com/apps/mergestorm-vortex) relit les PR du dépôt et y laisse des remarques.
Ce fichier rassemble l'évaluation de chacune de ses remarques, pour savoir ce que valent ses revues. Une session qui
traite l'une d'elles y ajoute la section de sa PR (voir « Ajouter une évaluation », plus bas).

## Verdicts

- **Fondé** : le défaut existe et un chemin réel l'atteint.
- **Partiellement fondé** : il y a un vrai défaut, mais l'effet décrit ou la correction proposée est faux.
- **Inatteignable** : c'est vrai de la fonction prise seule, mais aucun appelant ne l'atteint.
- **Faux** : le code est juste, la remarque se trompe.
- **Manqué** : un défaut du diff relu que le bot n'a pas signalé, trouvé par une autre revue, à la relecture ou par
  un test. Il compte à part.

## Bilan

| PR | Remarques | Fondées | Partiellement | Inatteignables | Fausses | Manqués |
|---|---|---|---|---|---|---|
| [149](https://github.com/pentest30/mini-nt-os/pull/149) | 3 | 1 | 1 | 1 | 0 | 2 |
| **Total** | **3** | **1** | **1** | **1** | **0** | **2** |

Pas encore évaluées : les 49 remarques des PR 122 (16), 123 (5), 125 (14), 126 (7), 132 (5), 133 (1) et 134 (1).

## Ajouter une évaluation

1. Vérifier chaque remarque dans le code de la PR, au commit relu, avant de conclure. Un verdict qui dépend d'un fait
   non vérifié porte « à confirmer » ; on le reprend quand on sait.
2. Ajouter en bas une section `## PR N : sujet`, avec le commit relu et la date. Elle a une ligne par remarque :
   - où (fichier et ligne) ;
   - la remarque, résumée en une phrase plutôt que copiée ;
   - le verdict ;
   - pourquoi, en citant le code qui le prouve ;
   - la suite donnée (le commit qui corrige, ou rien et pourquoi).
3. Lister ensuite les défauts manqués, avec qui les a trouvés.
4. Mettre à jour le bilan : la ligne de la PR, le total, et ce qui reste à évaluer.

## PR 149 : NtAccessCheck, l'effacement des fichiers, le banc des installeurs

Commit `60ec7a8`, relu le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/io/src/file.rs:653` | `check_open` accepte FILE_DELETE_ON_CLOSE sur un volume NTFS, en lecture seule ; le fichier ne serait pas effacé, sans erreur. | Inatteignable | `create_file` (`kernel/ntoskrnl/src/sys/file.rs`) refuse FILE_DELETE_ON_CLOSE sans DELETE. Sur un volume en lecture seule, `File::granted_access` rend `STATUS_MEDIA_WRITE_PROTECTED` pour DELETE, qui est dans `MUTATION_ACCESS`. La fonction seule reste incohérente avec `Volume::set_delete_pending`. | Refus ajouté à `check_open`, avec un test (en cours dans la PR 149). |
| `kernel/ntoskrnl/src/sys/file.rs:116` | Le commentaire dit que FILE_DELETE_ON_CLOSE ajoute DELETE, mais le code refuse l'ouverture sans DELETE. Selon le bot, le fichier temporaire de CreateFile échouerait. Il propose d'ajouter DELETE ou de corriger le commentaire. | Partiellement fondé | Le commentaire est faux et le code juste : la documentation publique de ZwCreateFile exige DELETE avec FILE_DELETE_ON_CLOSE. Ajouter DELETE s'écarterait de NT. L'échec de CreateFile suppose que le CreateFileW de `kernel32` n'ajoute pas DELETE (à confirmer). | Commentaire réécrit (en cours dans la PR 149). |
| `tests/native/appbench.c:266` | Si la boîte d'un installeur est figée, SendMessageW bloque le banc jusqu'au délai de QEMU, sans ses diagnostics. | Fondé | Un message envoyé à la fenêtre d'un autre thread attend que ce thread le traite. Une boîte figée est justement le cas que cette boucle cherche. | SendMessageTimeoutW, 2 s, puis IDOK (en cours dans la PR 149). |

Manqués :

- **Une ouverture et le dernier close du même fichier se croisent** (`kernel/ntoskrnl/src/sys/file.rs:166`). Un
  thread peut être préempté entre `check_open` et `handle_opened`. Pendant ce temps, `Volume::cleanup` efface le
  fichier en attente d'effacement, et l'ouverture rend un handle sur une entrée FAT effacée. Trouvé par la revue de
  Codex (P1).
- **`Volume::cleanup` efface le fichier sous un `KSpinLock`.** Il écrit sur le disque et alloue en tenant `opened`,
  donc à DISPATCH_LEVEL, contre 06 §4. Trouvé en vérifiant les remarques.
