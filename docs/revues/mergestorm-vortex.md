# Revues de mergestorm-vortex

Le bot [mergestorm-vortex](https://github.com/apps/mergestorm-vortex) relit les PR du dépôt et y laisse des remarques.
Ce fichier rassemble l'évaluation de chacune de ses remarques, pour savoir ce que valent ses revues. Une session qui
traite l'une d'elles y ajoute la section de sa PR (voir « Ajouter une évaluation », plus bas).

## Verdicts

- **Fondé** : le défaut existe et un chemin réel l'atteint.
- **Partiellement fondé** : il y a un vrai défaut, mais l'effet décrit ou la correction proposée est faux.
- **Inatteignable** : c'est vrai de la fonction prise seule, mais aucun appelant ne l'atteint.
- **Faux** : le code est juste, la remarque se trompe.
- **Sans suite** : le fait décrit est vrai, mais Mino y suit ReactOS, sa spécification ; le bot compare à la
  documentation de Win32 ou à Wine.
- **Manqué** : un défaut du diff relu que le bot n'a pas signalé, trouvé par une autre revue, à la relecture ou par
  un test. Il compte à part, et seulement une fois vérifié.

## Bilan

| PR | Remarques | Fondées | Partiellement | Inatteignables | Fausses | Sans suite | Manqués |
|---|---|---|---|---|---|---|---|
| [122](https://github.com/pentest30/mini-nt-os/pull/122) | 16 | 6 | 1 | 2 | 1 | 6 | 1 |
| [123](https://github.com/pentest30/mini-nt-os/pull/123) | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| [125](https://github.com/pentest30/mini-nt-os/pull/125) | 14 | 8 | 1 | 0 | 0 | 5 | 0 |
| [126](https://github.com/pentest30/mini-nt-os/pull/126) | 7 | 2 | 0 | 1 | 0 | 4 | 0 |
| [132](https://github.com/pentest30/mini-nt-os/pull/132) | 5 | 2 | 3 | 0 | 0 | 0 | 0 |
| [133](https://github.com/pentest30/mini-nt-os/pull/133) | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| [134](https://github.com/pentest30/mini-nt-os/pull/134) | 1 | 0 | 0 | 0 | 0 | 1 | 0 |
| [149](https://github.com/pentest30/mini-nt-os/pull/149) | 3 | 1 | 1 | 1 | 0 | 0 | 2 |
| [152](https://github.com/pentest30/mini-nt-os/pull/152) | 7 | 7 | 0 | 0 | 0 | 0 | 1 |
| [155](https://github.com/pentest30/mini-nt-os/pull/155) | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| [156](https://github.com/pentest30/mini-nt-os/pull/156) | 7 | 3 | 0 | 0 | 2 | 2 | 0 |
| [157](https://github.com/pentest30/mini-nt-os/pull/157) | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| [161](https://github.com/pentest30/mini-nt-os/pull/161) | 2 | 0 | 2 | 0 | 0 | 0 | 2 |
| [162](https://github.com/pentest30/mini-nt-os/pull/162) | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| [163](https://github.com/pentest30/mini-nt-os/pull/163) | 2 | 0 | 1 | 0 | 0 | 1 | 0 |
| **Total** | **76** | **41** | **9** | **4** | **3** | **19** | **6** |

Toutes les remarques jusqu'à la PR 157 sont évaluées, puis celles des PR 161 à 163. Restent celles des PR 158 et 159
(fusionnées), et celles de la PR 160 sur sa branche.

Ce qui ressort :

- **Ce qui a servi.** La moitié des remarques sont fondées, et 14 ont donné un correctif. Le bot est bon sur les
  bornes : allocation demandée par l'appelant, épaisseur d'une plume, nom long, profondeur des menus. Il l'est aussi
  sur les documents qui contredisent le code.
- **Les remarques sans suite.** Elles sont 16 sur 52. Le bot juge d'après la documentation de Win32 ou Wine, alors que
  Mino suit ReactOS. Avant d'agir sur une remarque, il faut regarder ce que fait ReactOS épinglé.
- **Les redites.** Le bot répète une remarque d'une passe à l'autre ou d'une PR à l'autre. C'est le cas de S3 trois
  fois dans la PR 132, de l'alignement d'ACCEL dans les PR 125 et 126, et du paragraphe de `m6-logon.md` dans les
  PR 132 et 133.
- **Ce qu'il manque.** La concurrence et l'IRQL : dans la PR 149, il n'a vu ni la course entre l'ouverture et le
  dernier close, ni l'effacement sous un `KSpinLock`.

## Ajouter une évaluation

1. Vérifier chaque remarque dans le code de la PR, au commit relu, avant de conclure, et regarder ce que fait
   ReactOS épinglé (`third_party/reactos-0.4.16`, par `git show HEAD:<chemin>`). Un verdict qui dépend d'un fait non
   vérifié porte « à confirmer » ; on le reprend quand on sait.
2. Ajouter en bas une section `## PR N : sujet`, avec les commits relus par le bot et la date de l'évaluation. Elle a
   une ligne par remarque :
   - où (fichier et ligne) ;
   - la remarque, résumée en une phrase plutôt que copiée ;
   - le verdict ;
   - pourquoi, en citant le code qui le prouve ;
   - la suite donnée (le commit qui corrige, ou rien et pourquoi).
3. Lister ensuite les défauts manqués, avec qui les a trouvés. Un défaut signalé par une autre revue et pas encore
   vérifié va dans « Manqués possibles », hors du bilan.
4. Mettre à jour le bilan : la ligne de la PR, le total, et ce qui reste à évaluer.

## PR 122 : le défilement, le caret et les menus

Commits relus par le bot : `6e0021f`, `9a03386` et `48cb0bc` (trois passes). Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/ntoskrnl/src/sys/scroll.rs:176` | ScrollWindowEx et ScrollDC écrivent `prcUpdate` après le défilement : avec un pointeur invalide, l'appel échoue alors qu'il a pris effet. | Partiellement fondé | Pour ScrollWindowEx, ReactOS écrit aussi `prcUpdate` après le défilement, exprès (`NtUserScrollWindowEx`, `scrollex.c`). Pour ScrollDC, ReactOS sonde `prcUpdate` avant la copie, et Mino non. | Aucune : `give_rect` vient toujours après la copie. |
| `kernel/win32k/src/caret.rs:460` | Si `scroll_dc` échoue, `after_scroll` n'est pas appelé et le caret reste caché. | Inatteignable | `scroll_dc` n'échoue que si le DC que `get_dc_ex` vient de donner ne se verrouille plus. Le bot le dit lui-même difficile à atteindre. | Aucune. |
| `kernel/win32k/src/menu.rs:386` | La branche MIIM_TYPE de `set_item_info` n'écrit pas `f_type`. | Inatteignable | `user32` ajoute toujours MIIM_FTYPE à MIIM_TYPE (`MENU_NormalizeMenuItemInfoStruct`), et la branche MIIM_FTYPE écrit le type. Le noyau suit `IntSetMenuItemInfo` de ReactOS. | Aucune. |
| `kernel/win32k/src/menu.rs:603` | `with` change la table avant de la publier. Si la publication échoue, l'appel rend une erreur alors que le changement est fait, et DestroyMenu perd ses handles. | Fondé | `with` rend l'erreur de `publish_dirty` après le changement, et `destroy` prend `unwrap_or_default()` : les handles ne sont pas libérés. Il faut un tas du bureau plein. | Aucune, le code est inchangé sur `main`. |
| `kernel/win32k/src/scrollex.rs:212` | SW_SCROLLCHILDREN déplace toutes les filles, pas seulement celles qui touchent le rectangle. | Sans suite | ReactOS fait de même : toutes les filles bougent, et seules celles qui touchent reçoivent WM_MOVE (`co_UserScrollWindowEx`). | Aucune. |
| `kernel/win32k/src/window.rs:649` | SetMenu accepte le handle d'une barre détruite. | Sans suite | `IntSetMenu` de ReactOS rend TRUE sans rien vérifier quand le menu ne change pas. DestroyMenu y laisse la barre à la fenêtre (« Only in Win9x », d'après les tests de Wine). | Aucune. |
| `kernel/win32k/src/menu.rs:364` | Bloquant. La profondeur n'est mesurée que pour le sous-menu accroché : des arbres accrochés l'un sous l'autre grandissent sans fin, et les parcours récursifs avec eux sur la pile du noyau. | Fondé | | Corrigé par `80dd95b` (`Menus::depth_above`), avec un test. |
| `kernel/win32k/src/nonclient.rs:293` | Bloquant. Une fenêtre WS_POPUP à menu sans titre a la place de sa barre, mais ne la peint pas. | Fondé | | Corrigé par `172aa71`, avec un test. |
| `kernel/win32k/src/menu.rs:296` | MAX_ITEMS est compté sur le menu nommé, pas sur le sous-menu qui reçoit l'item. | Fondé | | Corrigé par `80dd95b`, avec un test. |
| `kernel/win32k/src/menubar.rs:235` | Un item MF_DISABLED sans MF_GRAYED n'est pas peint grisé. | Faux | MF_DISABLED seul désactive l'item sans le griser : c'est MF_GRAYED qui grise. | Laissé, consigné dans la passation. |
| `kernel/win32k/src/paint.rs:563` | Si BeginPaint ne peut écrire son PAINTSTRUCT, le caret reste caché. | Fondé | | Corrigé par `c4bad5a`, testé par le scénario `caret`. |
| `docs/compat/m6-fenetres.md:971` | La doc dit qu'un item changé remet `cyMenu` à 0, ce que `set_item_info` ne fait pas. | Fondé | Seuls l'insertion et le retrait remettent la hauteur à 0, comme `IntSetMenuItemInfo` de ReactOS : c'est la doc qui se trompe. | Aucune, la phrase est toujours là. |
| `kernel/ntoskrnl/src/sys/menu.rs:88` | InsertMenuItem n'a pas le refus de MIIM_BITMAP avec l'ancienne taille de structure. | Sans suite | `UserInsertMenuItem` de ReactOS accepte aussi l'ancienne taille, avec `hbmpItem` à 0, sans refuser MIIM_BITMAP. | Aucune. |
| `kernel/ntoskrnl/src/sys/menu.rs:346` | Un TPMPARAMS illisible fait rendre FALSE sans code d'erreur. | Sans suite | `NtUserTrackPopupMenuEx` de ReactOS sort de même sans SetLastError. | Aucune. |
| `kernel/win32k/src/menu.rs:306` | Un identifiant absent ajoute l'item au bout du menu au lieu d'échouer. | Sans suite | `MENU_InsertItem` de ReactOS ajoute au bout quand l'identifiant n'est pas trouvé. | Aucune. |
| `kernel/win32k/src/menutrack.rs:395` | Un sous-menu en cascade est placé d'après le rectangle de la fenêtre, et non d'après sa zone cliente. | Sans suite | `MENU_ShowSubPopup` de ReactOS part aussi du rectangle de la fenêtre, moins SM_CXDLGFRAME. | Aucune. |

Manqués :

- **Une copie dans une même surface peut écraser sa propre source** (`kernel/win32k/src/gdi/bitblt.rs`,
  `overlap_order`). Les rectangles sont triés par leur haut, puis par leur gauche. Or les régions de Mino ne sont pas
  normalisées en bandes (`gdi/region.rs` le dit), et BitBlt comme le défilement peuvent donc écraser la source d'un
  rectangle suivant. Trouvé par Codex (P2), toujours sur `main`. L'autre remarque de Codex, sur la cadence du caret,
  est sans suite : `IntSetCaretBlinkTime` de ReactOS ne fait aussi que garder la valeur.

## PR 123 : la couche Mino des ruches et le logon

Commit relu par le bot : `e5c00f9`. Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `docs/compat/io-install.md:439` | Les chiffres de la taille de l'ESP mêlent Mo et Mio, et ne se recoupent pas. | Fondé | | Corrigé par `68f0def` (le compte en Mio et en clusters). |
| `kernel/io/src/fat.rs:1231` | Les noms longs n'ont pas de limite. Au-delà de 63 entrées, le numéro d'ordre se lit comme le drapeau de la dernière, et plus de 255 caractères sont acceptés. | Fondé | | Corrigé par `c0084fa` : refus au-delà de 255 unités (`STATUS_OBJECT_NAME_INVALID`). |
| `kernel/io/src/fat.rs:1232` | Un échec au milieu de l'écriture laisse des entrées de nom long orphelines. | Fondé | | Corrigé par `c0084fa` : les entrées sont effacées si l'entrée 8.3 ne peut pas suivre. |
| `xtask/src/main.rs:203` | MINOINIT.EXE manque d'une image dont la ruche le fait lancer. | Fondé | Codex l'a vu aussi (P1). | Corrigé par `033ff25` (`native::system_programs`). |
| `xtask/src/userland.rs:142` | Les ruches réécrites par `mkhive` ont un descripteur sans DACL sur chaque clé. | Fondé | C'est sans effet tant que le contrôle d'accès reste permissif. | Laissé, consigné dans la passation. |

## PR 125 : la barre de menus, les accélérateurs, SetWindowLong du style

Commits relus par le bot : `da0d791`, `0ac36c5`, `f513a6a`, `b8f8642`, `09e31eb`, `14fc4ac`, `c0df98a`, `544e6ea` et
`b9b46c6`. Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `docs/compat/m6-fenetres.md:1072` | La doc dit que WM_CANCELMODE oublie les touches du menu, alors que seul Alt est oublié. | Fondé | | Doc corrigée par `657f759`. |
| `kernel/win32k/src/defwnd.rs:723` | WM_CANCELMODE devrait aussi oublier F10. | Sans suite | ReactOS n'oublie qu'Alt (QF_FMENUSTATUS). | Laissé, consigné dans la passation. |
| `kernel/win32k/src/gdi/dib.rs:257` | Repartir des bouts arrondis d'un trait coupé change ses pixels et la phase de ses pointillés. | Fondé | Codex l'a vu aussi (P2). | Corrigé par `3d60a15` (`LineWalk::at`). |
| `kernel/win32k/src/gdi/object.rs:107` | GetObject d'une DIB section rend toujours une hauteur positive et BI_RGB. | Partiellement fondé | La hauteur positive est celle de ReactOS (`BITMAP_GetObject` rend `bmHeight`). En revanche, ReactOS rend BI_BITFIELDS pour une section dont les masques ne sont pas BGR, et Mino jamais. | Aucune. |
| `kernel/win32k/src/winpos.rs:749` | SetWindowPlacement rend TRUE même quand ShowWindow refuse. | Sans suite | `IntSetWindowPlacement` de ReactOS rend TRUE quel que soit le résultat de `co_WinPosShowWindow`. | Aucune. |
| `kernel/ntoskrnl/src/sys/accel.rs:36` | Bloquant. CreateAcceleratorTable alloue `count × 6` octets avant toute validation : avec 0xFFFFFFFF, le système s'arrête. | Fondé | | Corrigé par `14fc4ac` (65 536 entrées au plus, allocations faillibles), testé par la sonde de `notepad`. |
| `kernel/ntoskrnl/src/sys/accel.rs:38` | Les tampons ACCEL sont sondés sur 4 octets, alors qu'ACCEL est aligné sur 2. | Sans suite | ReactOS sonde aussi sur 4 (`ProbeForRead` et `ProbeForWrite` dans `accelerator.c`). | Aucune. |
| `kernel/ntoskrnl/src/sys/user.rs:341` | RegisterWindowMessage("#32770") rend l'atome entier 32770. | Sans suite | ReactOS passe par `IntAddAtom`, donc `RtlAddAtomToAtomTable`, qui lit aussi « #n » comme un atome entier. | Aucune. |
| `kernel/win32k/src/window.rs:456` | Les identifiants du chef d'une console viennent d'octets de plus qu'un autre processus peut écrire. | Sans suite | ReactOS lit les mêmes octets (`NtUserQueryWindow`). Il ne vérifie le processus qui écrit que pour GWLP_WNDPROC (`co_IntSetWindowLongPtr`). | Aucune. |
| `kernel/win32k/src/paint.rs:670` | Le nouvel ordre des sœurs ne vaut que pour le WM_PAINT tiré de la file, pas pour un redessin synchrone. | Fondé | | `544e6ea` revient à l'ordre de ReactOS dans les deux chemins. |
| `docs/compat/m6-fenetres.md:1105` | La sonde de `notepad` relit les titres toutes les 250 ms, et non chaque seconde. | Fondé | `POLL_MS` vaut 250 dans `tests/native/notepad1.c`. | Aucune, la phrase est toujours là. |
| `kernel/ntoskrnl/src/sys/object.rs:340` | NameInfoSize vaut 0 pour la racine, qui a pourtant le nom `\`. | Fondé | Mino donne la taille du nom de tout autre objet nommé et exclut la racine sans raison écrite ; ReactOS rend toujours 0. Ce que rend XP est à confirmer. | Aucune. |
| `kernel/win32k/src/window.rs:559` | `restyle` décide du passage de fille à non-fille d'après le style demandé, et non d'après celui que laisse WM_STYLECHANGING. | Fondé | | Corrigé par `b9b46c6`, avec un test. |
| `kernel/win32k/src/window.rs:567` | WM_STYLECHANGED est envoyé même si WM_STYLECHANGING a détruit la fenêtre. | Fondé | `send_message` ne vérifie pas que la fenêtre vit encore, alors que ReactOS envoie par un handle qui ne vaut plus rien. | Aucune. |

## PR 126 : le logon jusqu'à `userinit`

Commits relus par le bot : `7b96957` et `a4de67a`. Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/win32k/src/gdi/dib.rs:276` | Avec une plume de 2^31 − 1 pixels de large, un trait tient le verrou de la surface pendant des minutes. | Fondé | | Corrigé par `5d0ae2f` : l'épaisseur est bornée au plus grand côté de la surface. |
| `kernel/win32k/src/gdi/object.rs:74` | Sans tampon, GetObject d'une DIB section rend la taille d'un BITMAP, et non d'une DIBSECTION. | Sans suite | `BITMAP_GetObject` de ReactOS rend aussi `sizeof(BITMAP)` sans tampon. | Aucune. |
| `kernel/win32k/src/menutrack.rs:737` | TF_ENDMENU (0x10000) a la valeur de TPM_WORKAREA. | Inatteignable | `tpm::VALID` n'a pas ce bit : NtUserTrackPopupMenuEx refuse TPM_WORKAREA avant le suivi. ReactOS a la même valeur. | Aucune. |
| `kernel/cm/src/lib.rs:771` | Après NtUnloadKey, des clés encore ouvertes écrivent dans la ruche détachée et peuvent écraser la ruche rechargée. | Fondé | `unload_hive` ne refuse pas une ruche dont des clés sont ouvertes (le cas `STATUS_CANNOT_DELETE`). | Aucune. |
| `kernel/ntoskrnl/src/sys/accel.rs:47` | ACCEL est sondé sur 4 octets. | Sans suite | Redite de la PR 125. | Aucune. |
| `kernel/ntoskrnl/src/sys/gdi.rs:407` | Avec GCABCW_INDICES seul, GetCharABCWidths rend des entiers au lieu de flottants. | Sans suite | ReactOS ne rend des flottants que si `fl` vaut 0 (`if (!fl)` dans `freetype.c`). | Aucune. |
| `kernel/ntoskrnl/src/sys/gdi.rs:414` | Les ABCFLOAT perdent leurs fractions. | Sans suite | ReactOS arrondit aussi au pixel avant de convertir en flottant. | Aucune. |

Codex a vu les deux défauts d'ACCEL de cette PR, déjà signalés par le bot dans la PR 125 : rien de manqué.

## PR 132 : le seuil des apitests du M5

Commits relus par le bot : `f2bbb7a`, `77abbef` et `f6ec563`. Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `CLAUDE.md:50` | « S1, S2 et S3 réussis » contredit la feuille de route et l'ADR-002, qui laissent S3 à faire. | Partiellement fondé | Les documents se contredisent bien : l'index de `03-decisions.md` dit toujours « S1 réussi ; spikes S2–S3 ». Mais S3 (`user32` sur un win32k minimal) était fait depuis l'étape 6 du M5 : c'est l'index qu'il fallait corriger, pas `CLAUDE.md`. | Aucune, l'index n'a pas changé. |
| `docs/compat/m5-rostests.md:92` | Les totaux des tests écartés ne se recoupent pas avec les tableaux. | Fondé | 84 lancés et 23 écartés font 107, pas 108 ; 29 et 12 font 41, pas 40. | Aucune, les chiffres sont inchangés. |
| `docs/passation.md:12` | La même remarque sur S3. | Partiellement fondé | Redite de la remarque sur `CLAUDE.md`. | Aucune. |
| `docs/passation.md:12` | La même remarque sur S3, à la passe suivante (`77abbef`). | Partiellement fondé | Redite. | Aucune. |
| `docs/compat/m6-logon.md:74` | Le paragraphe du point d'arrêt dit encore qu'`explorer.exe` n'est pas sur le disque. | Fondé | | `bf3c82e` (PR 133) retire « C'est là que le logon s'arrête aujourd'hui », mais le paragraphe garde « qui n'est pas sur le disque ». |

## PR 133 : `explorer.exe` démarre, les fenêtres message seul

Commit relu par le bot : `f9b22da`. Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `docs/compat/m6-logon.md:54` | Le même paragraphe est toujours au présent. | Fondé | Redite de la remarque de la PR 132. | Aucune, il est inchangé sur `main`. |

Manqués possibles : selon Codex (P2), une fenêtre `HWND_MESSAGE` créée visible sans `WS_CHILD` peut prendre
l'activation et le focus du clavier. Ce n'est pas vérifié ici.

## PR 134 : les contrôles ScrollBar, les raccourcis clavier, la casse des noms 8.3

Commit relu par le bot : `11cfd7e`. Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `docs/compat/m6-logon.md:151` | « La station héritée » : `find_by_type` prend le premier handle de station de la table, quels que soient son héritage et ses droits. | Sans suite | ReactOS fait de même : `IntResolveDesktop` appelle `ObFindHandleForObject` sans objet, et le commente « Inherited window station ». | Aucune. |

Manqués possibles : selon Codex (P2), un DC pris dont la région visible est refaite garde dans son `DC_ATTR` l'ancienne
région, que lit le SelectClipRgn en lot de `gdi32`. Ce n'est pas vérifié ici.

## PR 149 : NtAccessCheck, l'effacement des fichiers, le banc des installeurs

Commit relu par le bot : `60ec7a8`. Évalué le 2026-11-19.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/io/src/file.rs:653` | `check_open` accepte FILE_DELETE_ON_CLOSE sur un volume NTFS, en lecture seule ; le fichier ne serait pas effacé, sans erreur. | Inatteignable | `create_file` (`kernel/ntoskrnl/src/sys/file.rs`) refuse FILE_DELETE_ON_CLOSE sans DELETE. Sur un volume en lecture seule, `File::granted_access` rend `STATUS_MEDIA_WRITE_PROTECTED` pour DELETE, qui est dans `MUTATION_ACCESS`. La fonction seule reste incohérente avec `Volume::set_delete_pending`. | Refus ajouté quand même (`delete_on_close_allowed`), avec un test : `f8e1b71`. |
| `kernel/ntoskrnl/src/sys/file.rs:116` | Le commentaire dit que FILE_DELETE_ON_CLOSE ajoute DELETE, mais le code refuse l'ouverture sans DELETE. Selon le bot, le fichier temporaire de CreateFile échouerait. Il propose d'ajouter DELETE ou de corriger le commentaire. | Partiellement fondé | Le commentaire est faux et le code juste : la documentation publique de ZwCreateFile exige DELETE avec FILE_DELETE_ON_CLOSE. Ajouter DELETE s'écarterait de NT. L'échec annoncé de CreateFile est faux : le CreateFileW de `kernel32` ajoute DELETE pour FILE_FLAG_DELETE_ON_CLOSE (`client/file/create.c` de ReactOS). | Commentaire réécrit : `f8e1b71`. |
| `tests/native/appbench.c:266` | Si la boîte d'un installeur est figée, SendMessageW bloque le banc jusqu'au délai de QEMU, sans ses diagnostics. | Fondé | Un message envoyé à la fenêtre d'un autre thread attend que ce thread le traite. Une boîte figée est justement le cas que cette boucle cherche. | SendMessageTimeoutW (SMTO_ABORTIFHUNG, 2 s), puis IDOK : `96ed824`. |

Manqués :

- **Une ouverture et le dernier close du même fichier se croisent** (`kernel/ntoskrnl/src/sys/file.rs:166`). Un
  thread peut être préempté entre `check_open` et `handle_opened`. Pendant ce temps, `Volume::cleanup` efface le
  fichier en attente d'effacement, et l'ouverture rend un handle sur une entrée FAT effacée. Trouvé par la revue de
  Codex (P1). Corrigé par `eee962c` (`ke::KGuardedMutex`) et `f8e1b71` : sous un verrou de FCB qui peut attendre,
  l'ouverture vérifie que l'entrée nomme toujours le fichier, et se compte (`Volume::begin_open`) ; le dernier close
  efface sous le même verrou. Test hôte `an_open_looked_up_before_the_deletion_finds_the_file_gone`.
- **`Volume::cleanup` efface le fichier sous un `KSpinLock`.** Il écrit sur le disque et alloue en tenant `opened`,
  donc à DISPATCH_LEVEL, contre 06 §4. Trouvé en vérifiant les remarques. Corrigé par `f8e1b71` : l'effacement se
  fait sous le verrou de FCB, et le `KSpinLock` ne garde plus que les comptes.

## PR 152 : les métriques des polices

Commit relu par les bots : `6f892d2`. Évalué le 2026-11-20. Vortex a posté cinq remarques dont trois fois la même
(le débordement de `FirstChar + Count`, en remarque principale puis deux fois parmi celles « hors des lignes
changées ») ; Codex en a posté deux.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/ntoskrnl/src/sys/gdi.rs:261` | `first + count` fait le tour en u32 (profil `release`, sans contrôles de débordement) : la plage est vide, la largeur rend TRUE sans rien écrire ; `as u16` tranque un FirstChar au-dessus de 0xFFFF. | Fondé | `(first..first + count)` avec FirstChar = 0xFFFFFFFF et Count = 2 rend une plage vide, `copy_to_user` de zéro octet réussit et le service rend TRUE ; 0x10041 devient 0x0041. | Plage validée par `checked_add` et bornée à un WCHAR (`first <= 0xFFFF`, fin `<= 0x1_0000`), sinon FALSE et `ERROR_INVALID_PARAMETER`. |
| `kernel/win32k/src/gdi/fontobj.rs:435` | `italic_angle` va brut dans l'OTM : c'est le 16.16 de `post`, le champ veut des degrés entiers — 65536 fois trop grand pour une italique. | Fondé | `OutlineNumbers::italic_angle` porte le Fixed de `post` (doc du champ), et `OutlineTextMetricW32::italic_angle` est `int` en degrés. Tahoma Regular (angle nul) ne le montrait pas. | Converti en degrés, arrondi (`(v + 0x8000) >> 16`) ; test `an_italic_face_tells_its_angle_in_degrees` (Courier New italique). |
| `kernel/ntoskrnl/src/sys/gdi.rs:249` | `flOptions` est jeté sans regard : un `GCW_INDICES` rendrait des largeurs de caractères pour des index de glyphes, en réussissant. | Fondé | Les valeurs seraient des index, traités comme des caractères : une réponse fausse vaut pire qu'un échec. | Drapeaux inconnus, `GCW_INDICES` et les flottants sans `GCW_NOFLOAT` refusés (FALSE, `ERROR_INVALID_PARAMETER` ; `ntgdityp.h` : WIN32 0x1, NOFLOAT 0x2, INDICES 0x8). |
| `abi/src/gdi.rs:960` (Codex) | Le remplissage vient après la PANOSE : le header de ReactOS pose `otmFiller` à 64 et la PANOSE de dix octets à 65, chaque composante lue est donc décalée d'un octet. | Fondé | `sdk/include/psdk/wingdi.h` de 0.4.16 : `BYTE otmFiller; PANOSE otmPanoseNumber;` — la structure avait `panose` à 64. | `filler: u8` puis `panose` (65), l'octet d'alignement explicite ; testé (`filler` 0, composante de famille 2 pour Tahoma). |
| `abi/src/gdi.rs:987` (Codex) | Le souligné rend sa position et sa taille échangées : le header pose `otmsUnderscoreSize` avant `otmsUnderscorePosition`. | Fondé | Le header de 0.4.16 a bien la taille (192) puis la position (196) — l'ordre inverse du barré. | Champs remis dans l'ordre, offset testé à 192. |

Manqués :

- **La structure comptait `otmpVersion` et `otmpNotice`.** Le header de ReactOS 0.4.16 s'arrête au quatrième nom
  (`otmpFullName`) : 216 octets, pas les 224 de l'ABI de Windows (six noms). Les champs de plus n'étaient jamais lus
  — la `gdi32` épinglée n'en a pas — mais la taille était fausse. Trouvé en vérifiant les deux remarques de Codex
  contre `wingdi.h`. Corrigé avec elles : quatre noms, 216 octets, `size_of` testé.

## PR 155 : la croissance de pile et le filtre de débogage

Commit relu par le bot : `d3aa0c8` (puis `6db467c`, hors des lignes changées). Évalué le 2026-11-20. Trois remarques.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/mm/src/address_space.rs:700` | L'accès mémoire sur une page committée de la pile devient une réussite silencieuse : `allocate` ne rend pas `STATUS_ALREADY_COMMITTED` sur une page déjà committée — `VadNode::commit` rend un changement dès que la protection diffère, et `map_commit` réécrit la page à READWRITE. Le chemin AV du `page_fault_hook` passe donc par là : une écriture dans une page PAGE_NOACCESS de la réserve de la pile réussit, et la limite suit. | Fondé | `virtual_alloc::allocate` → `VadNode::commit(start, end, protect)` : une page committée rend `PageChange { old_state: Committed, old_protect }` et `map_commit` appelle `m.protect_page(va, protect)` — jamais `ALREADY_COMMITTED`. L'écriture d'une page NOACCESS de la réserve réusissait en silence. | `MiCheckForUserStackOverflow` fidèle : l'extension ne se fait que par une faute de garde ; une violation d'accès dans la réserve délivre `STATUS_STACK_OVERFLOW` (`AddressSpace::stack_overflow`, la réserve lue du TEB), sans commiter ni reprendre. L'allocation-rewrite a disparu. Test de régression dans le smoke : `noaccess.exe` commite une page PAGE_NOACCESS sous sa limite et écrit dedans — le processus doit finir sur `STATUS_STACK_OVERFLOW` (l'écriture réusissait et le fil tournait à l'infini avant). |
| `docs/compat/applications.md:397` | « la page du tas que Windows tient projetée » : le nom de marque, que CLAUDE.md écarte au profit de « compatible XP ». | Fondé | La règle de rédaction du dépôt. | « la page du tas que la cible tient projetée ». |
| `kernel/ntoskrnl/src/main.rs:4580` | Le résultat du filtre pour le niveau 2 (`store_eax(status(14))`) est écrasé par `NtCreateDirectoryObject(...).store_eax(status(14))` du même test : `statuses[14]` porte le statut du répertoire, et l'assertion `(1, 0)` passe quel que soit le filtre. | Fondé | Les deux appels du même test écrivent le slot 14, et l'assertion tourne après tout le programme. | Le filtre va au slot 28 (le vecteur des statuts élargi à 29), l'assertion `(statuses[7], statuses[28]) == (1, 0)` ne passe plus que si le niveau 2 est filtré. |

## PR 156 : les verrous de plages d'octets (NtLockFile)

Commits relus par les bots : `d3ea9a6`, puis `4ca2cae` et `a68386b` (Vortex seul). Évalué le 2026-11-21. Sur
`d3ea9a6`, Vortex a posté deux fois la même remarque (en ligne, puis parmi celles « hors des lignes changées ») ;
Codex l'a postée aussi. Sur les deux commits suivants, Vortex a ajouté une remarque, en ligne puis en double, et
a reposté deux fois la première, déjà corrigée.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/ntoskrnl/src/sys/file.rs:475` | Le neuvième argument de NtReadFile et NtWriteFile est un `PULONG Key` optionnel : son adresse sert de clé, et un processus voit refuser ses propres E/S sur une plage qu'il a verrouillée avec cette clé. | Fondé | `transfer` passait `key`, l'adresse, à `File::lock_owner`. ReactOS 0.4.16 (`io/iomgr/iofunc.c`, NtReadFile et NtWriteFile : `IN PULONG Key OPTIONAL`, `if (Key) CapturedKey = ProbeForReadUlong(Key)`). Le cas « read with another key » de `lock1.c` ne passait que parce que l'adresse diffère de 0. `kernel32` passe NULL : aucune application touchée. | `4ca2cae` : la clé lue par `UserPtr::<u32>` (0 sans pointeur). `LOCK1.EXE` verrouille avec la clé 7 puis lit et écrit par un pointeur vers 7 (accepté ; refusé sans le correctif, vérifié), sans clé et par un pointeur vers 8 (refusés). |
| idem (hors des lignes changées) | La même, en double. | Fondé | Voir la ligne précédente. | `4ca2cae`. |
| idem (Codex, P2) | La même. | Fondé | Voir la première ligne. | `4ca2cae`. |
| `kernel/ntoskrnl/src/sys/file.rs:483` (sur `4ca2cae`) | Une E/S refusée par un verrou rend `STATUS_FILE_LOCK_CONFLICT` sans écrire le bloc d'état : y écrire l'échec et 0 octet. | Sans suite | ReactOS 0.4.16 : `vfatfs` (`rw.c`, VfatRead et VfatWrite) rend `STATUS_FILE_LOCK_CONFLICT` de façon synchrone, et `IopCompleteRequest` (`io/iomgr/irp.c`) ne copie `IoStatus` dans l'IOSB de l'appelant que si le statut n'est pas une erreur, ou pour une E/S en attente d'un fichier asynchrone : le bloc reste tel quel. | Rien. |
| idem (hors des lignes changées, sur `a68386b`) | La même. | Sans suite | Voir la ligne précédente. | Rien. |
| `kernel/ntoskrnl/src/sys/file.rs:481` (hors des lignes changées, sur `4ca2cae`) | La clé de NtReadFile et NtWriteFile prise comme une valeur, reposté. | Faux | Corrigé à ce commit : `transfer` lit la clé par `UserPtr::<u32>` (0 sans pointeur) avant `lock_owner`. Vortex a lui-même répondu « Fixed in 4ca2cae » à sa remarque d'origine. | Rien. |
| idem (sur `a68386b`) | La même, encore. | Faux | Voir la ligne précédente. | Rien. |

Aucun défaut manqué vérifié. Les dettes que la PR déclare (un verrou refusé sans FailImmediately n'attend pas ; le
mode de partage de CreateFile pas vérifié) ne sont pas des défauts du diff, et le bot ne les a pas relevées.

## PR 157 : Authenticode et le banc en session

Commit relu par les bots : `4cb8cad`. Évalué le 2026-11-21. Une remarque, postée par Vortex et par Codex.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `tests/native/auth1.c:100` | Le résultat de WinVerifyTrust est imprimé, jamais vérifié, et le scénario ne l'attend pas : une régression de la vérification de confiance laisse `authenticode` vert, alors que la PR dit WinVerifyTrust à 0 vérifié. | Fondé | La sonde allait jusqu'à « PASS » quel que soit `trust` ; les étapes suivantes ne lisent que le certificat du signataire. Sans les DLL enregistrées, WinVerifyTrust rendait `0x80070057` et le scénario aurait passé. | `1026f1c` : la sonde s'arrête si `trust` n'est pas 0, et le scénario attend `[auth] WinVerifyTrust: 0`. |
| idem (Codex, P2) | La même. | Fondé | Voir la ligne précédente. | `1026f1c`. |

Aucun défaut manqué vérifié.

## PR 161 : les procédures de l'autre jeu de caractères (CALLPROCDATA)

Commits relus par Vortex : `bef39ad`, puis `4e417c0`. Évalué le 2026-11-22. Vortex a posté une remarque, puis l'a
reprise à la passe suivante parmi celles « hors des lignes changées » ; la revue de Codex a échoué (limite d'usage),
sans remarque.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/win32k/src/callproc.rs:99` | La recherche du cache de `get` ignore le processus : pour une classe du système partagée comme Edit, un second processus reçoit de GetClassInfoA le handle du premier, que ValidateCallProc de `user32` refuse et qui meurt avec le premier. | Partiellement fondé | Le défaut existe, pas par ce chemin. Comme dans ReactOS, chaque processus a ses classes (`ClassLists` dans son `PROCESSINFO`, Edit comprise : le `user32` de chaque processus l'enregistre), et la classe d'un contrôle se voit par la procédure du client du jeu demandé (`Class::seen_procedure`), sans procédure d'appel. Le chemin réel est GetClassLongA(GCLP_WNDPROC) de la fenêtre d'un autre processus : `user32` (IntGetClsWndProc) appelle NtUserGetCPD, qui ne regarde pas le processus (ni dans ReactOS, ni dans `window::call_procedure`) ; le handle de l'autre processus allait à la classe, qui le rendait ensuite au sien. ReactOS a le même défaut : UserSearchForCallProc ne compare pas `ppi`. | `48460d8` : la recherche compare aussi le processus (`CallProc::owner`) et le tas du bureau. Étape 7 de `ansictl1.c` : un second processus (`ANSICTL1.EXE child`) reçoit le sien de GetClassLongA de la fenêtre du premier ; sans la comparaison, il recevait celui du premier, que CallWindowProcA refusait (vérifié par mutation). |
| idem (sur `4e417c0`, hors des lignes changées) | La même, reprise. | Partiellement fondé | Redite. | `48460d8`. |

Manqués :

- **Un thread d'un autre bureau recevait un handle qu'il ne lit pas.** La procédure d'appel est dans le tas du bureau
  du thread qui l'a demandée ; la recherche ne comparait pas le tas, et un thread du même processus sur un autre
  bureau recevait un handle hors de la plage de son tas (`user32` : DesktopPtrToUser, puis
  ONEPARAM_ROUTINE_GETDESKTOPMAPPING, que Mino n'a pas ; CallWindowProcA rend 0). Vu en vérifiant la remarque ;
  Vortex l'évoque sur la PR 164 (« and desktop heap »). Corrigé par `48460d8` ; étape 7 de `ansictl1.c` (un thread
  sur `MinoOther`), vérifié par mutation.
- **SetWindowLong(GWLP_WNDPROC) rendait l'ancienne procédure dans le jeu de la procédure donnée.** Vu par Vortex et
  Codex sur la PR 164, qui contient ce code (voir sa section). Corrigé par `48460d8`.

## PR 162 : les entrées d'un nom long dans une suite d'emplacements libres

Commits relus par Vortex : `22c673a` (rien à corriger), puis `4177f2e`. Évalué le 2026-11-22. Une remarque ; la
revue de Codex a échoué (limite d'usage).

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `docs/compat/applications.md:524` | « Le répertoire ne se trouvait ni par son nom long ni par son alias » : `FatVolume::find_entry` compare l'entrée 8.3 sans regarder les entrées de nom long qui la précèdent, et `NOGRAP~1` se trouvait encore ; seul le nom long, celui que PeaZip demande, échouait. | Fondé | `find_entry` : `let short = target.is_some_and(\|target\| ent[0..11] == target)`, où `target` vient de `short_name_11(name)`, indépendamment du nom long en cours. | `afb33aa` : la phrase dit que le nom long ne se trouvait plus, l'alias 8.3 si. |

Aucun défaut manqué vérifié.

## PR 163 : NtUserEnumDisplayMonitors

Commit relu par les bots : `9ec7ceb`, avec les PR 161 et 162 qu'elle contient. Évalué le 2026-11-22. Vortex a repris
la remarque du cache de la PR 161 ; Codex en a posté une sur une classe enregistrée avec une procédure d'appel.

| Où | Remarque | Verdict | Pourquoi | Suite |
|---|---|---|---|---|
| `kernel/win32k/src/callproc.rs:66` | Le cache rend le handle d'un autre processus, si les classes globales sont partagées entre processus. | Partiellement fondé | Redite de la PR 161 : elles ne le sont pas (`ClassLists` par processus) ; le chemin réel est GetClassLong de la fenêtre d'un autre processus. | `48460d8` (PR 161). |
| `kernel/win32k/src/window.rs:2094` (Codex, P2) | Une classe enregistrée par RegisterClassA avec la procédure d'appel que GetClassInfoA a rendue pour une classe Unicode fait des fenêtres ANSI (son `CSF_ANSIPROC`) qui exécutent la procédure Unicode : le texte y arrive sans conversion. | Sans suite | ReactOS fait de même : NtUserRegisterClassExWOW garde la procédure d'appel comme procédure de la classe (« Never seen this yet »), IntCreateWindow prend son `pfnClientPrevious` et le jeu de la classe (`CSF_ANSIPROC`) ; pour SetClassLong, IntSetClassWndProc prend aussi le jeu de l'appelant. Seul IntSetWindowProc prend celui de la procédure d'appel. Ce que fait XP reste à confirmer. | Aucune. |

Aucun défaut manqué vérifié.
