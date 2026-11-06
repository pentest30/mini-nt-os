# M5 — la console : un programme console lancé, et sa console

Le chemin des critères de sortie du M5 ([05](../05-feuille-de-route.md#m5--mode-console-puis-spike-s2)) : un
programme console (8 threads synchronisés par des sections critiques), puis `cmd.exe` interactif. Le `consrv`
épinglé n'a que son frontal graphique (`winsrv.dll`, `frontends/gui`) : la console est une fenêtre de USER, que
`consrv` crée dans `csrss` et peint avec une police à chasse fixe.

## Le banc d'essai : `CONSOLE1.EXE` lance `THREADS1.EXE`

Le scénario `console` met `CONSOLE1.EXE` (`tests/native/console1.c`, sous-système WINDOWS) à la place de
`winlogon.exe` : comme `winlogon`, il s'inscrit comme processus de logon et prend `WinSta0\Default`, puis lance par
CreateProcessW `THREADS1.EXE` (`tests/native/threads1.c`, sous-système CONSOLE, que `xtask` construit maintenant :
point d'entrée `ConsoleStartup`), attend sa fin et lit son code de sortie. Un programme console ne peut pas prendre
lui-même le bureau : `kernel32` le connecte à `consrv` avant son point d'entrée, et la console a besoin d'un bureau.

`THREADS1.EXE` est le programme du critère : 8 threads ajoutent 2000 fois 1 à un compteur sous une section critique,
en laissant les autres tourner tous les 64 tours pendant qu'ils la tiennent (Sleep(0)), pour qu'ils l'attendent ;
puis il écrit sur sa console (WriteConsoleW). Il ne va pas encore jusque-là : la console ne lui est jamais donnée.

## Étape 1 : CreateProcessW, l'emprunt d'identité, le bureau de la console

La sonde, dans l'ordre :

1. **CreateProcessW échoue** (`ERROR_PARTIAL_COPY`) : `kernel32` écrit les paramètres du nouveau processus, puis
   leur adresse dans son PEB, en `0x10` : il a pris le PEB à 0. Le noyau de ReactOS rend l'adresse du PEB d'un
   processus créé dans le TEB de son créateur, en `NtTib.ArbitraryUserPointer` (PspCreateProcess), et le
   CreateProcessInternalW de `kernel32` l'y lit, sans la demander (ProcessBasicInformation). C'est un écart de
   ReactOS sur XP, mais il fait partie de sa frontière noyau : NtCreateProcess(Ex) le fait maintenant, comme lui,
   pour tout créateur qui a un TEB.
2. **`csrss` ne peut pas emprunter l'identité du client** (« CSRSS: Can't impersonate client thread ») :
   NtImpersonateThread manquait. L'emprunt d'identité est fait :
   - `ps` : chaque thread peut emprunter un jeton (PS_IMPERSONATION_INFORMATION : jeton, niveau, copie à
     l'ouverture, effectif seul ; `EThread::impersonate`, `EThread::impersonation`) ;
   - `se` : `Token::duplicate` (SepDuplicateToken : un type et un niveau), `se::client::client_security`
     (SeCreateClientSecurity et SeImpersonateClientEx pour un client local : le jeton effectif du client, celui
     qu'il emprunte ou le jeton primaire de son processus ; une copie au niveau demandé en suivi statique, le jeton
     lui-même en suivi dynamique ; les niveaux vérifiés) ;
   - services : NtImpersonateThread (`THREAD_DIRECT_IMPERSONATION` sur le serveur, `THREAD_IMPERSONATE` sur le
     client), NtSetInformationThread(ThreadImpersonationToken) (un jeton d'emprunt d'identité, ou NULL : le retour à
     soi de CsrRevertToSelf), NtOpenThreadToken(Ex) qui rend le jeton emprunté (une copie, que le thread emprunte
     ensuite, quand l'emprunt vient d'un serveur : CopyOnOpen), `STATUS_NO_TOKEN` sans emprunt.
3. **Le frontal graphique ne se charge pas** : NtUserConsoleControl et NtUserResolveDesktop manquaient.
   - NtUserConsoleControl (`win32k::console`, `sys::console`) : l'atome de la classe des fenêtres console
     (GuiConsoleWndClassAtom), le thread d'entrée des consoles de chaque bureau
     (ConsoleCtrlDesktopConsoleThread : `Desktop::exchange_console_thread`, lu seulement avec
     INVALID_HANDLE_VALUE). Seul `csrss` peut l'appeler.
   - NtUserResolveDesktop (IntResolveDesktop) : la station et le bureau du processus console, ouverts dans `csrss` ;
     ceux d'un processus GUI qui les a déjà, sinon ceux du chemin `Station\Bureau` de ses paramètres (que
     CreateProcessW tient de `lpDesktop`), la station interactive n'allant qu'à un processus de la session
     d'ouverture de System ou de celle de son utilisateur.
4. **La fenêtre console n'est pas créée** : `consrv` crée son thread d'entrée (un thread de `csrss` sur le bureau),
   qui crée la fenêtre ; à WM_NCCREATE, InitFonts ne trouve ni la police « VGA », celle de la page de code 437, ni
   « Terminal », son repli (NtGdiGetFontFamilyInfo manque, et toute police donne Tahoma : `win32k::gdi::fontobj`).
   La sonde s'arrête là ; `kernel32` attend la console.

En passant, tolérés : `RtlOpenCurrentUser` échoue (pas de `\REGISTRY\USER\S-1-5-18`), `consrv` prend ses réglages
par défaut ; une assertion de `consrv` sur ses icônes (`GuiData->hIcon && GuiData->hIconSm` : USER ne charge pas
encore d'icônes, NtUserFindExistingCursorIcon manque), que la sonde laisse passer (`DbgPrompt` reçoit « i ») ;
NtUserGetObjectInformation, NtUserGetSystemMenu, NtGdiOpenDCW, NtUserNotifyProcessCreate manquent (0 rendu).

Pas encore : SeTokenCanImpersonate (un thread peut emprunter tout jeton : ils viennent tous de celui de System) ;
le DACL d'une copie à l'ouverture ; OpenAsSelf (sans contrôle d'accès, il ne change rien) ; `IsImpersonating` dans
le TEB ; pour NtUserResolveDesktop, la station par défaut d'un chemin qui n'en nomme pas (une station héritée, ou la
station des services `Service-0x0-3e7$` que ReactOS crée pour un processus de System : `STATUS_NOT_IMPLEMENTED`,
journalisé) ; ConsoleMakePalettePublic (pas de palettes) et ConsoleAcquireDisplayOwnership.

Tests : hôte (`se` : une copie d'emprunt d'identité a son type et son niveau ; SeCreateClientSecurity en suivi
statique et dynamique, le niveau d'un client qui emprunte, un niveau inconnu) ; le scénario `smoke` (un thread
emprunte sa propre identité, NtOpenThreadToken rend une copie d'emprunt d'identité à ce niveau, le retour à soi,
puis `STATUS_NO_TOKEN` ; un jeton primaire, un handle sans `TOKEN_IMPERSONATE` et un niveau inconnu refusés) ; le
scénario `console` sur les deux CPU. 4 mutations tuées : sans PEB rendu au créateur, sans emprunt (scénario
`console`), un retour à soi ignoré, un jeton primaire accepté (`smoke`). Sans test : le thread d'entrée d'un bureau
retrouvé par une seconde console (il n'y en a qu'une).

La suite : les polices de la console (étape 2).

## Étape 2 : les polices de la console

`consrv` crée la fenêtre de sa console avec la police de sa page de code : « VGA » pour la 437, « Terminal » en
repli (`concfg/font.c`). Il la vérifie d'abord par EnumFontFamiliesExW (IsValidConsoleFont2) : une police TrueType
doit être à pas fixe et FF_MODERN, sauf si elle est dans la liste `Console\TrueTypeFont` de la ruche SOFTWARE (Lucida
Console seulement). Tout donnait Tahoma, et NtGdiGetFontFamilyInfo manquait.

- **La ruche SOFTWARE** de ReactOS épinglé est sur le disque de démarrage et montée en `\REGISTRY\MACHINE\SOFTWARE`
  (`userland::mount_software_hive`, réécrite par NtFlushKey comme SYSTEM) : `FontSubstitutes` (34 substituts : « MS
  Shell Dlg » donne Tahoma, « Terminal » Lucida Console, « Courier » Courier New…), `Console\TrueTypeFont`.
- **Les polices du disque** : `win32k::font` tient une table de polices installées (plus l'énumération fermée de
  Tahoma, Tahoma gras et Marlett) ; le noyau installe chaque `.ttf` de `\SystemRoot\Fonts` (IntLoadSystemFonts ; Io sait
  lister un répertoire : `Volume::list`, `File::list`). Pour chacune : sa famille, son style et son nom complet (table
  `name`, `glyph::Names`), sa graisse, son italique, son pas et sa famille, son jeu de caractères (le premier de ses
  pages de code, comme ReactOS). `xtask` met sur le disque, en plus des polices du cadre, VGA (`UniVGA16.ttf`, famille
  « VGA » : sa table `post` la dit proportionnelle, son PANOSE à chasse fixe, ce qui suffit à FillTM), Lucida Console
  et Courier New.
- **La correspondance d'un LOGFONT** (TextIntRealizeFont) : son nom à travers les substituts (SubstituteFontRecurse,
  10 fois au plus), puis la police de cette famille la plus proche de sa graisse et de son italique ; sans elle, une
  police à pas fixe (Courier New d'abord) si le LOGFONT en demande une, sinon Tahoma. ReactOS pèse chaque écart
  (GetFontPenalty) ; ici, le nom décide.
- **L'énumération** (NtGdiGetFontFamilyInfo, `fontobj::family_info`, FONTFAMILYINFO dans `abi::gdi`) : les polices
  de ce nom (famille ou nom complet) et de ce jeu de caractères, puis celles des substituts de ce nom, sous le nom du
  substitut ; le LOGFONT et le NEWTEXTMETRIC de la hauteur par défaut, `lfPitchAndFamily` comme FontFamilyFillInfo
  (FIXED_PITCH pour VGA), TRUETYPE_FONTTYPE, la FONTSIGNATURE et l'écriture de la dernière page de code.
  `gdi32` rappelle le service quand son tampon est trop petit : le compte écrit est celui de toutes les polices.

**La sonde va au bout.** `consrv` crée la console ; `THREADS1.EXE` démarre, ses 8 threads comptent 16000 sans jamais
être deux dans la section critique, WriteConsoleW écrit ses 17 caractères, et il se termine avec 0x600D, que
`CONSOLE1.EXE` lit.

Mais les threads n'attendent jamais la section critique (« contended: no ») : Sleep(0) ne cède pas le processeur.
`ke::dispatcher::ke_delay_execution_thread` le dit (un intervalle nul revient aussitôt) ; XP donne le reste du quantum
à un thread prêt de même priorité. Le critère du M5 (8 threads synchronisés) attend ce correctif de Ke, pour que le
test exerce vraiment l'attente (la création de l'événement de la section critique, l'attente, le réveil).

En passant, toujours tolérés : l'assertion des icônes de `consrv` ; NtUserSetWindowLong, NtUserSetTimer,
NtUserShowWindowAsync (la fenêtre console n'est pas montrée), NtUserDestroyWindow, NtGdiCreateCompatibleDC,
NtGdiExtGetObjectW, NtGdiCreateBitmap, NtGdiCreatePatternBrushInternal, NtAddAtom manquent (0 rendu) ; `comctl32`
ne trouve pas son manifeste (contextes d'activation) ; NtQueryInformationThread(ThreadAmILastThread) et
NtSetInformationThread(ThreadQuerySetWin32StartAddress) manquent.

Ce qui manque : les polices bitmap (`.fon` : « Terminal » n'existe que par son substitut), les collections, les
polices privées (AddFontResource), le jeu de caractères d'un substitut (`Nom,jeu`, ignoré), les pénalités de
GetFontPenalty, le gras et l'italique synthétiques.

Tests : hôte (`glyph` : noms, italique, pages de code des polices épinglées, VGA à pas fixe et FF_MODERN ; `io` : un
répertoire liste ses noms ; `win32k` : une police par famille, graisse et italique, réinstallée à son rang, son pas et
son jeu de caractères, les substituts suivis et arrêtés sur une boucle ; la correspondance d'un LOGFONT ; l'énumération
par nom et par substitut) ; 10 mutations, toutes tuées (8 sur l'hôte ; une énumération vide et sans ruche SOFTWARE,
dans le scénario) ; le scénario `console` sur les deux CPU, qui va au bout.

La suite : Sleep(0) qui cède le processeur (étape 3).

## Étape 3 : Sleep(0) cède le processeur, le critère des 8 threads

Sleep(0) passe par NtDelayExecution avec un intervalle nul. Ke revenait aussitôt
(`ke::dispatcher::ke_delay_execution_thread` : « un intervalle nul ou déjà échu retourne aussitôt, sans céder le
processeur »), alors que XP donne le reste du quantum à un thread prêt de même priorité, et revient aussitôt s'il n'y
en a pas (le comportement que documente Sleep). Les 8 threads de `THREADS1.EXE`, qui appellent Sleep(0) en tenant la
section critique, ne laissaient donc jamais un autre thread la demander.

- `ke::sched::Scheduler::yield_to_equal` : s'il y a un thread prêt de la priorité du thread courant, celui-ci passe en
  queue de sa file avec un quantum neuf, et le premier de la file s'exécute ; sinon rien ne change. Un thread de
  priorité plus basse n'a pas le processeur.
- `ke::dispatcher::Platform::yield_execution` (le noyau : la commutation de `ke::sched` ; les tests hôte : le
  simulateur) ; KeDelayExecutionThread d'un intervalle nul l'appelle, après l'attente sans objet qui livre d'abord un
  APC utilisateur à une attente alertable (STATUS_USER_APC, sans céder). Un intervalle déjà échu revient toujours
  aussitôt.

La sonde : « contended: yes ». Les threads attendent la section critique (son événement est créé, attendu, signalé),
le compteur reste juste (16000, jamais deux threads dedans), et `THREADS1.EXE` se termine avec 0x600D : **le critère
« 8 threads synchronisés par des sections critiques » du M5 est coché** (scénario `console`).

Pas encore : NtYieldExecution (SwitchToThread), qui cède aussi à un thread de priorité plus basse ; la décroissance
de priorité d'un thread qui cède (le sien garde sa priorité et reçoit un quantum neuf).

Tests : hôte (`ke::sched` : céder seulement à un thread prêt de même priorité, dans l'ordre de la file, avec un quantum
neuf ; le dispatcher : un intervalle nul cède, une échéance passée non, un APC utilisateur d'abord) ; 2 mutations
(ne pas céder ; ne céder à personne), tuées sur l'hôte et dans le scénario `console`, qui exige « contended: yes ».

La suite : la fenêtre console montrée (NtUserShowWindowAsync) et son texte peint, les icônes de `consrv`, puis
l'entrée au clavier pour `cmd.exe` (le critère de `cmd.exe` interactif).

## Étape 4 : la fenêtre console montrée

La sonde allait au bout, mais la fenêtre de la console ne se montrait jamais. `consrv` range ses données dans sa
fenêtre (SetWindowLongPtr : GWLP_USERDATA pour sa procédure ; le PID et le TID du chef de la console dans les octets de
plus, `GWLP_CONSOLE_LEADER_PID`, `GWLP_CONSOLE_LEADER_TID`), puis son thread d'entrée la montre (ShowWindowAsync) et lui
poste des messages (PostMessage) : NtUserSetWindowLong, NtUserShowWindowAsync et NtUserPostMessage à une fenêtre
manquaient. Comme ReactOS (`window.c`, `winpos.c`, `message.c`, `main.c`, comme spécification) :

- `win32k::window::set_long` (co_IntSetWindowLongPtr) : un index positif est une place dans les octets de plus de la
  fenêtre (`cbWndExtra`, après le `WND`, où `user32` les lit lui-même ; `ERROR_INVALID_INDEX` au-delà) ; GWLP_USERDATA
  (`dwUserData` du `WND`), GWLP_ID, GWLP_HINSTANCE. GWL_STYLE, GWL_EXSTYLE, GWLP_WNDPROC et GWLP_HWNDPARENT : pas encore
  (`ERROR_CALL_NOT_IMPLEMENTED`, journalisé une fois ; `consrv` change GWL_EXSTYLE en passant). La fenêtre du bureau :
  `ERROR_ACCESS_DENIED` (ReactOS met à tort le statut NT comme erreur).
- NtUserShowWindowAsync : pour une fenêtre du thread courant, WM_ASYNC_SHOWWINDOW est traité aussitôt
  (co_WinPosShowWindow : rend si elle était visible) ; pour celle d'un autre thread, pas encore (les messages envoyés
  entre threads : `ERROR_CALL_NOT_IMPLEMENTED`, journalisé).
- NtUserPostMessage à une fenêtre (UserPostMessage) : le message va à la file du thread qui l'a créée ; la fenêtre du
  bureau n'a pas de thread (pas encore de thread du bureau) : il est perdu, journalisé une fois.
- InitThreadCallback (`win32k::startup`) : un thread client qui devient un thread GUI va sur le bureau de démarrage de
  son processus ; un processus qui n'en a pas encore le prend de ses paramètres (`DesktopInfo`, ce que CreateProcess
  tient de `lpDesktop` ; `STARTF_INHERITDESKTOP`) par IntResolveDesktop, une fois la station interactive créée, et
  cette station devient la sienne. Sans cela, le premier appel à `user32` d'un programme console (IsWindowVisible)
  trouvait `pDeskInfo` nul : assertion `pdi != NULL`, puis faute en 0. IntResolveDesktop quitte `sys::console` pour
  `win32k::startup`, que la conversion appelle aussi ; un chemin sans station (pas encore) laisse le thread sans
  bureau, journalisé (ReactOS fait échouer la conversion).

Le banc : `CONSOLE1.EXE` lance ensuite `CONSHOW1.EXE` (`tests/native/conshow1.c`, sous-système CONSOLE), qu'il attend
sans fin : il écrit « Mino console », attend sa fenêtre visible (GetConsoleWindow, IsWindowVisible), dit son
rectangle (23, 23 à 691, 455 ; zone cliente de 656 × 400 : 80 colonnes de 8 pixels et la barre de défilement, 25
lignes de 16) et lit dans ses octets de plus le chef de sa console (son processus et son thread), puis reste : la
capture montre sa fenêtre (bord, titre « C:\CONSHOW1.EXE » en gris, bouton de fermeture), sous celle de
`THREADS1.EXE`, qui reste aussi (NtUserDestroyWindow manque). Dans `gui`, un second thread va, à son premier appel à
`user32`, sur le bureau de démarrage du processus, et poste à une fenêtre du premier, dont la file reçoit le message
pour la fenêtre.

En passant, tolérés : l'assertion des icônes de `consrv` ; NtUserSetScrollInfo, NtUserShowScrollBar,
NtUserWindowFromPoint, NtUserCallOneParam(0x26), NtGdiCreateSolidBrush, NtUserSetTimer (le curseur ne clignote pas),
NtUserDestroyWindow manquent (0 rendu) ; DefWindowProc ignore WM_SETCURSOR.

Ce qui manque : la zone cliente n'est pas peinte. `consrv` compose le texte dans un DC en mémoire (CreateCompatibleDC,
une DIB section que GetDeviceCaps dimensionne : `DevCaps` est encore à zéro) puis le copie dans la fenêtre par BitBlt ;
c'est la partie suivante. Puis DestroyWindow, SetTimer, les barres de défilement.

Tests : hôte (`window` : place d'un LONG dans les octets de plus, USERDATA, ID et instance) ; les scénarios `console` (la
fenêtre de `CONSHOW1.EXE` visible, son rectangle, le chef de sa console, 6 pixels de la capture) et `gui` (le second
thread), sur les deux CPU, qui interdisent « no startup desktop for thread ». 10 mutations, toutes tuées (5 après
ajout de ces tests : les octets de plus, le message posté au mauvais thread ou sans sa fenêtre, le second thread sans
bureau, la conversion avant la station interactive).

La suite : le texte de la console peint (DC en mémoire, DIB sections, BitBlt), les icônes de `consrv`, puis l'entrée
au clavier pour `cmd.exe`.

## Étape 5 : le texte de la console peint

`consrv` compose sa console dans un DC en mémoire et la copie dans sa fenêtre (`conwnd.c`, `guitext.c` de ReactOS,
comme spécification) : à la création de la fenêtre, CreateCompatibleDC(NULL) ; à PM_RESIZE_TERMINAL, une DIB section
de la taille du tampon de l'écran (80 × 300 cellules de 8 × 16 pixels), de la profondeur de l'écran
(GetDeviceCaps(BITSPIXEL)), choisie dans le DC ; à WM_PAINT, le texte de chaque ligne (TextOutW, couleurs des
attributs, sa police VGA) et le curseur (un pinceau plein, PatBlt) dans le DC en mémoire, puis BitBlt dans le DC de la
fenêtre. NtGdiCreateCompatibleDC rendait 0 ; GetDeviceCaps, qui lit les capacités de l'écran dans la table des handles
partagée (un DC dit `DC_PRIMARY_DISPLAY`), y trouvait des zéros : `CreateDIBSection` n'arrivait pas au noyau.

- Mm : les **vues système** (`mm::system_view`, MmMapViewInSystemSpace) : une section du fichier d'échange projetée
  dans la région de 02 §4.2 (`0xFFFF_C000_0000_0000`), sous la moitié haute partagée par tous les espaces, ses pages
  créées à la projection (rien n'y fait de faute : DISPATCH_LEVEL), une page jamais projetée après chaque vue ; ses
  adresses reviennent à la région, ses pages restent à la section.
- Les capacités de l'écran (`win32k::gdi::devcaps`, PDEVOBJ_vGetDeviceCaps et le GDIINFO de `framebuf`) : 32 bits par
  pixel, sans palette, 96 points par pouce, écrites dans la table des handles quand le pilote d'affichage est
  installé.
- Les bitmaps (`win32k::gdi::surface`, SURFACE ; `dibobj.c`, `bitmaps.c`) : le bitmap par défaut (1 × 1, de stock,
  DEFAULT_BITMAP = 21 : `NB_STOCK_OBJECTS` passe à 22) ; les **DIB sections** de 32 bits (BI_RGB ou BI_BITFIELDS aux
  masques de BI_RGB) : leurs pixels dans une section que le processus voit à l'adresse rendue (`ppvBits`) et le noyau
  par une vue système, sans copie ; lignes de bas en haut si `biHeight` est positif ; un bitmap dans un seul DC à la
  fois, qu'on ne supprime pas tant qu'il y est choisi (ce que dit la documentation de DeleteObject ; ReactOS en diffère
  la suppression) ; supprimée, une DIB section quitte la mémoire du processus.
- Les DC en mémoire (`win32k::gdi::dc` : NtGdiCreateCompatibleDC, NtGdiSelectBitmap) : leur origine en (0, 0), leur
  région visible le bitmap choisi ; `DC_DIBSECTION` dans leurs attributs quand une DIB section y est choisie
  (`gdi32` n'y met plus en lot PatBlt et ExtTextOut) ; DeleteDC les supprime. PatBlt et le texte peignent sur la
  surface du DC (`DcState::draw` : l'écran ou son bitmap).
- BitBlt (`win32k::gdi::bitblt`, NtGdiBitBlt et NtGdiMaskBlt sans masque) : la destination coupée là où son DC peint,
  la source lue dans la surface de son DC, un ROP3 quelconque avec le motif d'un pinceau plein
  (`win32k::gdi::dib::rop3`), une étendue négative qui ne retourne pas l'image ; d'un bitmap à l'écran, de l'écran à
  un bitmap, dans l'écran (un défilement : chaque pixel lu avant d'être écrit) ; les bitmaps verrouillés avant
  l'écran, deux bitmaps dans l'ordre de leurs adresses.
- Les pinceaux d'un client (NtGdiCreateSolidBrush) : avec leurs attributs (`BRUSH_ATTR`) chez lui ; `gdi32` met leur
  suppression en lot (GdiBCDelObj).

`consrv` peint « Mino console » en gris sur noir dans la fenêtre de `CONSHOW1.EXE` (sa zone cliente, dans son bord
creusé, à partir de (29, 49)).

Le banc : `BITMAP1.EXE` (`tests/native/bitmap1.c`, scénario `bitmap`) met à l'épreuve ce que `consrv` emploie :
GetDeviceCaps d'un DC de fenêtre et d'un DC en mémoire, une DIB section où le noyau peint (PatBlt du pinceau du
programme) et où le programme lit, un pixel que le programme écrit et que BitBlt copie dans la fenêtre, puis dans la
fenêtre (un défilement), puis de la fenêtre dans une seconde DIB section, une DIB de bas en haut, un bitmap refusé par
un second DC, DeleteObject refusé pour un bitmap choisi, puis les suppressions (les pixels quittent la mémoire du
programme, VirtualQuery).

En passant : en C, l'ordre d'évaluation des arguments d'un appel n'est pas défini (GCC les évalue ici de droite à
gauche) ; le banc fait ses appels un par un avant de les journaliser.

Tests : hôte (Mm : les plages de la région ; win32k : les lignes de bas en haut, le ROP3 avec une source, BitBlt entre
surfaces et dans une surface, la géométrie et le découpage de BitBlt, les capacités de l'écran, l'en-tête d'une DIB
section, la sélection d'un bitmap) ; `system_view_self_test` (scénario `smoke`) ; les scénarios `bitmap` (12 marqueurs,
5 pixels) et `console` (3 pixels du texte de `consrv` ; les services qui manquaient y sont interdits), sur les deux
CPU. Mutations : 5 de Mm, 11 de l'hôte, 3 de la console, 10 du banc, toutes tuées.

Pas encore : les bitmaps compatibles (CreateBitmap, CreateCompatibleBitmap), les profondeurs autres que 32 bits, la
section d'une application (`hSection` de CreateDIBSection), les palettes, GetObject, GetDIBits, SetDIBits,
StretchBlt, MaskBlt avec un masque, NtGdiGetDeviceCaps ; les objets GDI d'un processus rendus à sa fin ; plusieurs
processeurs (la TLB des vues système). `consrv` demande encore les icônes (NtUserFindExistingCursorIcon), un motif
8 × 8 (NtGdiCreateBitmap, NtGdiCreatePatternBrushInternal), SetTimer (le curseur ne clignote pas), les barres de
défilement et DestroyWindow.

La suite : l'entrée au clavier pour `cmd.exe` (le thread d'entrée, i8042), puis `cmd.exe` et NtQueryDirectoryFile.

## Étape 6 : le clavier jusqu'aux fenêtres

Une touche frappée va maintenant jusqu'à la fenêtre au premier plan (`i8042prt`, `keyboard.c`, `msgqueue.c`,
`focus.c` et `input.c` de ReactOS, comme spécification) :

- Le pilote **`drivers/input/i8042`** (comme le prévoit l'audit pour `hal/src/ps2.rs`) : l'interruption IRQ1
  (`hal::idt`) met chaque octet du contrôleur dans l'anneau de `hal::ps2`, puis appelle un crochet
  (`hal::ps2::set_notify`) ; le décodeur (i8042KbdInterruptService) fait des octets du jeu 1 des
  KEYBOARD_INPUT_DATA (`abi::kbd`) : préfixes `E0` et `E1` (Pause), relâchement (`KEY_BREAK`).
- Le **thread d'entrée brute** (RIT, `ntoskrnl::input`, à LOW_REALTIME_PRIORITY + 3 comme dans ReactOS) : le crochet
  met un DPC dans la file, le DPC signale l'événement qu'attend le thread, qui vide le pilote vers win32k. Il ne le
  vide qu'une fois que win32k a pris l'écran : avant, l'ancien lanceur et `syscall.rs` lisent l'anneau.
- Les **tables de la disposition** (`win32k::kbdtables`, KBDTABLES) lues une fois au chargement, chaque liste bornée :
  IntVscToVk (scan code → touche virtuelle, `KBDEXT`, `KBDNUMPAD`), IntTranslateChar (modificateurs de la
  disposition, Caps Lock, AltGr, touches mortes, Ctrl + lettre), IntToUnicodeEx.
- **`win32k::input`** : UserProcessKeyboardInput et ProcessKeyEvent (l'état du clavier, gafAsyncKeyState :
  enfoncée, basculée à chaque appui ; la touche gauche ou droite et la touche commune ; WM_SYSKEYDOWN avec Alt sans
  Ctrl, F10, ou sans fenêtre qui a le clavier ; `lParam` : répétition, scan code, KF_EXTENDED, KF_ALTDOWN,
  KF_REPEAT, KF_UP ; Verr. Num. sur le pavé ; AltGr qui donne Ctrl), vers la file du premier plan.
- **Le premier plan et le focus** : une fenêtre de premier niveau activée (SetWindowPos, ShowWindow ; jusqu'ici
  « pas encore ») devient la fenêtre active de la file de son thread, qui passe au premier plan
  (co_IntSetForegroundWindow, co_IntSetActiveWindow) ; elle reçoit WM_ACTIVATE, dont DefWindowProc lui donne le
  clavier (SetFocus : NtUserSetFocus, co_UserSetFocus, WM_KILLFOCUS et WM_SETFOCUS).
- **La file** (`win32k::queue`) : les touches arrivent à part (messages matériels, `QS_KEY`) et sortent après les
  messages postés et WM_QUIT ; une touche qui sort change l'état du clavier du thread (UpdateKeyStateFromMsg), puis
  sa touche gauche ou droite devient la touche commune (co_IntProcessKeyboardMessage : VK_LSHIFT → VK_SHIFT).
- Services : NtUserGetKeyState et NtUserGetKeyboardState (l'état vu du thread), NtUserGetAsyncKeyState (celui du
  clavier), NtUserToUnicodeEx, NtUserTranslateMessage (WM_CHAR, WM_DEADCHAR et leurs variantes système postés),
  NtUserSetFocus.
- `xtask` : `keys = MARQUEUR => TOUCHES…` dans un scénario fait taper des touches par le moniteur de QEMU
  (`sendkey`) quand le marqueur paraît.

Comme ReactOS : relâcher une touche sans côté (une lettre) la marque à nouveau « enfoncée récemment » pour
GetAsyncKeyState (la touche commune, elle-même, est mise à jour comme encore enfoncée avant d'être relâchée) ; Alt
relâchée après Alt + une touche donne WM_KEYUP, Alt seule WM_SYSKEYUP.

Le banc : `KEYS1.EXE` (`tests/native/keys1.c`, scénario `keyboard`) charge la disposition US comme `winlogon`, ouvre
une fenêtre (WM_ACTIVATE, WM_SETFOCUS) ; le scénario tape Maj + H, I, Entrée : WM_KEYDOWN et WM_KEYUP (Maj en
VK_SHIFT, `lParam` exacts), WM_CHAR « H » Maj enfoncée puis « i » et Entrée ; GetKeyState, GetKeyboardState,
GetAsyncKeyState et ToUnicodeEx ; puis SetFocus(NULL) : A est une touche système pour la fenêtre active
(WM_SYSKEYDOWN, WM_SYSKEYUP), et SetFocus la lui rend.

En passant, la sonde (`ntoskrnl::userland`) ne savait des processus créés par `smss` que ceux qu'un handle tenait
encore à sa fin : un programme qui vit plus longtemps (ce banc) disparaissait de son rapport, une fois `csrss` séparé
de lui. Elle les garde désormais depuis leur création (`ps::set_create_process_notify`, comme
PsSetCreateProcessNotifyRoutine) ; `ps::child_processes` n'avait plus d'utilisateur.

Tests : hôte (le décodeur d'i8042 ; les tables : construites, et `kbdus.dll` de ReactOS épinglé quand il est là ;
ProcessKeyEvent, l'état asynchrone, UserProcessKeyboardInput ; la file : ordre, état du clavier, touche commune ; le
format `keys` d'`xtask`) ; les scénarios `keyboard` (24 marqueurs) et `gui` (WM_ACTIVATE, WM_SETFOCUS, WM_KILLFOCUS
dans ses suites de messages), sur les deux CPU. 10 mutations (l'état du clavier du thread, la touche commune, le
premier plan, KF_REPEAT, WM_CHAR, le crochet de l'interruption, SetFocus(NULL), la touche système sans focus, le
relâchement dans le décodeur, l'état passé à ToUnicodeEx), toutes tuées.

Pas encore : la souris ; les messages au premier plan perdu (WM_NCACTIVATE, WM_ACTIVATE inactif à l'ancienne
fenêtre, ceux d'un autre thread) ; les crochets, les raccourcis, Alt + pavé numérique, Alt + Tab, le changement de
disposition au clavier, les voyants, Impr. écran, SendInput ; les IRP (kbdclass) ; un premier plan qui garde le
thread fini (il reçoit encore les touches). La console : `consrv` reçoit le clavier, mais son WM_CHAR mène à la
lecture d'une ligne (ReadConsole), le pas suivant vers `cmd.exe`.

## Étape 7 : `cmd.exe` interactif

La lecture d'une ligne marchait déjà : une fois le clavier jusqu'aux fenêtres (étape 6), ReadConsoleW rend la ligne
tapée dans la fenêtre console. La procédure de la fenêtre de `consrv` (OnKey, ConioProcessKey : GetKeyboardState,
ToUnicodeEx) met chaque touche dans le tampon d'entrée de la console. La lecture en mode ligne, avec écho, attend
Entrée. `csrsrv` répond plus tard au client qui attend (CsrNotifyWait, NtReplyPort sur un message reçu auparavant).
Rien n'y manquait au noyau. Le vrai `cmd.exe` de ReactOS (mis dans `WINDOWS\SYSTEM32` par `xtask`) est donc lancé :

- il lit ses commandes, une ligne à la fois, tapées d'avance dans la console ;
- il lance un programme console dans sa console (`READ1.EXE`, qui lit la première ligne) ;
- il redirige `>` et `>>` vers des fichiers de `C:` ;
- il fait `set`, `type`, et un script `.bat` écrit par `echo`, avec une variable et `if exist`.

Il manquait **NtQueryDirectoryFile**, sans lequel FindFirstFile échoue (`STATUS_NOT_IMPLEMENTED` : « Incorrect
function. ») : `dir`, mais aussi `copy`, qui cherche ses sources par FindFirstFile. Le service suit
`find.c` de `kernel32`, qui l'appelle ; `iofunc.c` de ReactOS et la documentation publique de
ZwQueryDirectoryFile et de FsRtlIsNameInExpression ont servi de spécification :

- **`abi::file`** : FILE_DIRECTORY_INFORMATION, FILE_FULL_DIR_INFORMATION, FILE_BOTH_DIR_INFORMATION et
  FILE_NAMES_INFORMATION, comme en C (le nom à `FileName[1]`), avec leurs assertions ;
  `DirectoryEntry::encode` écrit une entrée de l'une de ces classes.
- **`io::directory`** :
  - l'expression (FsRtlIsNameInExpression sans casse) : `*`, `?`, et les jokers DOS que `kernel32` met à la place
    de certains (`<` pour `*` devant un `.`, `>` pour `?`, `"` pour un `.` devant eux) ;
  - le tampon : chaque entrée à un multiple de 8 octets, la dernière avec un `NextEntryOffset` de 0. Une entrée
    qui ne tient pas attend la requête suivante. La première, si elle ne tient pas, est coupée
    (`STATUS_BUFFER_OVERFLOW`, `FileNameLength` dit ce qui est écrit).
- **`io::File::query_directory`** :
  - l'état de l'énumération est dans l'objet `File`, comme le CCB d'un pilote de système de fichiers ;
  - l'expression est celle de la première requête (`*` sans nom), ignorée ensuite ;
  - un nom y répond par son nom long ou par son nom 8.3 ;
  - la reprise se fait à la place de l'entrée dans le répertoire (`FileIndex`), ou depuis le début avec
    `RestartScan` ;
  - `STATUS_NO_SUCH_FILE` si la première requête ne trouve rien, `STATUS_NO_MORE_FILES` ensuite.
- **`io::Volume::entries`** décrit chaque entrée : `.` et `..` d'un sous-répertoire de FAT, sans le nom du volume.
  `fat::dir_entries` donne aussi le nom 8.3 d'un nom long, la place de l'entrée et ses dates.
- **`sys::file`** : NtQueryDirectoryFile.
  - L'ordre des vérifications est celui du gestionnaire d'E/S : le bloc d'état et le tampon sondés, puis le nom
    capturé, puis `STATUS_INFO_LENGTH_MISMATCH` sous la taille de la classe, puis le handle (`FILE_LIST_DIRECTORY`).
  - Le bloc d'état est écrit pour un succès et pour les avertissements.
  - Les classes à identifiants de fichiers (37, 38) rendent `STATUS_NOT_IMPLEMENTED`, journalisé une fois.

Pour taper des commandes, `xtask` accepte du texte entre guillemets dans `keys =` : `"dir C:\"` donne les touches de
chaque caractère sur un clavier américain (`shift-semicolon` pour `:`…). Les touches vont plus vite : 30 ms enfoncées,
60 ms entre deux. La sonde de `smss` attendait son processus 10 s, puis le terminait, même pendant qu'on tapait. Elle
attend désormais 10 s après la dernière touche (`ntoskrnl::input::last_key_time`).

Le banc : `CONCMD1.EXE` (`tests/native/concmd1.c`, scénario `cmd`) prend la place de `winlogon.exe` et lance
`cmd /K C:\READ1.EXE`. Le scénario tape une ligne pour `READ1.EXE` (`tests/native/read1.c`), puis les commandes :
`echo`, `set`, `copy`, `type`, `dir /b C:\*.TXT`, `dir C:\`, un `.bat`, `exit`. `CONCMD1.EXE` relit ensuite
`C:\OUT.TXT` et `C:\DIR.TXT`, une ligne numérotée à la fois, sur le port de débogage.

Tests :

- hôte :
  - les entrées de chaque classe (`abi`) ;
  - l'expression avec les jokers DOS, le tampon : alignement, entrée unique, entrée qui attend, première coupée ;
  - l'énumération d'un répertoire du disque de test : `.` et `..`, nom long et nom 8.3, attributs, tailles,
    reprise, expression gardée, `STATUS_NO_SUCH_FILE`, `STATUS_NO_MORE_FILES`, fichier ;
  - les places dans un répertoire de deux clusters, au-delà d'une entrée effacée ;
- le scénario `cmd`, sur les deux CPU ;
- 17 mutations, toutes tuées : l'expression, le tampon, l'état, le nom du volume, les places, ShortNameLength,
  ReturnSingleEntry ignoré (ce dernier, par le scénario).

Pas encore : ce que `dir` affiche autour des noms (l'étape 8) ; les classes à identifiants
(FileIdBothDirectoryInformation) ; le partage et la suppression ; les noms longs créés ; les icônes de `consrv`,
SetTimer, les barres de défilement ; DestroyWindow (la fenêtre d'une console finie reste à l'écran).

## Étape 8 : ce que `dir` affiche autour des noms

À l'étape 7, `dir` listait les noms sans rien autour : ni en-tête du volume, ni place libre (« 0 bytes free »), et
des dates en « 01???01???1601 ». Chacun de ces manques avait sa cause, que `kernel32` de ReactOS épinglé
(`volume.c`, `disk.c`) et `dir.c` de `cmd` ont désignée.

**L'en-tête du volume.** GetVolumeInformationW ouvre la racine, puis la vérifie (IsThisARootDirectory) : son nom,
FileNameInformation, doit finir par `\`, et `\??\C:` doit être un lien. Ensuite elle demande
FileFsVolumeInformation. GetVolumePathNameW rend `C:\` sans le gestionnaire des points de montage : l'ouverture du
volume comme fichier échoue, et `C:\` reste.

- NtQueryInformationFile(**FileNameInformation**) : le chemin depuis la racine du volume (`\` pour la racine).
  `FileNameLength` dit la longueur entière ; un nom coupé rend `STATUS_BUFFER_OVERFLOW`.
- NtQueryVolumeInformationFile :
  - **FileFsVolumeInformation** : le numéro de série du BPB (`BS_VolID`, `4D49-4E4F` que `tools/mkfat` écrit),
    le nom de l'entrée de volume de la racine (aucun : « has no label »), sans date de création ;
  - **FileFsAttributeInformation** : `FAT32`, noms gardés avec leur casse, en Unicode, 255 caractères au plus ;
  - **FileFsSizeInformation** et **FileFsFullSizeInformation** : les clusters du volume, dont les libres, que
    `FatVolume::free_clusters` compte dans la FAT (le compte du secteur FSInfo n'est pas cru).

**Les dates.** Trois manques :

- `tools/mkfat` n'en écrivait pas. Chaque entrée de l'image porte désormais la même date, le 4 août 2004 à 12 h
  (XP SP2, ADR-003) : deux images construites sont identiques.
- Io n'en écrivait pas non plus :
  - un fichier créé prend le temps système (`hal::rtc::system_time`) pour création, dernier accès et dernière
    écriture ;
  - une écriture ou un changement de taille, pour dernier accès et dernière écriture ;
  - les dates de FAT (`fat::FatTime`, `fat::fat_time`) sont en heure locale, ici l'UTC faute de fuseau horaire.
- NtQueryDefaultLocale manquait. Sans lui, GetLocaleInfo recevait un identifiant indéfini, d'où les `???` des
  séparateurs. Il rend celui de `Nls\Language\Default` (0x0409), lu une fois la ruche SYSTEM montée
  (`ex::locale`). Celui de l'utilisateur est le même tant que NtSetDefaultLocale n'est pas là.

**`copy` et les dates.** NtSetInformationFile(**FileBasicInformation**), avec `FILE_WRITE_ATTRIBUTES` :

- les dates de création, de dernier accès et de dernière écriture (0 laisse un champ comme il est ; FAT n'a pas de
  date de changement) ;
- les attributs (lecture seule, caché, système, archive ; `FILE_ATTRIBUTE_NORMAL` les efface ; le bit de
  répertoire reste) ;
- une date que FAT ne tient pas, ou la racine, rendent `STATUS_INVALID_PARAMETER`.

Le `copy` de ReactOS ne reporte que la date de **création** de la source (GetFileTime, puis SetFileTime sur la
copie) : `dir /TC` la montre, `dir` montre la dernière écriture, celle de la copie.

**Les touches perdues.** Le scénario tapait des commandes après le `.bat`, et `cmd` les recevait avec Maj enfoncée
(`COPY C:|KERNEL>BIN`). La cause n'est pas le noyau :

- le thread d'entrée brute recevait autant d'appuis que de touches tapées, mais moins de relâchements ;
- l'anneau de `hal::ps2` n'avait rien perdu ;
- l'horloge n'a jamais été retenue plus de 100 ms, donc les interruptions n'étaient pas masquées ;
- les traces de QEMU (`input_event_key_qcode`, `ps2_keyboard_event`) montrent la perte en amont du clavier
  émulé : 670 appuis, 568 relâchements.

QEMU 8.2 tape un `sendkey` en appuyant ses touches, puis en les relâchant, une tenue d'écart entre deux, depuis une
file d'événements différés. Un `sendkey` qui arrive pendant que des relâchements attendent encore dans cette file en perd.
`xtask` attend désormais qu'une touche soit relâchée (deux tenues par touche de la combinaison, et une marge) avant la
suivante : 670 relâchements sur 670. L'étape 7 ne le voyait pas, seul `exit` (`EXIT` marche aussi) venait après le
moment où Maj restait enfoncée. En chemin, l'anneau de `hal::ps2` compte ce qu'il perd (`hal::ps2::dropped`), et la
sonde le dit ; il perdait sans rien dire.

Le banc : le scénario `cmd` vérifie l'en-tête de `dir` (sans nom, numéro de série), les dates des fichiers de l'image
(« 08/04/2004  12:00 PM »), la place libre (pas « 0 bytes free », pas de « 1601 »), `copy C:\KERNEL.BIN C:\K.BIN`
puis `dir /TC C:\K.BIN` (la date de création de la source), et `vol`.

Tests :

- hôte :
  - les structures et leurs noms coupés (`abi`) ;
  - les dates de FAT aller et retour, et hors de leurs années ;
  - un volume qui se décrit : nom de l'entrée de volume, numéro de série, clusters libres avant et après une
    écriture ;
  - les dates d'un fichier créé puis écrit (une horloge qui avance) ;
  - FileBasicInformation : dates, 0 qui laisse, `FILE_ATTRIBUTE_NORMAL`, le bit de répertoire, la date d'avant
    1980, la racine ;
  - les dates de `tools/mkfat` ;
  - le LCID de `Nls\Language` ;
  - la durée d'une touche dans `xtask` ;
- le scénario `cmd`, sur les deux CPU ;
- 17 mutations, toutes tuées (dont FileNameInformation sans `\` final, par le scénario) ; une autre, équivalente
  (la locale de l'utilisateur), a fait réduire `ex::locale` à une valeur.

**Le critère « `cmd.exe` est interactif » du M5 est coché** : `dir`, `copy`, `type`, `set` et un `.bat`, tapés dans
la console, rendent ce qu'ils rendent sur XP.

Pas encore :

- la casse des noms 8.3 (octet 12), la date de dernier accès à la lecture, le fuseau horaire ;
- NtSetDefaultLocale (la locale de l'utilisateur) ;
- ProcessDeviceMap (NtQueryInformationProcess, classe 0x17, que GetDriveType demande ; `dir` s'en passe) ;
- `del`, `ren`, `md`, `rd` (suppression et renommage d'Io) ;
- les outils externes de ReactOS (`find`, `sort`, `more`, `xcopy`, `attrib`…), à mettre sur le disque ;
- `format` et `chkdsk` (`fmifs.dll`, `ufat.dll` : l'ouverture d'un volume comme périphérique, les IRP) ;
- le défilement de la fenêtre console (la vue reste sur les 25 premières lignes).
