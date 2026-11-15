# M6 — le logon, de NtCreateToken à `userinit`

Premier critère de sortie du M6 ([05](../05-feuille-de-route.md#m6--win32k-avec-le-spike-s3-en-premier)) : « `winlogon`
(ouverture de session automatique), `userinit` et `explorer` affichent le bureau, la barre des tâches et le menu
Démarrer ». L'étape 27 du M5 ([`m5-csrss.md`](m5-csrss.md)) menait le second démarrage du scénario `logon` jusqu'à
NtCreateToken : `msgina` ouvre la session d'`Administrator` par LsaLogonUser, `msv1_0` valide le compte, et `lsasrv`
fait le jeton de la session. Ce document suit la suite, jusqu'à `userinit.exe` qui cherche le shell.

La spécification suivie est ReactOS 0.4.16 (le comportement de ses DLL et services, et `ntoskrnl/se`, `ntoskrnl/config`,
`ntoskrnl/ex/locale.c`, `ntoskrnl/ps/security.c` comme description) ; aucun code n'en est porté.

## Ce que le logon demandait, dans l'ordre

Chaque ligne est un arrêt du scénario `logon`, sa cause, et ce qui l'a levé.

1. **NtCreateToken** (`se::Token::create`, SepCreateToken ; `sys::security::nt_create_token`). `lsasrv` fait le
   jeton primaire de l'utilisateur : son SID et ses groupes, ses privilèges, son propriétaire par défaut (l'utilisateur,
   ou un groupe qui porte `SE_GROUP_OWNER` : sinon `STATUS_INVALID_OWNER`), son groupe principal (l'utilisateur ou un de
   ses groupes : sinon `STATUS_INVALID_PRIMARY_GROUP`), sa DACL par défaut, sa source, sa session d'ouverture (que le
   moniteur de références doit connaître : `STATUS_NO_SUCH_LOGON_SESSION`), sous `SeCreateTokenPrivilege`. Tout est
   capturé (`se::capture_sid`, `se::capture_acl`, partagés avec la capture des descripteurs). Un jeton d'emprunt
   d'identité prend son niveau de la qualité de service des attributs. LsaLogonUser réussit.
2. **FileEaInformation** (NtQueryInformationFile, classe 7). `userenv` fait le profil d'`Administrator` en copiant
   celui de `Default User` (CopyDirectory) ; CopyFileW demande la taille des attributs étendus avant de copier, et la
   classe manquait (erreur 87, profil refusé). Ni la FAT ni NPFS n'en ont : 0.
3. **NtLoadKey** (`cm::load_hive`, `sys::registry::nt_load_key`). `userenv` monte le `NTUSER.DAT` du profil en
   `\REGISTRY\USER\<SID>` par RegLoadKeyW, qui donne la clé relativement au handle de `HKEY_USERS` (le SID seul) :
   la ruche est lue par Io, montée sous une clé virtuelle ouverte, et NtFlushKey la réécrit dans ce fichier.
   `SeRestorePrivilege`, que `userenv` active.
4. **NtUnloadKey** (`cm::unload_hive`). `userenv` charge la ruche pour la préparer, la décharge, puis la recharge
   pour la session : sans le déchargement, le second chargement trouvait le nom pris (erreur 183). La ruche est
   réécrite si elle a changé, puis démontée ; les clés encore ouvertes la gardent.
5. **NtDuplicateToken** (`se::Token::duplicate_as`). ImpersonateLoggedOnUser fait une copie d'emprunt d'identité du
   jeton de l'utilisateur, que `winlogon` emprunte pour préparer sa session. `EffectiveOnly` ne garde que les groupes
   et privilèges actifs. Un `DesiredAccess` nul donne à la copie les droits du handle copié : c'est ce que
   DuplicateTokenEx demande pour la copie primaire de CreateProcessAsUser (sans cela, le handle n'avait aucun droit, et
   l'assignation du jeton était refusée, `STATUS_ACCESS_DENIED`).
6. **Les paramètres régionaux de l'utilisateur**. SetDefaultLanguage de `winlogon` lit
   `HKCU\Control Panel\International\Locale` et le redonne par NtSetDefaultLocale(UserProfile). La ruche DEFAULT du
   LiveCD a la clé, vide (c'est l'installation de ReactOS qui l'écrit) : la couche Mino pose `Locale` = `00000409`
   (`tools/mkhive/mino.inf`), qui passe dans `NTUSER.DAT` de `Default User`, puis dans chaque profil. NtSetDefaultLocale
   écrit maintenant la valeur de l'utilisateur dans son profil (RtlOpenCurrentUser : la ruche du SID du jeton effectif,
   `.DEFAULT` sans elle), et `ex::locale` sépare les paramètres de l'utilisateur de ceux du système (ceux du système
   tant que rien ne les fixe) ; NtQueryDefaultLocale répond selon `UserProfile`. Sans la valeur, `winlogon` fermait la
   session sans un mot (ses avertissements ne sont pas compilés dans la version publiée). `winsrv` dit alors « We are
   logged on ».
7. **ProcessAccessToken** (NtSetInformationProcess, classe 9 ; `sys::security::assign_primary_token`,
   `ps::EProcess::set_primary_token`). `msgina` lance `userinit.exe` par CreateProcessAsUserW : le processus est créé
   suspendu, puis reçoit le jeton primaire de l'utilisateur (`TOKEN_ASSIGN_PRIMARY`, un jeton primaire,
   `SeAssignPrimaryTokenPrivilege` actif).

`userinit.exe` (sur le disque depuis cette étape) tourne alors sous le jeton de l'utilisateur : il se connecte à
`csrss` et à win32k, charge la disposition de clavier, applique les paramètres de l'utilisateur
(UpdatePerUserSystemParameters), puis cherche le shell de `Winlogon\Shell`, `C:\WINDOWS\explorer.exe`, qui n'est pas
sur le disque : « Failed to start default shell », puis la boîte « Userinit failed to start the shell! ».

## Vu en chemin, pas fait

- Le thread de `userinit` n'a pas de bureau de démarrage : « no startup desktop for thread … of userinit.exe
  (STATUS_NOT_IMPLEMENTED) » (`win32k::startup`) ; il prend celui de son processus ensuite. À diagnostiquer avant
  `explorer`, qui doit s'ouvrir sur `WinSta0\Default`.
- NtDeleteKey (le nettoyage de `winlogon` à la fermeture d'une session : `Volatile Environment`), FileStreamInformation
  (classe 22, que CopyFileW demande sans en dépendre), NtUserSetThreadState, NtUserUpdatePerUserSystemParameters
  (rend 0), NtUserSystemParametersInfo (classes 0x0E, 0x14, 0x5A), NtUserCallOneParam (0x31), NtUserCallHwnd.
- La parenté des jetons (`ParentTokenId`, SeIsTokenChild, SeIsTokenSibling) n'est pas suivie : un jeton tiré de celui
  de l'appelant demande donc aussi `SeAssignPrimaryTokenPrivilege` ; `winlogon` l'a actif.
- NtUnloadKey démonte une ruche dont des clés sont ouvertes (NT refuse : `STATUS_CANNOT_DELETE`).
- NtLoadKey refuse un fichier désigné relativement à un répertoire ouvert (`STATUS_NOT_IMPLEMENTED`) : sa réécriture
  demande son nom entier.

## Le shell : `explorer.exe`

`explorer.exe` est sur le disque des scénarios qui le demandent (`shell = explorer`, ici `logon`), dans
`C:\WINDOWS` (`SHELL_FILES`, `xtask/src/userland.rs` : la fermeture de ses imports vient avec, `browseui` et
`shdocvw` compris). Les autres disques ne le prennent pas : avec ces trois fichiers, la copie du disque de
l'installateur ne tenait plus sur sa cible (`installer-finish` : « copy failed: c0000185 »). `userinit` le lance
sous le jeton de l'utilisateur.

**Les classes COM d'`explorer` et les fenêtres message seul** (PR 133, `claude/logon-explorer`, fusionnée ici).
`explorer` crée par COM son menu Démarrer (CLSID_StartMenu, `{4622AD11-FF23-11D0-8D34-00A0C90F2719}`) et le site de
bandes de sa barre (CLSID_RebarBandSite, `{ECD4FC4D-521C-11D0-B792-00A0C90312E1}`), que rien n'enregistrait
(`REGDB_E_CLASSNOTREG`) : l'installation de ReactOS appelle DllRegisterServer des DLL de `syssetup.inf`
(`RegistrationPhase2`, `OleControlDlls`). `minoinit.exe` appelle CoInitialize, puis DllRegisterServer de celles de
cette liste qui sont sur le disque, avant la réécriture des ruches. `browseui` et `rpcrt4` réussissent (le scénario
`logon` attend `browseui`) ; `oleaut32`, `shdocvw` et `urlmon` rendent `E_NOINTERFACE`, `shell32` `E_FAIL`, `wininet`
n'a pas de DllRegisterServer : à diagnostiquer (sans doute le registrar d'ATL, `atl.dll`, en tête de la liste et pas
sur le disque, et l'enregistrement des bibliothèques de types). La fenêtre d'appartement de COM n'était pas créée non
plus (`combase` apartment.c : « CreateWindow failed with error 1400 ») : chaque bureau a maintenant sa fenêtre des
messages (`win32k::window::create_message_window`, `spwndMessage`, `FNID_MESSAGEWND`), dont les fenêtres créées avec
`HWND_MESSAGE` sont les enfants (cachées, hors des fenêtres de premier niveau ; scénario `gui`). En chemin, CopyFileW
de `minoinit` échouait (erreur 998) selon la profondeur de sa pile : NtSetInformationFile(FileBasicInformation)
exigeait un tampon aligné sur 8 octets, que les compilateurs x86 ne garantissent pas à une structure posée sur la
pile ; 4 suffisent maintenant, comme pour les autres valeurs de 64 bits (scénario `cmd`, `concmd1.c`).

**Le premier lancement a mis au jour un bogue du noyau.** `explorer` mourait (`c0000096`, une instruction privilégiée à
l'adresse `0x006E0057`) dans la création de sa barre des tâches. Ses registres sauvés portaient les mots successifs de
« Shell_TrayWnd » en UTF-16 : EBX « l_ », EDI « Tr », EBP « ay », et l'adresse de retour « Wn ». NtUserGetAtomName
prend une UNICODE_STRING (`pustrName`, useratom.c), que `user32` pose sur sa pile quand une classe est donnée par
son atome (ClassNameToVersion, VersionRegisterClass, autour de CreateWindowEx et de RegisterClass) ; Mino la prenait
pour le tampon et y écrivait le nom entier, au-delà de ses 8 octets. Le même motif (« SHELLDLL_DefView » sur la pile)
faisait planter la boîte Enregistrer sous du Bloc-notes avant la PR 127. NtUserGetAtomName suit maintenant
useratom.c :

- le nom vient de la table de USER comme RtlQueryAtomInAtomTable le rend (`win32k::atom::query_name`) : 255
  caractères au plus (IntGetAtomName), « #n » pour un atome entier (NtQueryInformationAtom aussi, qui rendait les
  chiffres sans « # ») ;
- la UNICODE_STRING est lue, son tampon sondé sur `MaximumLength` ; le nom y est tronqué pour laisser la place du nul
  (`win32k::atom::copied_name_units`), rien sans cette place ; le service rend le nombre de caractères copiés ;
- 0 pour un thread sans bureau (IntGetAtomName) ; 0 et la dernière erreur pour un atome inconnu ou une adresse fautive.

**La correction a montré deux autres écarts, dans la boîte Enregistrer sous du Bloc-notes.** Tant que la pile de
`user32` était écrasée, la création de la vue de dossier (CDefView, « SHELLDLL_DefView ») échouait sans bruit et la
boîte n'avait pas de liste ; `notepad-save` passait ainsi. La vue créée, deux écarts du noyau l'ont arrêtée :

- **SendMessage vers une fenêtre qui n'existe pas rendait une valeur au hasard.** CDefView compte les colonnes de
  l'en-tête de sa liste (`Header_GetItemCount(ListView_GetHeader(...))`) alors que la liste n'a pas encore d'en-tête :
  SendMessageW(NULL, HDM_GETITEMCOUNT). `user32` (SendMessageW, SendMessageA) passe au noyau l'adresse d'une variable
  `Result` qu'il n'initialise pas et la rend telle quelle. ReactOS (NtUserMessageCall, FNID_SENDMESSAGE) y écrit
  toujours la valeur de co_IntDoSendMessage, 0 pour une fenêtre inconnue (`ERROR_INVALID_WINDOW_HANDLE`), et rend
  TRUE ; Mino rendait FALSE sans l'écrire. CDefView prenait donc des colonnes pour existantes, les modifiait
  (LVM_SETCOLUMN) au lieu de les insérer, et l'assertion `MapFolderColumnToListColumn(0)` (CDefView.cpp:1178)
  arrêtait le Bloc-notes. NtUserMessageCall(FNID_SENDMESSAGE) suit maintenant ReactOS (`sys::message`,
  `send_message_result`) : TRUE et 0 si l'envoi échoue, avec son erreur ; FALSE seulement si `ResultInfo` est fautif.
- **Une fenêtre déjà active était réactivée, et perdait le focus.** comdlg32 redimensionne sa boîte (ArrangeCtrlPositions :
  SetWindowPos sans SWP_NOACTIVATE). Mino ne tenait une fenêtre pour déjà active que si elle avait aussi le focus ;
  celui de la boîte était sur le champ du nom : WM_NCACTIVATE, WM_ACTIVATE, puis le focus à la boîte elle-même, que
  DefDlgProc rendait à son premier contrôle, la liste « Enregistrer dans ». Les touches tapées après Alt+N y
  choisissaient « Poste de travail », et le champ ne gardait que la dernière lettre : « Path does not exist ».
  ReactOS (co_IntSetActiveWindow) ne fait rien pour une fenêtre déjà active ; après WM_ACTIVATE, il ne donne le focus
  à la fenêtre que s'il n'est pas déjà dans l'une de ses filles (IntGetNonChildAncestor). `win32k::input::activate`
  fait de même (`focus_is_in`).

**Le thread du bureau : MsgWaitForMultipleObjects.** CDesktopThread::Initialize attend son thread du bureau et
l'événement que celui-ci signale une fois le bureau créé, par MsgWaitForMultipleObjects (`desktop.cpp`). `user32`
(RealMsgWaitForMultipleObjectsEx) y ajoute l'événement de la file du thread, qu'il demande par
NtUserCallOneParam(ONEPARAM_ROUTINE_GETINPUTEVENT, 0x27 ; IntMsqSetWakeMask), puis efface le masque de réveil
(NOPARAM_ROUTINE_MSQCLEARWAKEMASK, 0x03). Mino n'avait ni l'un ni l'autre : WAIT_FAILED tout de suite, E_FAIL
(`desktop.cpp:193`), et Initialize remettait le plateau à NULL avant que le thread du bureau ne s'en serve
(l'assertion d'ATL, atlcomcli.h:208, `p != 0`). Comme InitThreadCallback, chaque thread GUI reçoit maintenant à sa
conversion un handle (EVENT_ALL_ACCESS) sur l'événement de sa file (`hEventQueueClient`,
`win32k::gui::ThreadInfo::queue_event_handle`), fermé à sa fin s'il le désigne encore ; IntMsqSetWakeMask
(`win32k::queue::input_event`) rend ce handle et signale l'événement si la file a déjà changé pour le masque demandé
(ou, MWMO_INPUTAVAILABLE, si l'un de ses bits est levé). La file de Mino n'a pas de masque de réveil (son événement
est signalé à chaque message) : NOPARAM_ROUTINE_MSQCLEARWAKEMASK n'a rien à défaire. ReactOS y remet aussi
`fsWakeBits` à zéro (« very hacky ») ; Mino ne le fait pas, ses bits de réveil suivent ce que tient la file.

**La fenêtre du shell : NtUserSetShellWindowEx.** Le thread du bureau crée alors le bureau d'`explorer` (« Progman »,
sa vue de dossier sur le Bureau de l'utilisateur et de All Users) et déclare sa fenêtre celle du shell
(`win32k::shell`, comme `window.c`) : une fois par station (ShellWindow, ShellListView), dans le `DESKTOPINFO` du
bureau (`hShellWindow`, `spwndShell`, `spwndBkGnd`, `ppiShellProcess`, que `user32` lit pour GetShellWindow), et
la fenêtre du shell passe au bas de l'ordre Z (`WNDS2_BOTTOMMOST`), que SetWindowPos ne lui fait plus quitter
(UserGetShellWindow dans co_WinPosSetWindowPos). Détruite, elle quitte la station et le `DESKTOPINFO`. Pas encore :
le raccourci Ctrl+Échap (SC_TASKLIST), faute de RegisterHotKey.

**Ce qu'une fenêtre découvre en changeant seulement de rang.** Le bureau d'`explorer`, d'abord au-dessus de tout,
avait recouvert la barre des tâches ; passé au fond, il ne la découvrait pas : SetWindowPos tenait pour découvert
l'ancien rectangle moins le nouveau, vide quand seul l'ordre Z change. Comme co_WinPosSetWindowPos
(co_VIS_WindowLayoutChanged de VisBefore moins VisAfter), `win32k::winpos::set_window_pos` compare maintenant ce qu'on
voyait de la fenêtre avant et après, ses sœurs au-dessus déduites (`paint::visible_region`) : la barre des tâches
se repeint.

**La station d'un chemin de bureau sans station.** NtUserSetShellWindowEx prend la station du processus ; celui
d'`explorer` n'en avait pas : `msgina` donne à `userinit`, puis à `explorer`, le chemin `Default`, sans station, que
win32k refusait (STATUS_NOT_IMPLEMENTED, « no startup desktop »). Le bureau restait alors au-dessus de tout, et
une fois son fond peint, il couvrait la barre des tâches. Comme IntResolveDesktop, `win32k::startup::resolve_desktop`
prend maintenant la station héritée du processus (ObFindHandleForObject, `ob::HandleTable::find_by_type`) si son
interactivité (`!WSS_NOIO`) correspond à son droit sur WinSta0, sinon WinSta0 s'il y a droit (le LUID de son
utilisateur, ou System avec des handles hérités) (`default_station`). Pas encore : la station des services
(`Service-0x…$`), dont `services.exe` et `lsass.exe` restent privés comme avant, et le bureau hérité d'un chemin
sans bureau (`Default` à la place).

**Le fond du bureau : NtUserPaintDesktop.** `explorer` peint le fond de son bureau par PaintDesktop. Comme
IntPaintDesktop sans papier peint (`win32k::desktop::paint_desktop`), la boîte de découpage du DC prend le pinceau
de la classe de la fenêtre du bureau, COLOR_BACKGROUND (la classe garde la forme « couleur + 1 », ramenée au pinceau
public de la couleur), par PATCOPY, sans changer le pinceau choisi dans le DC. Pas encore : le papier peint
(SPI_SETDESKWALLPAPER, classe 0x14 de NtUserSystemParametersInfo), le texte de version (PaintDesktopVersion), le
fond noir du mode sans échec.

**Les DC pris pendant qu'une fenêtre bouge.** `explorer` prend le DC de son bureau quand celui-ci est au-dessus de
tout, et le garde. Comme DceResetActiveDCEs, `win32k::dce::reset_active_dcs` refait après chaque SetWindowPos la
région visible de chaque DC du cache pris pour une fenêtre ; ceux de la fenêtre déplacée ou de ses filles suivent
son coin, et la région qui les coupe, gardée à leur prise, est décalée d'autant.

**Le bouton Démarrer : DeferWindowPos.** La barre des tâches place son bouton Démarrer, son site de bandes et sa
zone de notification par BeginDeferWindowPos, DeferWindowPos et EndDeferWindowPos (traywnd.cpp, AlignControls), que
Mino n'avait pas (« BeginDeferWindowPos failed. lastErr=120 », traywnd.cpp:1705) : le bouton, créé de taille nulle,
le restait. Comme `simplecall.c` et `winpos.c` (`win32k::deferpos`) : BeginDeferWindowPos
(NtUserCallOneParam, ONEPARAM_ROUTINE_BEGINDEFERWNDPOS, 0x1E) rend un lot, objet USER `TYPE_SETWINDOWPOS` du
processus (rendu à sa fin) ; DeferWindowPos (NtUserDeferWindowPos) y range un déplacement par fenêtre, un second
déplacement de la même fenêtre se fondant dans le premier (IntDeferWindowPos : ce que le second change remplace, ses
`SWP_NO*` ne restent que si les deux les portaient) ; EndDeferWindowPos (NtUserEndDeferWindowPosEx) les fait l'un après
l'autre par SetWindowPos, saute une fenêtre détruite entre-temps, s'arrête au premier échec et rend le lot. Les
drapeaux et les fenêtres refusés le sont comme dans ReactOS (`ERROR_INVALID_FLAGS`, `ERROR_INVALID_PARAMETER`,
`ERROR_INVALID_DWP_HANDLE`, le bureau et sa fenêtre des messages). La barre appelle aussi NtUserSetWindowRgn sans région
(un seul moniteur) : la fenêtre n'en a pas, son cadre se recalcule et elle passe en tête de ses sœurs (SetWindowPos
HWND_TOP, SWP_FRAMECHANGED), et NtUserRemoveProp (UserRemoveProp, la liste des propriétés republiée dans le tas
partagé). Le bouton Démarrer est maintenant à gauche de la barre, (2, 776)-(66, 796), le bouton de `user32` avec son
texte « Start » : pas encore son logo, ni le thème de comctl32 6, faute de l'assemblage côte à côte
`Microsoft.Windows.Common-Controls` 6.0 (« Could not find dependent assembly ») et des listes d'images. Pas encore :
une vraie région de fenêtre (refusée, journalisée une fois), EndDeferWindowPos asynchrone.

**Le menu Démarrer attendait les icônes.** Avec les classes COM de la PR 133, `explorer` crée son menu Démarrer
pendant la création de sa barre (CTrayWindow::OnCreate, CreateStartMenu : les dossiers `Start Menu` de
l'utilisateur et de All Users parcourus), mais ses barres d'outils demandent la liste d'images du système
(CMenuToolbars.cpp:356, SHGetImageList), que `shell32` ne pouvait pas créer sans les icônes (« Failed to add
IDI_SHELL_DOCUMENT icon to cache ») : SHGetImageList appelait QueryInterface d'une liste NULL (une lecture en 0 dans
`shell32`, RVA `0xF4533`), que `user32` rattrapait (« Exception when calling unicode WndProc ... Msg 1 ») ; OnCreate
s'arrêtait là, sans site de bandes ni zone de notification, et un clic sur Démarrer donnait traywnd.cpp:2997 (E_FAIL)
et l'assertion d'ATL atlwin.h:1124. La branche des icônes (`claude/blissful-herschel-4bf0cc`, fusionnée ici :
NtUserGetIconInfo, GetDIBits, StretchBlt, NtGdiCreateDIBitmapInternal, NtGdiAlphaBlend, les images de `comctl32`,
`shell32` enregistré) lève ce blocage.

**Le bureau, la barre des tâches et le menu Démarrer.** `explorer` crée maintenant toute sa barre : le bouton
Démarrer, le site de bandes, la zone de notification et son horloge ; son bureau montre ses quatre icônes (My
Documents, My Computer, My Network Places, Recycle Bin). Un clic sur le bouton Démarrer (la souris de QEMU, scénario
`logon`) poste TWM_OPENSTARTMENU à la barre, qui ouvre son menu (CMenuDeskBar::Popup : la fenêtre « BaseBar »,
SetWindowPos HWND_TOPMOST, SWP_SHOWWINDOW) au-dessus du bouton, en (2, 498)-(175, 776), et enfonce le bouton
(BM_SETSTATE) : Programs, Documents, Settings, Search, Help and Support, Run..., Shut Down..., avec leurs icônes et le
bandeau. **Le premier critère du M6 est atteint.**

Écarts et dettes vus en chemin :

- **Le menu met 15 à 30 s à paraître la première fois.** Chacune de ses icônes fait créer par `shell32` une section de
  données de `shell32.dll` (NtCreateSection, `SEC_COMMIT`, pour LoadImage), et Mino copie le fichier entier dans
  chaque section (`sys::section`, `io_manager::File::read_all` : 10,9 Mo lus en PIO sur le disque ATA à chaque fois).
  NT partage une seule *control area* par fichier entre ses sections ; Mino en est loin. Tâche : une copie par fichier
  (ou des pages lues à la demande), pour toutes les sections d'un même fichier. Le scénario `logon` attend le menu
  jusqu'à 120 s (`screen-wait`).
- Le suivi du menu par la souris et le clavier n'est pas vérifié : `shell32` (CMenuFocusManager) pose des crochets
  WH_GETMESSAGE et WH_MSGFILTER (SetWindowsHookEx, pas encore).
- En chemin : NtUserSystemParametersInfo (classes 0x14 SPI_SETDESKWALLPAPER, 0x2B et 0x2C MINIMIZEDMETRICS, 0x2F et
  0x30 WORKAREA, 0x42, 0x100A), NtUserCallHwnd (0x48), NtUserCallHwndOpt (0x4B), NtUserGetAncestor,
  NtUserGetDoubleClickTime, NtUserFindWindowEx, NtUserSetParent, NtUserRegisterHotKey, NtUserGetSystemMenu,
  NtUserCallOneParam (0x28 GETKEYBOARDLAYOUT, 0x31 MESSAGEBEEP), NtQueryInformationThread (classe 0x10),
  NtNotifyChangeDirectoryFile (« ReadDirectoryChangesW ... failed », le bureau ne suit pas son dossier). La fenêtre
  « Progman » mesure (1, 0)-(32768, 32767) : la taille de l'écran virtuel qu'il demande est à vérifier
  (SM_CXVIRTUALSCREEN, SM_XVIRTUALSCREEN). Le bouton Démarrer n'a pas son logo (comctl32 6, l'assemblage côte à côte
  manque).

**Le menu Démarrer s'ouvre et suit la souris : les crochets.** Avec les icônes (PR 135), un clic sur Démarrer crée
le menu (ses barres d'outils, leurs icônes, sa fenêtre CMenuDeskBar montrée au-dessus de la barre), mais le menu
restait inerte : son suivi est celui de `shell32` (CMenuFocusManager), qui pose un crochet WH_GETMESSAGE sur son
thread, prend la capture et regarde chaque message de la souris avant que GetMessage le rende (WindowFromPoint,
GetAncestor, TB_HITTEST, puis WM_USER_CHANGETRACKEDITEM à la barre d'outils sous la souris). `win32k::hook` (`hook.c`
et `callback.c` de ReactOS) : un crochet est un objet USER (`TYPE_HOOK`) dans le tas du bureau
(`abi::user::Hook32`, dont CallNextHookEx de `user32` lit `phkNext`, `HookId` et `Ansi`), dans la chaîne de son
thread et de son type, ou dans celle du bureau pour un crochet global ; `fsHooks` dans le `CLIENTINFO` et le
`DESKTOPINFO` (`user32` le teste : CallMsgFilter) ; NtUserSetWindowsHookEx (les refus de ReactOS),
NtUserSetWindowsHookAW, NtUserUnhookWindowsHookEx, NtUserCallNextHookEx (le crochet courant du thread et
`phkCurrent`), NtUserCallMsgFilter ; la procédure appelée par `user32` (USER32_CALLBACK_HOOKPROC, le MSG après
HOOKPROC_CALLBACK_ARGUMENTS, relu pour WH_GETMESSAGE). WH_GETMESSAGE est appelé par `queue::peek` (PeekMessage,
GetMessage et les boucles du noyau, comme co_IntGetPeekMessage), WH_SYSMSGFILTER puis WH_MSGFILTER par la boucle des
menus (MSGF_MENU) ; les autres types se posent sans être appelés (journalisé une fois par type). Un crochet part avec
le thread qu'il accroche, avec celui qui l'a posé (ReactOS : le premier seul) ou avec son processus. Et ce que le
crochet du menu demande : NtUserWindowFromPoint (`win32k::mouse::window_from_point`, co_WinPosSearchChildren : une
fille transparente à la souris, désactivée ou cachée laisse le point à son parent, le bureau hors de toute fenêtre),
NtUserGetAncestor (`win32k::window::ancestor`), NtUserGetForegroundWindow et SetForegroundWindow (NtUserCallHwndLock
0x5B : la fenêtre de premier niveau activée). Dans la VM, le menu s'ouvre, le survol de « Programs » ouvre son
sous-menu et un clic exécute l'item. La première ouverture prenait 55 s dans VirtualBox : `shell32` ouvre
`shell32.dll` (11 Mio) comme fichier de données pour chaque icône, et NtCreateSection relisait le fichier entier, une
commande ATA par secteur (14 fois, 55,2 s) ; la branche `claude/file-read-speed` (le partage des octets d'un fichier
entre ses sections, `io::section_cache`) la ramène à 75 ms. Les suivantes sont immédiates (0,13 s) ; le sous-menu de
« Programs », dont le dossier est vide, s'ouvre sans son item « (Empty) » dessiné, à vérifier. Un item de dossier tue encore `explorer` : la fenêtre de dossier que `browseui`
crée échoue (CreateWindowEx rend 0) juste après la création d'une barre de défilement (le contrôle, dont
SetScrollInfo(SB_CTL) rend 0 : pas encore SB_CTL), puis une assertion (`int 3`, 80000003, NtRaiseHardError absent)
arrête le processus ; à diagnostiquer. Pas encore, vus en chemin : NtUserTrackMouseEvent, SPI_GETMENUSHOWDELAY
(0x6A : le sous-menu s'ouvre sans délai), NtUserGetDoubleClickTime, NtUserCallNoParam 9, NtUserGetThreadState 0xB,
Ctrl+Échap (RegisterHotKey).

## La suite

Le premier critère du M6 est atteint ; restent le changement de résolution (troisième critère : `bochs-dispi`,
ChangeDisplaySettings, le panneau Affichage). Pour le shell : la fenêtre de dossier qu'ouvre un item du menu Démarrer
(la barre de défilement contrôle, SB_CTL, puis ce que `browseui` demande ensuite) ; Ctrl+Échap et les raccourcis
(RegisterHotKey) ; la zone de travail (SPI_SETWORKAREA), FindWindowEx, SetParent, TrackMouseEvent ; le papier peint
(SPI_SETDESKWALLPAPER), la station des services, le presse-papiers, les notifications, `NtNotifyChangeKey`.

## Tests

Hôte : `se` (un jeton créé tel qu'on l'a donné, le propriétaire et le groupe principal refusés, un jeton d'emprunt
d'identité créé, la copie « effective only »), `cm` (une ruche montée sous une clé virtuelle ouverte, refusée sous une
clé de ruche, déchargée puis rechargée), `ex` (les paramètres de l'utilisateur suivent ceux du système jusqu'à être
fixés). Scénario `logon` : les marqueurs du profil chargé (`IncrementRefCount(S-1-5-21-…)`), de la session ouverte
(« We are logged on »), de `userinit` (son thread converti), d'`explorer` (son thread converti, `desktop.cpp:193`, sa
barre des tâches à l'écran : deux pixels) ; chaque échec traversé est interdit (NtCreateToken, LsaLogonUser, le
profil, RegLoadKeyW, ImpersonateLoggedOnUser, l'assignation du jeton, CreateProcessAsUserW, « Failed to start default
shell »), et la fin d'`explorer` (`(explorer.exe) ended`). Neuf mutations (chacun des sept services ou classes
retiré, la valeur `Locale` de la couche, les droits d'une copie à `DesiredAccess` nul) font échouer le scénario ;
l'ancien NtUserGetAtomName aussi (`explorer` meurt). Hôte : `win32k::atom` (« #n » d'un atome entier, la copie bornée
par `MaximumLength` avec son nul). Scénario `send-messages` : SendMessageW(NULL) rend 0 et
`ERROR_INVALID_WINDOW_HANDLE`, la pile salie d'un motif avant l'appel (l'ancien service rend ce motif, 0x5EEDBEEF).
Scénario `activate-app`, étapes 4 et 5 : SetWindowPos d'une fenêtre active dont une fille a le focus ne lui envoie
pas WM_ACTIVATE et laisse le focus à la fille ; une fenêtre dont WM_ACTIVATE donne le focus à sa fille le lui laisse
(l'ancien `activate` échoue aux deux). `notepad-save` va de nouveau au bout, la vue de dossier créée. Scénario
`msg-wait` (`msgwait1.c`) : MsgWaitForMultipleObjects expire sur une file vide, se réveille pour un message posté
par un autre thread, attend un thread et un événement comme `explorer`, puis encore après WaitMessage ; sans
GETINPUTEVENT, chaque attente rend WAIT_FAILED. Scénario `zorder` (`zorder1.c`) : deux fenêtres qui se
chevauchent, celle du dessus envoyée au fond sans bouger ; la capture montre la première repeinte dans le
chevauchement (l'ancien calcul y laisse la seconde). Hôte : `win32k::winsta` (une station prend un seul shell,
jusqu'à la destruction de sa fenêtre). Scénario `logon` : `Documents and Settings\Administrator\Desktop` parcouru,
`desktop.cpp:193` et `atlcomcli.h` interdits, la barre des tâches visible au-dessus du bureau (ses deux pixels, que
le bureau recouvrait sans SetShellWindowEx), « no startup desktop » interdit pour `userinit` et `explorer`. Scénario
`paint-desktop` (`paintdsk1.c`) : un DC en mémoire peint en blanc prend la couleur du bureau par PaintDesktop et
garde son pinceau ; une fenêtre dont WM_ERASEBKGND appelle PaintDesktop montre cette couleur (sans le service, le
blanc reste). Scénario `dc-reset` (`dcreset1.c`) : le DC gardé d'une fenêtre passée sous une autre ne peint plus
sur elle, ni à son ancienne place une fois déplacée ; le programme lit l'écran (l'ancien DC faisait les deux).
Hôte : `ob` (le premier handle d'un type), `win32k::startup` (la station d'un chemin sans station),
`win32k::desktop` (le pinceau d'une classe).
Scénario `defer-window-pos` (`defer1.c`, AMD et Intel) : BeginDeferWindowPos(-1) refusé ; un lot de trois
déplacements, le troisième fondu dans le premier, chacun rendant le lot, EndDeferWindowPos place les deux fenêtres ;
le lot fini refusé (`ERROR_INVALID_DWP_HANDLE`) ; un drapeau inconnu, SWP_ASYNCWINDOWPOS et le bureau refusés, un lot
vide fini ; SetWindowRgn(NULL) met la fenêtre en tête ; RemoveProp rend la donnée puis plus rien. Quatre mutations
(sans la routine BEGINDEFERWNDPOS, SetWindowRgn qui garde le rang, RemoveProp sans republier la liste, les drapeaux
du lot non vérifiés) le font échouer. Hôte : `win32k::deferpos` (la fusion de deux déplacements). Scénario `logon` :
le bouton Démarrer à l'écran (ses bords gauche et droit), « BeginDeferWindowPos failed » interdit. Puis, avec les
icônes : un clic sur Démarrer (`keys`, la souris de QEMU) et le menu ouvert au-dessus du bouton (sa face, son bord
droit, le bouton enfoncé ; `screen-wait = 120`, une option de `xtask` : l'écran capturé de nouveau chaque seconde
jusqu'à montrer les pixels) ; `minoinit` enregistre `browseui` et `shell32` (0).

Les apitests de `ntdll` (scénario `rostests`) restent à 43 sur 84, le plancher, mais pas les mêmes : NtDuplicateToken
(un `NewTokenHandle` nul : `STATUS_ACCESS_VIOLATION`, la poignée écrite d'abord, comme ProbeForWriteHandle) et
NtOpenThreadToken passent ; NtAccessCheck et NtAccessCheckByTypeResultList, qui passaient en se sautant faute de
NtDuplicateToken (GetToken), vont maintenant jusqu'à NtAccessCheck, pas encore là (SeAccessCheck, ADR-011).
NtSetDefaultLocale de l'utilisateur rend `STATUS_OBJECT_NAME_NOT_FOUND` pour un LCID que `Nls\Locale` ne connaît
pas, comme l'apitest l'attend d'XP (ExpValidateNlsLocaleId : la valeur introuvable) ; un groupe de langues absent
reste `STATUS_INVALID_PARAMETER`.

Scénario `hooks` (`tests/native/hook1.c`, AMD et Intel) : les refus de SetWindowsHookEx, WH_GETMESSAGE (le code, le
message sorti ou non, changé par le crochet), deux crochets dans l'ordre et CallNextHookEx, UnhookWindowsHookEx deux
fois, CallMsgFilter avec et sans crochet, WH_MSGFILTER dans TrackPopupMenu (MSGF_MENU, le message traité finit le
menu), un crochet sur un autre thread (appelé dans ce thread, rendu à sa fin), GetAncestor, WindowFromPoint (filles
transparente, désactivée, cachée ; le bureau), SetForegroundWindow et GetForegroundWindow. Sept mutations le font
échouer : WH_GETMESSAGE ou MSGF_MENU retiré, crochets gardés à la fin du thread, le dernier posé appelé le dernier,
`fsHooks` non publié, HTTRANSPARENT ignoré, SetForegroundWindow sur la fille elle-même. Hôte : `win32k::hook`.
