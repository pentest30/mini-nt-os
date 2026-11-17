# M6 : les fenêtres, avec le vrai `user32`

Observations du début du M6 ([05](../05-feuille-de-route.md#m6--win32k-avec-le-spike-s3-en-premier)) : ce que fait un
programme Win32 de test, lié au `user32` de ReactOS 0.4.16, quand il enregistre des classes et crée des fenêtres sur
le win32k de Mino. À mettre à jour à chaque étape.

## Le banc d'essai : `GUI1.EXE` à la place de `winlogon.exe`

`winlogon` s'arrête avant sa première fenêtre (son serveur RPC demande les tubes nommés, puis viennent `services`,
`lsass` et `msgina` : [`m5-csrss.md`](m5-csrss.md)). Le scénario `gui` donne donc à `smss` un autre programme à lancer
comme commande initiale : `tests/native/gui1.c`, compilé par MinGW (sous-système WINDOWS 5.1, sans runtime C, entrée
`GuiStartup`), lié à `ntdll`, `kernel32` et `user32` par des bibliothèques d'importation tirées de
`tests/native/*.def`. La clé `initial-command = GUI1.EXE` du scénario le met sur le disque à la place de
`WINDOWS\SYSTEM32\WINLOGON.EXE` (`xtask`, `put_initial_command`). `smss` le lance comme il lancerait `winlogon`,
`csrss` en fait un processus CSR, et son `user32` se connecte à `csrss` et à win32k comme celui de `winlogon` (dont
le rappel ClientThreadSetup).

Comme `winlogon`, le programme s'inscrit comme processus de logon (RegisterLogonProcess), crée `WinSta0` et le bureau
`Default`, s'y place et y passe (SwitchDesktop : le fond du bureau est peint). Chaque étape, et chaque message que
reçoit sa procédure de fenêtre, va au port de débogage (`DbgPrint`), où le scénario les cherche ; il se termine avec
un statut qui dit où il s'est arrêté.

## Étape 1 : les classes de fenêtres

`RegisterClassExW` de `user32` enregistre d'abord ses contrôles du système (RegisterSystemControls : Button, ListBox,
Edit, Static, Ghost… avec leur FNID et `CS_GLOBALCLASS`), puis la classe demandée, par NtUserRegisterClassExWOW.
Pour chacun, `LoadCursorW` cherche un curseur partagé (NtUserFindExistingCursorIcon) puis en crée un (NtGdiOpenDCW) :
ces services manquent, la classe n'a pas de curseur, et l'enregistrement continue.

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::atom` | la table des atomes de USER (gAtomTable), aux règles de RtlAddAtomToAtomTable : atome entier (de 1 à `0xBFFF`, ou `#` et des chiffres) sans entrée ; nom en chaîne de 255 caractères au plus, atome à partir de `0xC000`, le même sans tenir compte de la casse, compte de références, place réutilisée |
| `win32k::class` | les classes privées et publiques de chaque processus (les plus récentes d'abord) ; à son premier enregistrement, les classes du système à procédure du serveur (bureau, menus, sélecteur de tâches, barres de défilement, titres d'icônes, fenêtres de messages) ; deux atomes par classe (nom et version) ; une procédure du client qui est celle d'une classe à procédure du serveur donne cette procédure (`CSF_SERVERSIDEPROC`) ; la recherche de CreateWindowEx (privée de l'instance, publique, puis celles de `user32`) ; le `CLS` dans le tas de chaque bureau où la classe aura une fenêtre |
| NtUserRegisterClassExWOW (`sys::class`) | les refus de ReactOS (drapeau autre que `CSF_ANSIPROC` : `ERROR_INVALID_FLAGS` ; taille de `WNDCLASSEXW`, longueurs impaires, octets de plus négatifs ou qui débordent, instance nulle, nom vide qui n'est pas un atome : `ERROR_INVALID_PARAMETER`) ; une classe privée de la même instance, ou publique, du même nom : `ERROR_CLASS_ALREADY_EXISTS` ; rend l'atome du nom |
| NtUserGetClassInfo (`sys::class`) | le `WNDCLASSEXW` de la classe que CreateWindowEx trouverait (instance nulle : celle de `user32`), procédure vue par le client (ANSI ou non), `CS_GLOBALCLASS` ôté d'une classe à FNID ; rend l'atome du nom ; sans classe : `ERROR_CLASS_DOES_NOT_EXIST` |

Le programme enregistre sa classe (atome `0xC00A`, après celles des contrôles), la retrouve telle qu'il l'a donnée
(`GetClassInfoExW`), retrouve la classe Button de `user32` (globale, mais sans `CS_GLOBALCLASS` puisqu'elle a un
FNID), ne trouve pas une classe jamais enregistrée (1411) et ne peut pas enregistrer la sienne deux fois (1410). Il
s'arrêtait ensuite à NtUserCreateWindowEx (étape 2).

Écarts : ni objets curseur et icône (les handles sont gardés, `spicn` et `spcur` restent nuls), ni pinceaux (un
pinceau du système vaut sa couleur plus un, comme pour la classe du bureau) ; le nom de menu reste dans le client
(les pointeurs de `CLSMENUNAME`) ; le compte des fenêtres d'une classe n'est pas tenu dans le `CLS` ; pas de
`atomSysClass` dans le `SERVERINFO` ; ni désenregistrement (NtUserUnregisterClass), ni procédures d'appel (une
classe Unicode demandée en ANSI rend sa procédure, journalisé une fois).

Tests : hôte (`win32k::atom` : casse, atomes entiers, longueurs, références et réutilisation ; `win32k::class` :
recherche par nom et par atome, instance, classes globales, celles de `user32` en dernier, refus d'un double,
atomes rendus, classes du système une fois, procédure du serveur reprise) ; le scénario `gui`, sur les deux CPU.

## Étape 2 : NtUserCreateWindowEx, et les messages de la création

`CreateWindowExW` de `user32` cherche d'abord la classe (`GetClassInfoExW`, pour son menu), puis appelle
NtUserCreateWindowEx. Comme `co_UserCreateWindowEx` de ReactOS (`window.c`, `message.c`, `callback.c`, comme
spécification), win32k (`win32k::window::create_window`) :

1. trouve la classe par le nom de sa version (`ERROR_CANNOT_FIND_WND_CLASS`), le parent (la fenêtre du bureau, ou
   celle que donne une fenêtre fille ; une fenêtre fille sans parent : `ERROR_TLW_WITH_WSCHILD`) et le propriétaire
   (d'une fenêtre qui n'est pas fille : la fenêtre de premier niveau du parent donné) ;
2. corrige la place (IntFixWindowCoordinates : `CW_USEDEFAULT` d'une fenêtre qui n'est pas recouvrante vaut 0 ; une
   recouvrante, sans moniteur, prend 0, 0, 800 × 600, comme ReactOS sans moniteur) ; une fenêtre fille se place dans
   la zone cliente de son parent ;
3. crée le `WND` dans le tas du bureau (octets de plus de la classe compris), son handle (`TYPE_WINDOW`, le
   `THREADINFO` du thread), le `CLS` de la classe sur ce bureau, le nom dans le tas ; corrige les styles
   (`WS_VISIBLE` ôté, `WS_CLIPSIBLINGS` pour une fenêtre qui n'est pas fille, `WS_CAPTION` pour une recouvrante,
   `WS_EX_WINDOWEDGE` d'après le cadre, `WNDS_SENDSIZEMOVEMSGS` pour une recouvrante) ; les `WNDS2_*` de
   compatibilité d'après la version qu'attend le module ; la procédure de la classe (celle d'un contrôle, dans le jeu
   de caractères de la fenêtre) ;
4. envoie WM_NCCREATE (refusé : pas de fenêtre), lie la fenêtre parmi les enfants de son parent (en haut de l'ordre
   Z, une fille en bas), envoie WM_NCCALCSIZE (la zone cliente, ramenée dans la fenêtre), WM_CREATE (-1 : pas de
   fenêtre), puis WM_SIZE et WM_MOVE à une fenêtre qui n'attend pas d'être montrée, et WM_PARENTNOTIFY au parent
   d'une fenêtre fille (sauf `WS_EX_NOPARENTNOTIFY`) ;
5. donne la fenêtre à son thread (elle vit autant que lui) ; rend son handle, l'erreur Win32 remise à 0.

Un message envoyé à une fenêtre du thread courant dont la procédure est dans le client va à `user32` par
KeUserModeCallback (USER32_CALLBACK_WINDOWPROC, `WINDOWPROC_CALLBACK_ARGUMENTS` suivi du `lParam` emballé, repris
pour un message qui y écrit) ; pendant le rappel, le `CLIENTINFO` du thread désigne la fenêtre (`CallbackWnd` : son
handle, son `WND` dans la vue du processus). Le `CREATESTRUCT` de WM_NCCREATE et WM_CREATE est emballé comme
PackParam : ses chaînes à la suite, leurs positions à la place des pointeurs, `A` et l'atome ou `S` et le nom de la
classe ; `user32` le déballe (MsgiKMToUMMessage). NtUserDefSetText (DefWindowProc sur WM_NCCREATE et WM_SETTEXT)
change le nom, à sa place s'il y tient ; un texte ANSI garde son ASCII (le reste devient `?`, journalisé).

Le programme crée une fenêtre `WS_POPUP` de 400 × 300 en (100, 50) : sa procédure reçoit WM_NCCREATE et WM_CREATE
avec le `CREATESTRUCT` donné (paramètre, nom, classe, place, style), et, pendant WM_CREATE, son `CLIENTINFO` désigne
la fenêtre et son `WND` (dont le premier mot est le handle) ; elle reçoit, dans l'ordre, `0081 0083 0001 0005 0003`.
`user32` lit lui-même dans son `WND` son nom (`GetWindowTextW`, par WM_GETTEXT à DefWindowProc), son style corrigé
(`84000000`) et son rectangle ; `SetWindowTextW` change le nom (plus long : un bloc neuf ; plus court : à sa place).
Une fenêtre fille (`WS_CHILD`, identifiant 7, en (10, 20) dans la fenêtre) reçoit les mêmes messages, et son parent
WM_PARENTNOTIFY (WM_CREATE, 7, la fille) ; `GetParent` et `GetWindow(GW_CHILD)` suivent les liens des `WND`, et la
fille est en (110, 70). Une fille sans parent (1406), une fenêtre d'une classe inconnue (1407) et une fenêtre dont la
procédure refuse WM_NCCREATE ne sont pas créées. Le programme va au bout (statut `0x600D`).

Ce qui manque, journalisé une fois : la partie noyau de DefWindowProc et WM_GETMINMAXINFO (étape 3), montrer une
fenêtre créée visible (ShowWindow, SetWindowPos), les menus (une fenêtre
qui n'est pas fille ne peut pas en recevoir : `ERROR_INVALID_MENU_HANDLE`), les fenêtres de messages (`HWND_MESSAGE`),
les messages envoyés à un autre thread, DestroyWindow (les fenêtres d'un thread vivent autant que lui ; une création
qui échoue ne reçoit ni WM_DESTROY ni WM_NCDESTROY : fait à l'étape 14), les crochets (`WH_CBT`), une fenêtre créée
réduite ou agrandie.

Tests : hôte (`win32k::window` : `CREATESTRUCT` emballé, styles d'une fenêtre neuve, place par défaut, compatibilité,
zone cliente ramenée dans la fenêtre) ; le scénario `gui`, sur les deux CPU.

Correction (étape 3) : NtUserCreateWindowEx lisait le bit `bAnsi` des `LARGE_STRING` de la classe et de sa version.
`user32` n'y pose que `MaximumLength` : le bit est ce qui restait sur sa pile, et une classe pouvait ne pas être
trouvée (1407), selon les appels précédents. Comme ProbeAndCaptureLargeString, la capture l'ignore maintenant (le nom
de la fenêtre aussi : CreateWindowExA le convertit en Unicode sans ôter le bit) ; seul NtUserDefSetText le lit.

## Étape 3 : les métriques du système et DefWindowProc du noyau

`user32` lit lui-même les métriques du système (`GetSystemMetrics`) et les couleurs système (`GetSysColor`) dans le
`SERVERINFO` de la section partagée, `aiSysMet` (en `0x5CC`) et `argbSystem` (en `0x7BC`) : les positions viennent du
`user32` épinglé. Pour les messages qu'il ne traite pas lui-même (WM_NCCALCSIZE, WM_NCPAINT, WM_SETCURSOR,
WM_SYSCOMMAND…), son DefWindowProc appelle NtUserMessageCall avec `FNID_DEFWINDOWPROC`. Comme ReactOS (`metric.c`,
`stockobj.c`, `defwnd.c`, `nonclient.c`, `winpos.c`, `message.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::metrics` | InitMetrics avec les valeurs par défaut de ReactOS sans profil d'utilisateur (titre de 19 + 1, bordure de 1, barres de défilement de 16, menus de 18…) et le mode de l'écran (640 × 480 sans affichage) ; les 31 couleurs système de ReactOS ; écrites dans le `SERVERINFO` quand `csrss` initialise win32k (InitVideo), gardées pour les calculs du noyau (UserGetSystemMetrics) |
| `win32k::defwnd` | IntDefWindowProc : WM_NCCALCSIZE (NC_HandleNCCalcSize : bordures d'après UserHasWindowEdge et UserGetWindowBorders, titre ou petit titre, bord client, barres de défilement, à gauche aussi ; avec des rectangles valides, `WVR_VALIDRECTS` et les `WVR_*REDRAW` de la classe ; les `WNDS_HAS*` gardés dans le `WND`) ; WM_DEVICECHANGE rend TRUE, un message au-delà de WM_USER 0 ; les valeurs par défaut de WM_GETMINMAXINFO (co_WinPosGetMinMaxInfo : IntGetWindowBorders, taille et place agrandies, suivi entre SM_CXMINTRACK et SM_CXMAXTRACK) |
| NtUserMessageCall (`sys::message`) | `FNID_DEFWINDOWPROC` : la fenêtre (`hWnd` nul permis ; inconnue : FALSE, `ERROR_INVALID_WINDOW_HANDLE`), le résultat dans `ResultInfo`, TRUE ; une structure illisible ou un `ResultInfo` où l'on ne peut écrire : FALSE (ReactOS n'a pas de garde autour de ce traitement) ; les autres types : FALSE et `ERROR_CALL_NOT_IMPLEMENTED`, journalisés une fois chacun |
| `win32k::window::create_window` | WM_GETMINMAXINFO avant WM_NCCREATE, à une fenêtre recouvrante ou à cadre épais ; sa taille est ramenée entre le suivi minimal et maximal que laisse la procédure (le minimum l'emporte) |

Le programme lit l'écran (1280 × 800), le titre (20), le cadre (4), la largeur minimale (112) et trois couleurs
(fond du bureau `a56e3a`, fenêtre `ffffff`, boutons `c8d0d4`). Une fenêtre `WS_OVERLAPPEDWINDOW` (`CW_USEDEFAULT`)
reçoit `0024 0081 0083 0001` (pas encore WM_SIZE ni WM_MOVE : elle attend d'être montrée) ; WM_GETMINMAXINFO lui
donne 1288 × 808 en (−4, −4) agrandie, un suivi de 112 × 28 à 1292 × 812 ; elle est en 0, 0, 800 × 600 (ReactOS
sans moniteur), sa zone cliente fait 792 × 572 (4 de bordure, 20 de titre) et son `WND` a `WNDS_HASCAPTION` pendant
WM_CREATE. DefWindowProcW de WM_NCCALCSIZE avec des rectangles valides rend `0x400` et la zone cliente du premier.
Des fenêtres `WS_POPUP | WS_CAPTION | WS_THICKFRAME` créées trop petites, trop grandes, ou avec un minimum que leur
procédure relève (300 × 200), ont la taille permise ; elles sont créées avec des uns sur la pile, que `user32` laisse
dans le bit `bAnsi` du nom de la classe.

Ce qui manque, journalisé une fois : les autres messages de DefWindowProc (peinture du cadre, WM_NCHITTEST,
WM_SETCURSOR, WM_SYSCOMMAND, WM_CLOSE, les touches… : ils attendent les contextes de périphérique, le
positionnement et l'entrée), le texte ANSI de DefWindowProcA, les autres types de NtUserMessageCall (SendMessage et
ses variantes, la barre de défilement, le bureau, les menus) ; ni moniteur (étape 4), ni profil d'utilisateur pour
les métriques (`HKCU\Control Panel\Desktop\WindowMetrics`), ni SystemParametersInfo, ni menus (`WNDS_HASMENU`).

Tests : hôte (`win32k::metrics` : les métriques d'un écran 1280 × 800, le fond du bureau ; `win32k::defwnd` :
bords en relief, zone cliente d'une fenêtre recouvrante, bordure fine, bord client, barres de défilement, titre
d'outil, fenêtre réduite, WM_GETMINMAXINFO de cadres divers) ; le scénario `gui`, sur les deux CPU.

## Étape 4 : le moniteur, et SetWindowPos

Comme ReactOS (`monitor.c`, `window.c`, `winpos.c`, `defwnd.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::monitor` | un moniteur principal, de la taille de l'écran, attaché avec les métriques quand il y a un affichage (co_IntInitializeDesktopGraphics) : handle USER (`TYPE_MONITOR`), rectangle et zone de travail, le compte des fenêtres placées en cascade (`cWndStack`) ; le moniteur d'un rectangle (`MONITOR_DEFAULTTONULL`, `…TOPRIMARY`, `…TONEAREST`) |
| NtUserMonitorFromWindow, NtUserMonitorFromRect, NtUserMonitorFromPoint, NtUserGetMonitorInfo (`sys::monitor`) | `dwFlags` inconnu : `ERROR_INVALID_FLAGS` ; un rectangle vide compte pour son coin ; `MONITORINFO` ou `MONITORINFOEXW` (nom `\\.\DISPLAY1`), une autre taille : `ERROR_INVALID_PARAMETER` ; un moniteur inconnu : `ERROR_INVALID_MONITOR_HANDLE` |
| `win32k::window::fix_coordinates` | IntFixWindowCoordinates sur un moniteur : `CW_USEDEFAULT` donne à une fenêtre recouvrante la place du `STARTUPINFO` (`STARTF_USEPOSITION`) ou la suivante d'une cascade (un bouton de titre et un cadre plus loin, recommencée au-delà du quart de la zone de travail), et sa taille (`STARTF_USESIZE`) ou les trois quarts de la zone ; `CW_USEDEFAULT` sur 16 bits vaut -32768 (corrigé : 32768 l'était aussi) |
| `win32k::window::min_max_info` | co_WinPosGetMinMaxInfo, pour la création et SetWindowPos : valeurs par défaut, WM_GETMINMAXINFO, puis ce que la procédure a laissé s'adapte à la zone de travail (`WNDS_MAXIMIZESTOMONITOR`) |
| `win32k::winpos` | co_WinPosSetWindowPos : WM_WINDOWPOSCHANGING (la procédure peut changer la demande), les nouveaux rectangles, WinPosFixupFlags (ce qui ne change pas, une fenêtre de premier niveau qui s'active monte en haut), WM_NCCALCSIZE avec des rectangles valides, l'ordre Z, les enfants déplacés avec la zone cliente, `WS_VISIBLE` (`SWP_SHOWWINDOW`, `SWP_HIDEWINDOW`), WM_CHILDACTIVATE à une fenêtre fille qui s'active, WM_WINDOWPOSCHANGED (sauf pour une fenêtre invisible dont seul le rang change) |
| `win32k::window::link` | IntLinkHwnd : en haut sous les fenêtres au premier plan, en bas, au premier plan (`HWND_TOPMOST`, `WS_EX_TOPMOST`), hors du premier plan (`HWND_NOTOPMOST`), après une sœur |
| `win32k::defwnd` | WM_WINDOWPOSCHANGING : la taille demandée ramenée dans les limites de WM_GETMINMAXINFO ; WM_WINDOWPOSCHANGED : WM_MOVE (zone cliente dans celle du parent d'une fenêtre fille, sinon à l'écran) et WM_SIZE si elle a bougé ou changé |
| NtUserSetWindowPos, NtUserMoveWindow (`sys::window`) | une fenêtre, ou une sœur `hWndInsertAfter`, qui n'existe pas : `ERROR_INVALID_WINDOW_HANDLE` ; la fenêtre du bureau : FALSE ; coordonnées sur 16 bits, tailles de 0 à 32767 ; MoveWindow : sans ordre Z ni activation |

Le `WINDOWPOS` de WM_WINDOWPOSCHANGED donne la place dans la zone cliente du parent, comme le dit l'API (ReactOS y met
des coordonnées d'écran, les mêmes pour une fenêtre de premier niveau).

Le programme trouve le moniteur de sa fenêtre (0, 0, 1280 × 800, zone de travail identique, principal,
`\\.\DISPLAY1`), aucun loin de l'écran sauf le plus proche, et `ERROR_INVALID_FLAGS`. Sa fenêtre recouvrante
(`CW_USEDEFAULT`) est en 0, 0, 960 × 600 (zone cliente 952 × 572, `WNDS_MAXIMIZESTOMONITOR`), la suivante en 23, 23.
SetWindowPos la déplace en (50, 60) en 400 × 300 : `0046 0024 0083 0047 0003 0005`, le `WINDOWPOS` final (drapeaux
`0x1c`), WM_MOVE (54, 84), WM_SIZE 392 × 272 ; trop petite, elle prend 112 × 28 ; déplacée seulement,
`0046 0047 0003` ; MoveWindow la place en (100, 100), 300 × 200. Une fenêtre déplacée emmène sa fille ; la fille
déplacée reçoit `0046 0022 0047 0003` et WM_MOVE (20, 30) dans son parent. Deux fenêtres cachées changent de rang
(en haut, en bas, après l'autre, au premier plan puis hors de lui ; une seule reçoit `0046`), sont montrées et
cachées (`IsWindowVisible`). SetWindowPos d'une fenêtre inconnue, ou après elle : FALSE, 1400.

Correction : la numérotation des services de win32k. `tools/syscall-gen` suivait `w32ksvc32.h` sans `DBG` ; les
binaires publiés de ReactOS sont construits avec : cinq services de plus avant `NtGdiMakeObjectXferable`, et les 26
derniers numéros décalés (MonitorFromWindow de `user32` tombait sur `NtGdiDdDDICreateAllocation`). Les 1770 stubs
de `ntdll`, `user32` et `gdi32` s'accordent maintenant avec les tables, et `syscall-gen --check` (`cargo xtask lint`)
les vérifie quand l'espace utilisateur a été téléchargé.

Ce qui manque, journalisé une fois : les régions visibles (une fenêtre est visible avant si elle et ses parents le
sont et qu'elle n'est pas vide), repeindre ce qui a bougé et la copie des bits valides, l'activation et le premier
plan (aucune fenêtre n'y est ; une fenêtre de premier niveau qui s'active monte seulement en haut), garder les
fenêtres possédées au-dessus de leur propriétaire (WinPosDoOwnedPopups), `SWP_ASYNCWINDOWPOS` (fait tout de suite),
plusieurs moniteurs et la zone de travail réduite, DeferWindowPos, une fenêtre réduite ou agrandie.

Tests : hôte (`win32k::monitor` : le moniteur d'un rectangle, la cascade ; `win32k::window` : places par défaut sans
moniteur et sur un moniteur, `STARTUPINFO`, `CW_USEDEFAULT` sur 16 bits ; `win32k::defwnd` : limites de
WM_WINDOWPOSCHANGING, adaptation à la zone de travail ; `win32k::winpos` : drapeaux corrigés, rang déjà tenu,
activation, nouveaux rectangles ; `syscall-gen` : les stubs trouvés et vérifiés, les stubs du moniteur qui demandent
`DBG`) ; le scénario `gui`, sur les deux CPU.

## Étape 5 : ShowWindow

`ShowWindow` de `user32` appelle directement NtUserShowWindow. Comme co_WinPosShowWindow de ReactOS (`winpos.c`,
`window.c`, `main.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::winpos::show_window` | la commande du `STARTUPINFO` du processus (`STARTF_USESHOWWINDOW`, lu de ses paramètres au premier besoin) pour sa première fenêtre recouvrante à titre et sans propriétaire, et pour `SW_SHOWDEFAULT`, une seule fois ; les drapeaux de SetWindowPos de la commande (`show_command`) ; WM_SHOWWINDOW si la visibilité change (ou `SW_SHOWNA`) ; SetWindowPos (en haut, ou au premier plan) si ses parents sont visibles, sinon `WS_VISIBLE` seul ; puis WM_SIZE et WM_MOVE qui attendaient (`WNDS_SENDSIZEMOVEMSGS`, co_WinPosSendSizeMove) ; rend si elle était visible |
| `win32k::window::create_window` | une fenêtre créée avec `WS_VISIBLE` est montrée à la fin de sa création, avec `SW_SHOW` ou, pour une fenêtre recouvrante placée par défaut, la commande passée en `y` (IntFixWindowCoordinates) |
| NtUserShowWindow (`sys::window`) | une fenêtre qui n'existe pas : `ERROR_INVALID_WINDOW_HANDLE` ; la fenêtre du bureau : FALSE ; une commande au-delà de `SW_MAX` : `ERROR_INVALID_PARAMETER` |

Le programme montre une fenêtre recouvrante (`SW_SHOWNORMAL`) : `0018 0046 0047 0005 0003` (WM_SHOWWINDOW, SetWindowPos,
puis WM_SIZE 952 × 572 et WM_MOVE en (50, 70) qu'elle attendait), elle était cachée et devient visible ; `SW_SHOW`
d'une fenêtre visible ne fait rien et rend TRUE ; `SW_HIDE` la cache (`0018 0046 0047`), puis ne fait rien. La fille
d'une fenêtre cachée reçoit WM_SHOWWINDOW et `WS_VISIBLE`, sans être visible. Une commande de 12 : 87 ; une fenêtre
inconnue : 1400. Une fenêtre recouvrante créée visible avec `SW_SHOWNOACTIVATE` en `y` reçoit
`0024 0081 0083 0001 0018 0046 0047 0005 0003` (drapeaux de son `WINDOWPOS` : `0x1857`, sans activation ni ordre Z), une
fenêtre contextuelle créée visible `0081 0083 0001 0005 0003 0018 0046 0047`.

Les fenêtres montrées n'étaient pas encore peintes à cette étape : l'écran restait le fond du bureau (étape 6).

Ce qui manque, journalisé une fois : réduire et agrandir (co_WinPosMinMaximize : les commandes qui le demandent, ou
montrer une fenêtre réduite ou agrandie, ne font rien et rendent FALSE ; le placement des fenêtres, WINDOWPLACEMENT),
la fenêtre active, le premier plan et le focus (à cacher la fenêtre active, une autre devrait l'être), les fenêtres
possédées montrées et cachées avec leur propriétaire, ShowWindowAsync, la peinture.

Tests : hôte (`win32k::winpos` : les commandes et leurs drapeaux, le `STARTUPINFO` pour la première fenêtre
recouvrante seulement, une fois ; `win32k::window` : la commande en `y`) ; le scénario `gui`, sur les deux CPU.

## Étape 6 : peindre le cadre des fenêtres

Dans ReactOS, le cadre d'une fenêtre se dessine dans le noyau : `user32` passe WM_NCPAINT à NtUserMessageCall, et
DefWindowProc (NC_DoNCPaint) dessine avec GDI sans repasser par le mode utilisateur. Le fond de la zone cliente, lui,
passe par `user32` et `gdi32` (WM_ERASEBKGND : `GetClipBox`, `FillRect`, donc SelectObject et PatBlt sur un HDC du
client) : il attend la table des handles GDI partagée et les attributs des contextes de périphérique. Comme ReactOS
(`painting.c`, `vis.c`, `nonclient.c`, `draw.c`, `winpos.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::gdi::region` | des régions, unions de rectangles disjoints : coupe à un rectangle, retrait d'un rectangle, intersection |
| `win32k::gdi::draw` | des opérations de dessin (remplissage, dégradé horizontal), faites sur une surface, décalées à l'origine d'une fenêtre et coupées à une région ; DrawEdge (bords en relief et creux, normaux ou doux, milieu, ajustement) |
| `win32k::nonclient` | NC_DoNCPaint en opérations : bord en relief (ou statique), cadre épais (`COLOR_INACTIVEBORDER`) et fin, barre de titre en dégradé (SPI_GETGRADIENTCAPTIONS, vrai par défaut : `UPM_DEFAULT`), boutons fermer, réduire et agrandir (DrawFrameControl : relief doux et face), trait sous le titre, bord client creux ; ce qu'il ne dessine pas encore |
| `win32k::paint` | VIS_ComputeVisibleRegion (coupée aux zones clientes des parents, sans les sœurs visibles au-dessus) ; IntInvalidateWindows (cadre et fond à repeindre, avec les enfants visibles) ; co_IntPaintWindows et UserSyncAndPaintWindows (WM_NCPAINT aussitôt) ; DefWindowProc de WM_NCPAINT (le cadre, dans la région visible) ; ce qu'une fenêtre découvre : le fond du bureau s'y repeint, ses sœurs sont invalidées |
| `win32k::winpos::set_window_pos` | après le déplacement : la fenêtre visible est invalidée entière (pas de copie des bits valides), ce qu'elle découvre est exposé ; une fenêtre montrée, déplacée, redimensionnée ou dont le cadre change se repeint aussitôt (WM_NCPAINT avant WM_WINDOWPOSCHANGED) |

Une fenêtre montrée reçoit maintenant `0018 0046 0085 0047 0005 0003` (WM_NCPAINT entre WM_WINDOWPOSCHANGING et
WM_WINDOWPOSCHANGED). Sur la capture de l'écran, les fenêtres « Pending » (0, 0, 200 × 100) et « Visible » (69, 69,
960 × 600) ont leur cadre : bord en relief, titre en dégradé de `808080` vers `C0C0C0` (inactives : il n'y a pas
encore de fenêtre active), trait sous le titre, boutons ; « Pending », repeinte sous « Visible » (`SWP_FRAMECHANGED` :
`0046 0083 0085 0047`), est coupée par elle. Là où était « Shown » avant d'être cachée, le bureau est repeint. La
fille encadrée d'une fenêtre à `WS_CLIPCHILDREN` est coupée à la zone cliente de son parent. « Cover », montrée puis
cachée dans « Visible », y laisse son cadre : le bureau ne repeint pas par-dessus « Visible », qui n'est pas encore
repeinte. Les zones clientes ne sont pas effacées : on voit au travers ce qui était dessous.

Ce qui manque, journalisé une fois : WM_ERASEBKGND et WM_PAINT des fenêtres du client (contextes de périphérique),
le texte du titre et les symboles des boutons (polices, ADR-013), l'icône du titre, les barres de défilement, la
fenêtre active (tout cadre est dessiné inactif), une sœur découverte ne se repeint qu'à sa prochaine invalidation (pas
encore de WM_PAINT tiré de la file des messages), les fenêtres d'un autre thread, une partie seulement du cadre
(WM_NCPAINT avec une région), les régions de fenêtre, `WS_EX_TRANSPARENT`. Le dégradé interpole chaque composante
en ligne (le moteur de ReactOS, absent des sources épinglées, peut arrondir autrement) ; le bureau, sans thread à lui,
se repeint dans le thread qui le découvre.

Tests : hôte (`gdi::region` : bandes, intersection ; `gdi::draw` : bords en relief, creux, doux, milieu, un bord
intérieur seul, dégradés, origine et coupe ; `nonclient` : cadre d'une fenêtre recouvrante, boutons, titre actif et
inactif, cadres sans titre, bords statique et client, fenêtre d'outil, couleurs de chaque partie sur une palette
codée) ; le scénario `gui`, sur les deux CPU, avec seize pixels de la capture de l'écran.

## Étape 7 : effacer la zone cliente (la table des handles GDI, les DC, PatBlt en lot)

Le fond de la zone cliente s'efface en mode utilisateur : win32k envoie WM_ERASEBKGND avec un HDC qu'il prête,
`user32` (DefWindowProc) lit le pinceau de la classe (`GetClassLongPtrW(GCL_HBRBACKGROUND)`), demande la boîte de
découpage (`GetClipBox` : NtGdiGetAppClipBox) et la remplit (`FillRect` : `GetSysColorBrush` pour une couleur du
système plus un, `SelectObject`, `PatBlt`, `SelectObject`). `gdi32` ne fait presque rien par le noyau : il vérifie
chaque handle dans la table des handles GDI que win32k lui montre en lecture seule (`PEB.GdiSharedHandleTable`),
change le pinceau du DC dans les attributs du DC (`DC_ATTR`, dans la mémoire du processus, trouvés par l'entrée de la
table) et met PatBlt en lot dans le TEB (`GdiTebBatch`), que win32k exécute au retour du rappel (KeUserModeCallback,
`BatchFlushRoutine`) ou au service suivant du thread chez lui. Comme ReactOS (`gdiobj.c`, `stockobj.c`, `dclife.c`,
`dcattr.c`, `dcobjs.c`, `bitblt.c`, `cliprgn.c`, `gdibatch.c`, `windc.c`, `painting.c`, comme spécification ; les
décalages lus dans `gdi32` et `user32` épinglés) :

| Partie | Ce qu'elle fait |
|---|---|
| `abi::gdi` | l'entrée de la table (`GDI_TABLE_ENTRY`, 16 octets), `DEVCAPS`, `DC_ATTR` (0x1D0 octets), `GDI_TEB_BATCH` (dans le TEB en 0x1D4), `GDIBSPATBLT` (0x40 octets), les types de handles, les bits de `ulDirty_`, les ROP ; `SERVERINFO.ahbrSystem` (0x838) dans `abi::user` |
| `win32k::gdi::handles` | la table : une section du fichier d'échange (les entrées, puis les capacités de l'écran), projetée en lecture seule (`SEC_NO_CHANGE`) dans chaque processus GUI ; handle = `FullUnique << 16 \| index`, dix entrées réservées ; propriétaire (PID, public ou personne) et attributs de chaque objet ; objets de stock |
| `win32k::gdi::brush` | les pinceaux pleins et nul ; ceux de stock (WHITE_BRUSH à NULL_BRUSH) et des 31 couleurs du système, publics, ces derniers dans `ahbrSystem` |
| `win32k::gdi::dc` | les DC de l'écran : région visible, origine, pinceau ; pris par un processus, ils reçoivent des attributs neufs dans des blocs de 64 Kio de sa mémoire (GdiPoolAllocate), rendus au repos ; DC_vUpdateFillBrush (`DC_BRUSH_DIRTY`), PatBlt (tout ROP3 sans source, étendues négatives), GetClipBox (complexité de la région) |
| `win32k::gdi::batch` | les appels en lot du TEB : PatBlt exécuté avec le pinceau qu'il apporte, les autres sautés (journalisés une fois) ; le lot vidé |
| `win32k::dce` | le cache des DC de fenêtres (UserGetDCEx : `DCX_USESTYLE`, coupe aux enfants et aux sœurs, `DCX_INTERSECTRGN` et `DCX_EXCLUDERGN`, origine de la zone cliente ou de la fenêtre ; UserReleaseDC) |
| `win32k::paint` | co_IntPaintWindows : après WM_NCPAINT, WM_ERASEBKGND avec un DC du cache coupé à la région à mettre à jour ; une fenêtre qui rend 0 garde son fond à effacer |
| `sys::gdi` | NtGdiPatBlt, NtGdiGetAppClipBox, NtGdiFlush ; `sys::dispatch` exécute le lot avant chaque service de win32k, Ps après chaque rappel (`ps::callback::set_gdi_batch_flush`) |
| `win32k::gdi::dib` | PatBlt d'un pinceau plein par un ROP3 sans source quelconque (PATCOPY, PATINVERT, DSTINVERT, BLACKNESS…) |

Une fenêtre montrée reçoit maintenant `0018 0046 0085 0014 0047 0005 0003` (WM_ERASEBKGND après WM_NCPAINT). Le DC
de WM_ERASEBKGND de « Visible » donne `GetClipBox` 2 (une région simple : toute la zone cliente, 952 × 572) ; celui
de « Pending », repeinte sous « Visible », 3 (un L : une région complexe, de 192 × 72) ; rendu, il ne sert plus
(`GetClipBox` 0, `PatBlt` FALSE et `ERROR_INVALID_HANDLE` par NtGdiPatBlt, `gdi32` n'y trouvant plus d'attributs).
`GetSysColorBrush(COLOR_WINDOW)` est un pinceau de stock que `GetObjectType` reconnaît par la table seule. Sur la
capture, les zones clientes sont blanches (`COLOR_WINDOW + 1`) et coupées comme les cadres : le titre de « Visible »
reste au-dessus de la zone cliente de « Pending » ; « Clipper » (`WS_CLIPCHILDREN`), effacée de nouveau
(`SWP_FRAMECHANGED`), laisse le bord de sa fille. « Cover », d'une autre classe (`COLOR_HIGHLIGHT + 1`), trace 24
traits noirs (un PatBlt chacun : plus qu'un lot n'en tient, `gdi32` appelle NtGdiFlush au vingt et unième) puis un
trait du pinceau propre du DC, blanc.

La région à mettre à jour d'une fenêtre reste un rectangle (celui qui tient ce qui a été invalidé). Une région du
noyau n'est pas normalisée en bandes : la complexité de GetClipBox se tire de son aire (un seul rectangle exactement
quand ses rectangles disjoints remplissent leur boîte), ce qui donne le résultat de ReactOS. Un appel en lot plus court
que son enregistrement finit le lot (ReactOS lirait les octets suivants). Les attributs d'un DC repris sont toujours
neufs (IntGdiCleanDC ; `DCX_NORESETATTRS` n'est pas suivi).

Ce qui manque, journalisé une fois : WM_PAINT des fenêtres du client (tiré de la file, BeginPaint, EndPaint : la
région à mettre à jour reste, effacée), NtUserGetDCEx et NtUserReleaseDC, les DC d'une fenêtre ou d'une classe
(`CS_OWNDC`, `CS_CLASSDC` : un DC du cache), le DC du parent (`CS_PARENTDC`), les autres appels en lot (PolyPatBlt,
TextOut, SelectClipRgn, suppression d'objets…), et sans journal : les DC en mémoire, les pinceaux et autres objets
créés par un client (CreateSolidBrush, NtGdiGetStockObject), les stylos (`hpen` nul), les transformations (matrices à
zéro, `MM_TEXT`), les capacités de l'écran (`DevCaps` à zéro), la suppression des objets et les objets d'un processus
rendus à sa fin, les DC dont la fenêtre bouge pendant qu'ils sont pris.

Tests : hôte (`abi::gdi` : appel en lot relu, attributs d'un DC neuf ; `gdi::handles` : types, reprises, bit de stock,
propriétaires, table pleine, ce que vérifie GdiValidateHandle ; `gdi::dc` : ROP avec source, rectangle de PatBlt,
DC_vUpdateFillBrush, boîte de découpage, blocs d'attributs ; `gdi::batch` : appels suivis, lot coupé ; `gdi::dib` :
les ROP3 sans source ; `dce` : `DCX_USESTYLE`) ; l'auto-test du noyau (scénario `smoke` : la table en lecture seule
dans le PEB, WHITE_BRUSH et le pinceau de `COLOR_WINDOW` publics) ; le scénario `gui`, sur les deux CPU, avec 32 pixels
de la capture de l'écran.

## Étape 8 : WM_PAINT, BeginPaint et EndPaint

Une fenêtre peinte jusqu'ici l'était aussitôt (cadre et fond, étape 7), mais jamais validée : sa région à mettre à
jour restait. WM_PAINT n'est pas posté dans la file : comme dans ReactOS (`painting.c`, `message.c`, `msgqueue.c`,
`defwnd.c`, comme spécification), un compte des fenêtres à peindre de chaque thread (`cPaintsReady`, `QS_PAINT` tant
qu'il n'est pas nul) dit à PeekMessage et GetMessage, une fois les messages postés et WM_QUIT sortis, de chercher la
première fenêtre du thread qui a quelque chose à peindre (IntFindWindowToRepaint : dans l'ordre Z, un parent avant
ses enfants) et de lui donner WM_PAINT, tant qu'elle n'est pas validée. `user32` passe WM_PAINT par
NtUserDispatchMessage, qui appelle la procédure ; DefWindowProc (NtUserMessageCall) fait BeginPaint et EndPaint.

| Partie | Ce qu'elle fait |
|---|---|
| `abi::user` | `PAINTSTRUCT` (64 octets), `QS_PAINT`, `WNDS_INTERNALPAINT`, `WNDS_UPDATEDIRTY`, `WNDS_PAINTNOTPROCESSED`, `WNDS2_WMPAINTSENT`, `WNDS2_STARTPAINT`, WM_PAINTICON, WM_TIMER |
| `win32k::queue` | le compte des fenêtres à peindre et `QS_PAINT` (MsqIncPaintCountQueue, MsqDecPaintCountQueue) ; PeekMessage cherche WM_PAINT quand il n'y a plus de message posté ; WaitMessage revient aussi pour `QS_PAINT` |
| `win32k::window` | chaque changement d'une fenêtre compte pour son thread si elle se met à avoir quelque chose à peindre (visible, région à mettre à jour ou `WNDS_INTERNALPAINT`) ou cesse de l'avoir ; IntDispatchMessage : WM_PAINT à la procédure, puis cadre et fond repeints si elle n'a pas appelé BeginPaint |
| `win32k::paint` | IntGetPaintMessage (filtre : la fenêtre ou l'un de ses parents, l'intervalle ; pas les messages du seul thread), IntFindWindowToRepaint, IntBeginPaint (cadre, DC du cache coupé à la région à mettre à jour, région validée, `rcPaint` par GetClipBox, WM_ERASEBKGND, cadre des enfants), IntEndPaint, DefWindowProc de WM_PAINT |
| `win32k::dce` | `DCX_INTERSECTRGN` sans région : un DC qui ne peint rien (DceUpdateVisRgn) |
| `win32k::gui` | le `THREADINFO` d'une fenêtre, par l'adresse du serveur de son thread (`pti`) |
| `sys` | NtUserBeginPaint, NtUserEndPaint, NtUserDispatchMessage |

Dans `gui`, une boucle de messages (PeekMessage, DispatchMessage) suit les fenêtres créées : `GetQueueStatus(QS_PAINT)`
vaut `00200020` avant, 0 après ; WM_PAINT va six fois, dans l'ordre Z, à « Popup », « Striped », « Clipper », sa fille
« Framed » (dont le cadre et le fond, invalidés avec ceux de son parent, se repeignent dans BeginPaint), « Visible »
(découverte par « Cover » : son cadre et son fond se repeignent, et les restes de « Cover » disparaissent de la
capture), puis « Pending ». Le popup se peint lui-même entre BeginPaint et EndPaint (un carré noir) : `rcPaint` est sa
zone cliente, `fErase` 0 (son fond déjà effacé) ; le DC rendu par EndPaint, PatBlt le refuse. PeekMessage ne donne
WM_PAINT qu'au filtre qui le demande : la fenêtre ou un de ses parents (une autre fenêtre : rien tant que le popup, au
premier plan, est à peindre), pas les messages du seul thread, pas un intervalle au-delà de WM_PAINT.

Un écart avec ReactOS : le compte des fenêtres à peindre est tenu à chaque changement d'une fenêtre (`window::change`),
y compris quand elle se cache ou se montre ; il reste exact, et IntGetPaintMessage n'a pas à le remettre à zéro quand
il ne trouve plus de fenêtre (ReactOS le fait, avec un message d'erreur, une fenêtre cachée gardant sa région).

Ce qui manque : InvalidateRect, ValidateRect, RedrawWindow, UpdateWindow, GetUpdateRect et GetUpdateRgn (les régions
à mettre à jour ne viennent que du noyau), WM_SYNCPAINT, WM_TIMER et les procédures de minuterie de DispatchMessage
(journalisé une fois), le curseur caché pendant BeginPaint, le dessin de l'icône d'une fenêtre réduite. Sans test (des
mutations qui les retirent survivent) : une procédure qui ne fait pas BeginPaint pour WM_PAINT (son cadre et son fond
repeints par IntDispatchMessage ; elle reçoit WM_PAINT de nouveau, comme dans ReactOS), le cadre des enfants repeint
par BeginPaint (aucun enfant de `gui` n'a son seul cadre à repeindre), le DC de BeginPaint coupé à la région à mettre
à jour (elle couvre toujours toute la zone cliente), WM_PAINT réservé aux fenêtres du thread (`gui` n'a qu'un thread
GUI).

Tests : hôte (`queue` : compte et `QS_PAINT` ; `paint` : fenêtre à peindre, filtre de WM_PAINT ; `dce` : coupe d'un
DC ; `gui` : thread d'une adresse du serveur ; `abi::user` : `PAINTSTRUCT`) ; le scénario `gui`, sur les deux CPU, avec
les fenêtres peintes par la boucle de messages et 36 pixels de la capture.

## Étape 9 : InvalidateRect, ValidateRect, RedrawWindow, UpdateWindow, GetUpdateRect

Le client demande lui-même à repeindre : `user32` passe InvalidateRect, ValidateRect et RedrawWindow à
NtUserInvalidateRect, NtUserValidateRect et NtUserRedrawWindow, UpdateWindow à NtUserCallHwndLock
(`HWNDLOCK_ROUTINE_UPDATEWINDOW`, 0x5E), GetUpdateRect à NtUserGetUpdateRect ; il lit d'abord lui-même `WND.hrgnUpdate`
(0x68) et l'enfant (`spwndChild`, 0x38) pour ne pas appeler le noyau sans rien à faire. Comme ReactOS (`painting.c`,
`simplecall.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::gdi::region` | l'union d'une région et d'un rectangle (ses rectangles restent disjoints), son rectangle englobant |
| `win32k::window` | la région à mettre à jour devient une région (dans la zone cliente, depuis son coin) ; `WND.hrgnUpdate` vaut `HRGN_WINDOW` tant qu'elle n'est pas vide, faute d'objets région de GDI (`user32` ne fait que le comparer à NULL) |
| `win32k::paint` | IntInvalidateWindows (`RDW_INVALIDATE`, `RDW_FRAME`, `RDW_ERASE`, `RDW_INTERNALPAINT` ; `RDW_VALIDATE`, `RDW_NOFRAME`, `RDW_NOERASE`, `RDW_NOINTERNALPAINT` ; les enfants visibles, sauf `RDW_NOCHILDREN` ou ceux d'un parent à `WS_CLIPCHILDREN` sans `RDW_ALLCHILDREN` ; `WNDS_UPDATEDIRTY` pour une fenêtre d'un autre thread), co_UserRedrawWindow (le rectangle ou la fenêtre, puis `RDW_UPDATENOW` ou `RDW_ERASENOW` ; rien pour une fenêtre qu'on ne voit pas), co_IntUpdateWindows (WM_PAINT envoyé aussitôt, puis aux enfants ; IntValidateParents), co_UserGetUpdateRect (le rectangle englobant, coupé à la zone cliente et aux parents ; `bErase` : cadre et fond d'abord) ; l'invalidation d'une fenêtre montrée ou déplacée y passe aussi |
| `sys::window` | NtUserRedrawWindow (drapeaux vérifiés : `ERROR_INVALID_FLAGS`), NtUserInvalidateRect, NtUserValidateRect (hWnd nul : tout le bureau), NtUserGetUpdateRect, NtUserCallHwndLock (`UPDATEWINDOW` ; les autres routines journalisées) |

Dans `gui`, après la boucle de messages : deux rectangles disjoints invalidés dans « Visible » donnent un rectangle
englobant de 10, 10 à 120, 60 ; validés l'un après l'autre, il ne reste rien (une région, non un rectangle) et
`QS_PAINT` s'éteint. UpdateWindow du popup invalidé et à effacer lui envoie WM_PAINT aussitôt (`000f 0014`) : son
premier carré disparaît, le second est dessiné 12 pixels plus loin. RedrawWindow(`RDW_ERASENOW`) d'un coin de 5 × 5
pixels l'efface aussitôt (`0014`, visible sur la capture) sans le valider (GetUpdateRect : 12, 0, 17, 5 ; `QS_PAINT`) ;
GetUpdateRect(`TRUE`) l'efface de nouveau ; ValidateRect le valide. `RDW_UPDATENOW` avec `RDW_FRAME` : WM_PAINT, où
BeginPaint repeint le cadre et efface (`000f 0085 0014`). `RDW_INTERNALPAINT` : pas de région, mais `QS_PAINT` et
WM_PAINT, puis plus rien. « Clipper » (`WS_CLIPCHILDREN`) n'invalide sa fille qu'avec `RDW_ALLCHILDREN`, et
UpdateWindow les peint l'un puis l'autre (`000f 0014 000f 0085 0014` : la fille invalidée avec son cadre). Une
fenêtre jamais montrée n'est pas invalidée ; un drapeau inconnu est refusé (1004). InvalidateRect sans effacer :
WM_PAINT n'efface pas (`000f`) ; un fond à effacer, validé, ne l'est plus. Un parent sans `WS_CLIPCHILDREN`
invalide sa fille ; UpdateWindow de la fille valide sa part dans la région du parent (il lui reste 0, 20, 192, 72) ;
sa procédure ne faisant pas BeginPaint, son cadre et son fond sont repeints quand même (`000f 0085 0014`), et elle
reste à peindre.

Ce qui manque : InvalidateRgn, ValidateRgn, GetUpdateRgn et RedrawWindow avec une région (pas encore d'objets région
de GDI : `ERROR_NOT_ENOUGH_MEMORY`, journalisé une fois ; faits à l'étape 10), le fond du bureau repeint à la demande (RedrawWindow,
InvalidateRect de NULL : journalisé une fois ; ses fenêtres le sont), WM_SYNCPAINT et `WNDS_SYNCPAINTPENDING`, la
région de fenêtre (SetWindowRgn), le passage en coordonnées logiques d'une fenêtre `CS_OWNDC` dans GetUpdateRect.
Sans test : la validation refusée d'une fenêtre invalidée par un autre thread (`WNDS_UPDATEDIRTY` : `gui` n'a qu'un
thread GUI). Mutation équivalente : ôter l'effacement oublié quand la validation vide la région (BeginPaint n'efface
pas une région vide, et le cadre et le fond repeints aussitôt oublient eux-mêmes un fond sans région).

Tests : hôte (`gdi::region` : union disjointe, rectangle englobant ; `window` : région à mettre à jour ;
`paint` : région de l'écran dans la zone cliente) ; le scénario `gui`, sur les deux CPU, avec 42 pixels de la capture.

## Étape 10 : GetDC et ReleaseDC, les régions de GDI, InvalidateRgn, ValidateRgn, GetUpdateRgn

Le client prend lui-même un DC pour peindre hors de WM_PAINT, et se sert de régions. `user32` passe GetDC, GetDCEx et
GetWindowDC à NtUserGetDC, NtUserGetDCEx et NtUserGetWindowDC, ReleaseDC à NtUserCallOneParam
(`ONEPARAM_ROUTINE_RELEASEDC`, 0x39 : `user32!ReleaseDC` le pousse), ValidateRgn à NtUserCallHwndParamLock
(`TWOPARAM_ROUTINE_VALIDATERGN`, 0x65), InvalidateRgn et GetUpdateRgn à NtUserInvalidateRgn et NtUserGetUpdateRgn.
`gdi32` crée une région par NtGdiCreateRectRgn, puis la tient lui-même tant qu'elle est vide ou rectangulaire : il en
lit et en écrit les attributs (`RGN_ATTR`, dans la mémoire du processus, nommés par l'entrée de la table des handles),
en les marquant `ATTR_RGN_DIRTY` (SetRectRgn, CombineRgn de deux rectangles quand le résultat en est un) ; pour le
reste, il appelle NtGdiCombineRgn et NtGdiGetRgnBox. DeleteObject d'une région et SelectClipRgn (`RGN_COPY` d'un
rectangle ou d'aucune région) vont dans le lot du TEB ; DeleteDC appelle NtGdiDeleteObjectApp. Comme ReactOS
(`region.c`, `cliprgn.c`, `gdiobj.c`, `gdibatch.c`, `windc.c`, `painting.c`, comme spécification) :

| Partie | Ce qu'elle fait |
|---|---|
| `abi::gdi` | `RGN_ATTR` et ses drapeaux (`ATTR_RGN_VALID`, `ATTR_RGN_DIRTY`), `RGN_AND` … `RGN_COPY`, les appels en lot `GDIBSEXTSELCLPRGN` (24 octets, `GDIBS_NORECT`) et `GDIBSOBJECT` (8 octets) |
| `abi::user` | `ONEPARAM_ROUTINE_RELEASEDC`, `TWOPARAM_ROUTINE_VALIDATERGN`, `DCX_NOCLIPCHILDREN` |
| `win32k::gdi::region` | IntGdiCombineRgn (`RGN_AND`, `RGN_OR`, `RGN_XOR`, `RGN_DIFF`, `RGN_COPY`), REGION_Complexity (une région est un rectangle quand ses morceaux remplissent le rectangle qui les tient), REGION_SetRectRgn (coins dans n'importe quel ordre), un déplacement qui ne dépasse pas les entiers |
| `win32k::gdi::handles` | une entrée rendue (ENTRY_vPushFreeEntry) perd type, propriétaire et attributs et compte une reprise de plus ; les entrées rendues sont reprises les premières (la dernière d'abord) ; GreDeleteObject (ni de stock, ni publique, au processus) |
| `win32k::gdi::rgnobj` | les régions d'un client : leurs attributs pris dans des blocs de sa mémoire (`pPoolRgnAttr`), repris avant chaque usage (REGION_vSyncRegion) et réécrits après (REGION_UnlockRgn) ; NtGdiCreateRectRgn ; la suppression rend les attributs |
| `win32k::gdi::dc` | la région de découpage d'un DC (`dclevel.prgnClip`, depuis son origine) et là où il peint (`prgnRao`) ; IntGdiExtSelectClipRgn et IntSelectClipRgn (sans région de découpage, un mode la combine au rectangle qui tient la région visible ; `RGN_AND` la prend telle quelle), IntGdiExtSelectClipRect (le SelectClipRgn en lot) ; `VisRectRegion` des attributs écrit à la prise du DC (`gdi32` en tire ce que rend un SelectClipRgn en lot) ; GetClipBox et PatBlt sur `prgnRao` |
| `win32k::gdi::batch` | SelectClipRgn et DeleteObject (d'une région ou d'un objet) en lot |
| `win32k::dce` | les règles des `DCX_*` de UserGetDCEx au complet (sans fenêtre : tout l'écran, du cache ; une fenêtre qui n'est pas un enfant coupe toujours ses sœurs ; `DCX_NOCLIPCHILDREN` ; le DC du parent seulement pour qui ne coupe ni sœurs ni enfants) ; la région d'un client donnée à GetDCEx, à l'écran, au DC jusqu'à sa remise où elle est supprimée sauf `DCX_KEEPCLIPRGN` ; `HRGN_WINDOW` ; seul le processus qui a pris un DC le rend |
| `win32k::paint` | co_UserRedrawWindow avec une région (dans la zone cliente, elle l'emporte sur le rectangle), co_UserGetUpdateRgn (la région à mettre à jour coupée à la zone cliente et aux parents, dans la zone cliente) |
| `sys::gdi` | NtGdiCreateRectRgn, NtGdiCombineRgn, NtGdiGetRgnBox, NtGdiDeleteObjectApp, NtGdiExtSelectClipRgn |
| `sys::window` | NtUserGetDC, NtUserGetDCEx, NtUserGetWindowDC, NtUserInvalidateRgn, NtUserGetUpdateRgn, NtUserCallHwndParamLock (`VALIDATERGN` ; les autres routines journalisées), NtUserRedrawWindow avec une région |
| `sys::message` | `ONEPARAM_ROUTINE_RELEASEDC` |

Dans `gui`, après les tests de l'étape 9, un popup « Regions » de 200 × 150 pixels en 1050, 600 :

- Régions : une région créée aux coins inversés tient de 0, 0 à 100, 100 (GetRgnBox, lu par `gdi32` dans ses
  attributs) ; avec une autre de 50, 50 à 150, 150, `RGN_OR` (dans le noyau) donne une région complexe de 0, 0 à
  150, 150, `RGN_AND` (dans `gdi32`) le rectangle commun, `RGN_DIFF` (dans le noyau) un L ; SetRectRgn (dans `gdi32`)
  puis `RGN_OR` : le noyau reprend le rectangle changé (10, 10 à 150, 150) ; sans seconde région, CombineRgn rend
  ERROR (6). DeleteObject, en lot : GetObjectType et GetRgnBox ne trouvent plus rien, et la région suivante reprend
  l'entrée, avec un compte de reprises de plus.
- DC : GetDC donne la zone cliente (GetClipBox 0, 0, 200, 150), où PatBlt noircit le coin ; ReleaseDC le rend une
  fois (1, puis 0 ; PatBlt le refuse ensuite) ; DeleteDC aussi (1, puis ReleaseDC 0 et DeleteDC 0 avec l'erreur 6).
  GetWindowDC de « Plain » : toute la fenêtre (200 × 100), dont le coin du cadre noircit ; GetDC(NULL) : tout l'écran
  (1280 × 800), sur le bureau. GetDCEx(`DCX_INTERSECTRGN`) d'une région de l'écran : GetClipBox 50, 50, 70, 70, seul ce
  carré noircit, et la région est supprimée à la remise ; avec `DCX_EXCLUDERGN | DCX_KEEPCLIPRGN`, un DC complexe, et
  la région reste.
- Découpage : SelectClipRgn d'un carré (en lot ; 2, d'après `VisRectRegion`) puis GetClipBox (120, 0, 140, 20) ;
  PatBlt de toute la zone cliente ne noircit que le carré ; ExtSelectClipRgn(`RGN_OR`) d'un autre (dans le noyau) rend
  3 ; SelectClipRgn d'une région hors de la fenêtre rend 1, d'aucune région 2 (GetClipBox : toute la zone cliente).
- Région à mettre à jour : deux InvalidateRgn, GetUpdateRgn rend 3 (10, 10 à 60, 60) ; ValidateRgn de l'une, 2 (l'autre
  seule) ; ValidateRgn(NULL), 1 (rien). InvalidateRgn(NULL) : 0 (1400). InvalidateRgn sans effacer, puis UpdateWindow :
  WM_PAINT seul. RedrawWindow(`RDW_ERASENOW`) d'une région de 10, 10 à 30, 30 efface aussitôt ce carré (`0014`, et le
  coin noir coupé sur la capture) sans le valider (GetUpdateRgn : 2). « Plain » validé puis invalidé dans sa seule
  barre de titre (`RDW_FRAME`) : `user32`, qui voit `WNDS_SENDNCPAINT`, demande au noyau, qui vide la région donnée
  (GetUpdateRgn : 1).

Écarts avec ReactOS : sans `DCX_CACHE`, une fenêtre sans DC à elle a un DC du cache, comme dans XP (`DCX_CACHE` ne fait
que passer outre `CS_OWNDC` et `CS_CLASSDC`) et Wine (ReactOS rend NULL) ; seul le processus qui a pris un DC le rend
(ReactOS ne vérifie pas, et rendrait les attributs au mauvais processus) ; `VisRectRegion` est écrit à la prise du DC
(ReactOS l'écrit au premier dessin, CLIPPING_UpdateGCRegion). `WND.hrgnUpdate` reste `HRGN_WINDOW` tant que la région à
mettre à jour n'est pas vide : `user32` ne fait que le comparer à NULL.

Ce qui manque : NtGdiSetRectRgn (`gdi32` change lui-même une région qui a ses attributs), les autres formes de région
(ellipses, polygones, ExtCreateRegion), OffsetRgn, EqualRgn, PtInRegion, RectInRegion, GetRegionData, GetClipRgn,
ExcludeClipRect, IntersectClipRect, OffsetClipRgn, SetMetaRgn, `DCX_INTERSECTUPDATE` (journalisé une fois), les DC
d'une fenêtre ou d'une classe (`CS_OWNDC`, `CS_CLASSDC` : un DC du cache, journalisé une fois), les régions et les DC
d'un processus rendus à sa fin, le cache de handles du PEB. Sans test : NtGdiDeleteObjectApp d'un autre objet qu'un DC
(`gdi32` met en lot la suppression d'une région), le refus de rendre le DC d'un autre processus (`gui` n'a qu'un
processus GUI), le libre des attributs d'une région supprimée (une fuite n'a pas d'effet visible). Les 27 mutations
des autres parties sont tuées ; un `|` dans un marqueur `expect` en fait deux marqueurs au choix (`xtask`) : le
message de `DCX_EXCLUDERGN, DCX_KEEPCLIPRGN` n'en a plus.

Tests : hôte (`abi::gdi` : appels en lot et attributs relus ; `gdi::region` : CombineRgn, complexité, coins,
déplacement ; `gdi::handles` : entrée rendue puis reprise ; `gdi::rgnobj` : attributs repris et réécrits ;
`gdi::dc` : région de découpage, modes, rectangle en lot, `VisRectRegion`, place des attributs d'une région ;
`gdi::batch` : appels lus ; `dce` : règles des `DCX_*`) ; le scénario `gui`, sur les deux CPU, avec 57 pixels de la
capture.

## Étape 11 : le texte du titre et les symboles des boutons (polices, ADR-013)

Le cadre peint par le noyau (étape 6) n'avait ni le texte du titre ni les symboles des boutons. Il les a maintenant,
dessinés avec les polices de ReactOS épinglé, sans FreeType :

- `libs/glyph` (no_std, testée sur l'hôte) : `ttf-parser` 0.21 lit la police (les versions suivantes demandent
  `core_maths` et `libm` sans `std`, hors de l'ADR-016) ; un rastériseur maison accumule l'aire signée de chaque pixel
  en virgule fixe 16.16 (niveaux de gris, courbes aplaties à un dixième de pixel près, sans hinting). Les métriques
  sont celles que GDI lit : ascent et descent Windows de la table `OS/2`, `xAvgCharWidth`. Tahoma à 8 points
  (hauteur -11) a celles d'XP : ascent 11, descent 2, largeur moyenne 5. Le Marlett épinglé (celui de Wine) place ses
  symboles par Unicode (de `0` à `y`) ; une vraie police symbole se lit par sa table symbole (U+F000 à U+F0FF).
- `xtask` met `tahoma.ttf`, `tahomabd.ttf` et `Marlett.ttf` dans `WINDOWS\FONTS` ; le noyau les lit par Io au
  démarrage et les installe dans win32k (`userland::install_fonts`, « [boot] fonts installed: … »).
- `win32k::font` : les fichiers installés, un texte mis en glyphes à une hauteur de LOGFONT (négative : l'em ;
  positive : la cellule), avances arrondies au pixel, coupé et fini par « ... » s'il ne tient pas (DT_END_ELLIPSIS),
  glyphes en niveaux de gris ou monochromes (`NONANTIALIASED_QUALITY`), et le cache des glyphes rendus.
- Dessin (`gdi::draw`, `Op::Glyph`) : un glyphe va vers sa couleur à proportion de sa couverture
  (`Bitmap::blend_coverage`), coupé à son rectangle et à la région visible.
- `nonclient` (UserDrawCaptionText, UITOOLS95_DrawFrameCaption de ReactOS comme spécification) : le titre en Tahoma
  gras (lfCaptionFont par défaut : -11, gras ; Tahoma normal pour une fenêtre d'outils), en `COLOR_CAPTIONTEXT` ou
  `COLOR_INACTIVECAPTIONTEXT`, à deux pixels du bord (pas encore d'icône), centré dans les 19 lignes du titre (ligne de
  base à 11 pixels sous le haut de la cellule), jusqu'aux boutons ; chaque bouton a son caractère de Marlett (`r`
  fermer, `0` réduire, `1` agrandir, `2` restaurer), monochrome, dans son carré moins un pixel, d'une cellule de sa
  hauteur, en `COLOR_BTNTEXT` ; réduire ou agrandir sans le style qui le permet est grisé (une ombre en
  `COLOR_BTNHIGHLIGHT` décalée d'un pixel, puis `COLOR_BTNSHADOW`).

Sur la capture du scénario `gui` : « Visible », « Clipper », « Striped », « Plain » dans leur titre, les trois
boutons avec leur symbole. `GetSystemMetrics` n'a pas changé : les métriques de l'étape 2 supposaient déjà ces
polices (largeur moyenne du titre 6).

Ce qui manque : les polices d'un LOGFONT quelconque (correspondance des noms et des graisses, `FontSubstitutes`), les
objets police de GDI (NtGdiHfontCreate, SelectObject), ExtTextOut, DrawText, GetTextExtentPoint32, GetTextMetrics,
GetCharWidth, le crénage, le hinting, ClearType ; l'icône du titre (icônes) ; le titre d'une fenêtre active (pas de
fenêtre active : tous les cadres sont inactifs, étape 6). `DFCS_INACTIVE` du bouton fermer (`CS_NOCLOSE`, menu
système) n'est pas suivi.

Tests : hôte (`glyph` : formes de couverture connue, polices de ReactOS si présentes ; `win32k::font` : métriques,
« ... », Marlett monochrome ; `gdi::dib` : mélange coupé ; `nonclient` : texte placé, rien au-dessus des capitales ni
sous la ligne de base, couleurs active et inactive, titre long fini par des points avant les boutons, symboles des
trois boutons, bouton grisé) ; 7 mutations du placement, des couleurs, du grisé, du mélange et des points, toutes
tuées ; le scénario `gui` sur les deux CPU, avec 3 pixels de plus sur la capture (le `l` de « Visible », sous sa
ligne de base, le centre de la croix) et le pixel de la face du bouton fermer déplacé à côté de la croix.

## Étape 12 : le texte des clients (polices de GDI, TextOut, GetTextMetrics, GetTextExtentPoint32)

Un nouveau programme de test, `tests/native/text1.c` (scénario `text`, à la place de `winlogon.exe` comme `gui`),
prend un bureau puis fait du texte par `gdi32`. Sa première sonde : NtGdiGetStockObject, NtGdiHfontCreate (que
`gdi32` appelle sans dire la taille de l'ENUMLOGFONTEXDVW), NtGdiGetTextMetricsW (68 octets, TMW_INTERNAL) et
NtGdiGetTextExtent manquaient ; TextOutW et SelectObject d'une police passent par le lot du TEB (`gdi32` met en lot
le texte que `lpk` lui rend : GdiBCTextOut, avec les attributs du DC pris à ce moment ; GdiBCSelObj, après avoir
changé `hlfntNew` des attributs lui-même), que le noyau sautait.

- `glyph` : les champs de TEXTMETRIC d'une police TrueType (FillTM de ReactOS comme spécification) :
  l'interligne interne (WinAscent + WinDescent - unitsPerEm), la largeur maximale (`hhea`), la graisse
  (`usWeightClass`), les premier, dernier, défaut et coupure des caractères (`OS/2`), le pas et la famille (PANOSE,
  `post` : `TMPF_FIXED_PITCH` pour un pas variable, `TMPF_VECTOR`, `TMPF_TRUETYPE`, `FF_SWISS`), police symbole
  (une table symbole, comme FreeType).
- `abi::gdi` : LOGFONTW, TEXTMETRICW, TMDIFF, TMW_INTERNAL, GDIBSTEXTOUT, GDIBSEXTTEXTOUT, `LO_FONT_TYPE`, les
  polices de stock, ETO_*, TA_*.
- `win32k::gdi::fontobj` : l'objet police (LFONT) dans la table des handles, au processus ou public ; les sept
  polices de stock (CreateStockFonts : SYSTEM_FONT « System » 16 gras, DEFAULT_GUI_FONT « MS Shell Dlg » -11…) ; la
  correspondance d'un LOGFONT : une graisse de 600 ou plus donne Tahoma gras, « Marlett » Marlett, tout autre nom
  Tahoma ; le TMW_INTERNAL d'une police (l'italique, le soulignement et le barré demandés) ; l'étendue d'un texte.
- La police d'un DC est celle de ses attributs (`hlfntNew`), lus par le noyau au moment voulu ; un DC neuf a la police
  du système.
- `win32k::gdi::text` (GreExtTextOutW comme spécification) : le texte placé selon l'alignement (TA_LEFT, TA_RIGHT,
  TA_CENTER ; TA_TOP, TA_BASELINE, TA_BOTTOM), sur sa cellule remplie de la couleur de fond en mode OPAQUE, sur le
  rectangle rempli avec ETO_OPAQUE, coupé à lui avec ETO_CLIPPED et à la région où peint le DC ; les avances d'un
  client (`lpDx`, les horizontales d'ETO_PDY).
- Lot (`gdi::batch`) : GdiBCTextOut (ses avances puis ses caractères, depuis l'octet 0x50), GdiBCExtTextOut (un
  rectangle rempli), GdiBCSelObj (rien à faire : le noyau lit `hlfntNew`).
- Services : NtGdiGetStockObject, NtGdiHfontCreate (le LOGFONTW au début de ce qu'il reçoit), NtGdiSelectFont,
  NtGdiGetTextMetricsW, NtGdiGetTextExtent, NtGdiExtTextOutW.

Ce que lit le programme : les polices de stock sont des polices (`OBJ_FONT`), l'ancienne police d'un DC neuf est celle
du système ; DEFAULT_GUI_FONT a les métriques de Tahoma 8 points d'XP (hauteur 13, ascent 11, descent 2, interligne
interne 2, externe 0, largeur moyenne 5, graisse 400, pas et famille `0x27`, ANSI_CHARSET) ; « Mino » fait 23 × 13,
27 × 13 en gras. Sur la capture : « Mino » en bleu marine, « Opaque te » sur son rectangle jaune coupé, « Bold » en
gras.

Sans hinting (ADR-013), un fût d'un pixel de Tahoma normal tombe souvent sur deux colonnes : les pixels du texte
tirent vers sa couleur sans toujours l'atteindre.

Ce qui manque : les autres polices du disque et leur correspondance par nom, `FontSubstitutes`, l'énumération des
polices, GetObject d'une police, la largeur, l'italique, le soulignement et le barré au dessin, l'orientation,
TA_UPDATECP, ETO_GLYPH_INDEX, ETO_RTLREADING, les DC transformés, GetTextExtentExPoint (NtGdiGetTextExtentExW : DrawText
en a besoin), GetCharWidth, GetTextFace, OUTLINETEXTMETRIC, NtGdiOpenDCW (que `user32` appelle à la création d'une
fenêtre, sans effet visible). Sans test de bout en bout : NtGdiSelectFont et NtGdiExtTextOutW appelés directement
(`gdi32` met en lot SelectObject et TextOut ; ils servent quand le lot est plein ou un DC a une section DIB) ; leurs
parties communes passent par les tests hôte.

Tests : hôte (`glyph` : TEXTMETRIC de Tahoma, Tahoma gras et Marlett ; `fontobj` : correspondance, métriques, étendue ;
`text` : alignements, fond de cellule et rectangle, coupure, avances ; `batch` : TextOut, ExtTextOut et SelectObject
lus) ; 10 mutations de l'alignement, du fond, de la coupure, des avances, de la graisse, des métriques et du lot,
toutes tuées sur l'hôte, et 3 dans le scénario (police initiale d'un DC, hauteur d'une étendue, TextOut en lot) ; le
scénario `text` sur les deux CPU, avec 8 pixels de la capture.

## Étape 13 : DrawText (GetTextExtentExPoint, IntersectClipRect, GetRandomRgn)

`tests/native/text1.c` appelle maintenant le DrawTextW de `user32` (son `rtl/text.c`), qui fait tout chez le client
au-dessus de trois services qui manquaient, que la sonde montre l'un après l'autre :

- NtGdiGetTextExtentExW (GetTextExtentExPointW) : DrawText mesure chaque ligne, et cherche où couper un mot, par
  combien de caractères tiennent dans une largeur (`pcCh`) et l'étendue cumulée de chacun (`pdxOut`, toutes, comme
  ReactOS). `win32k::font::advances` rend les avances par unité UTF-16, arrondies au pixel par glyphe comme celles de
  `text_run` (la dernière étendue est la largeur de GetTextExtentPoint32) ; `fontobj::text_extents` les cumule.
  `dxMax` est non signé (-1 : tout tient). GTEF_INDICES (GetTextExtentExPointI) est refusé : pas encore.
- NtGdiGetRandomRgn (GetRandomRgn) : avant de se couper à son rectangle, DrawText garde la région de découpage du DC
  dans une région à lui (CLIPRGN : 1 et la région, depuis l'origine du DC ; 0 sans région de découpage, le cas ici).
  APIRGN donne la même chose faute de région de méta, SYSRGN la région visible à l'écran, METARGN 0.
- NtGdiIntersectClipRect (IntersectClipRect) : la région de découpage coupée par le rectangle (sans elle, elle devient
  le rectangle), sur `dc::select_clip_rect` de l'étape 10 ; rend la complexité de la région où le DC peint.

À la fin, DrawText rend au DC la région gardée (SelectClipRgn, que `gdi32` met en lot ; ici, aucune région). Il
dessine chaque ligne par ExtTextOutW avec ETO_CLIPPED : son texte est donc coupé deux fois.

Ce que lit le programme : « Words wrapped on more lines » coupé en deux lignes dans 100 pixels (DT_WORDBREAK : 26) ;
« Centred » centré dans un rectangle de 100 × 40 (DT_CENTER | DT_VCENTER | DT_SINGLELINE : 26, le décalage compris) ;
le rectangle qu'il faut au texte (DT_CALCRECT : 145 × 13) ; « Clipped text » coupé à 40 pixels (13), puis « After »
dessiné : la région de découpage est rendue. GetTextExtentExPointW de « Mino » dans 12 pixels : 2 caractères, étendues
8, 11, 17, 23. IntersectClipRect appelé deux fois, le second rectangle croisant le premier : une région de 100, 150 à
140, 163 (GetClipBox), qui coupe un TextOutW (qui, lui, ne coupe pas) ; SelectClipRgn(NULL) rend la zone cliente.

Le premier pixel choisi pour la coupure de DrawText tombait entre deux lettres : blanc même sans coupure, il ne
vérifiait rien. Il est remplacé par la hampe du « t » de « text », relevée sur une capture faite sans
IntersectClipRect.

Ce qui manque : les préfixes (`&`, que DrawText souligne ; le test met DT_NOPREFIX), DT_END_ELLIPSIS et
DT_PATH_ELLIPSIS non vérifiés, les DC transformés, GetTextExtentExPointI, la région de méta (SetMetaRgn).

Tests : hôte (`fontobj` : étendues cumulées croissantes, la dernière est la largeur) ; 6 mutations, toutes tuées dans
le scénario : `pcCh` qui compte tout, `pdxOut` non écrit, GetRandomRgn qui dit une région absente ou qui rend la région
visible, IntersectClipRect sans effet ou qui remplace la région. Les deux dernières survivaient à la première version
du test : DrawText coupe aussi par ETO_CLIPPED, et sans région préalable, AND et COPY donnent la même chose. Le
scénario `text` passe sur les deux CPU, avec 7 pixels de plus.

## Étape 14 : DestroyWindow, DestroyMenu, et la fin d'un thread ou d'un processus GUI

Jusqu'ici, les fenêtres d'un thread vivaient autant que lui, et rien ne revenait à win32k à la fin d'un thread ou
d'un processus GUI : fenêtres, menus, minuteries, DC du cache, objets GDI et classes restaient. DestroyWindow
échouait faute de service, si bien que le DefWindowProc de `user32`, qui répond à WM_CLOSE par DestroyWindow, ne
fermait rien (SC_CLOSE envoie déjà WM_CLOSE, `win32k::sizemove`). ReactOS sert de spécification
(co_UserDestroyWindow, IntSendDestroyMsg, co_UserFreeWindow, IntDestroyMenuObject, ExitThreadCallback,
ExitProcessCallback) ; son code n'est pas porté.

`win32k::destroy` :

- NtUserDestroyWindow (`destroy_window`) : la fenêtre d'un autre thread et celle d'un bureau sont refusées
  (`ERROR_ACCESS_DENIED`), un handle qui n'est pas une fenêtre aussi (`ERROR_INVALID_WINDOW_HANDLE`). Une fille
  prévient son parent (WM_PARENTNOTIFY : WM_DESTROY, son identifiant, elle) ; visible, elle est cachée
  (ShowWindow(SW_HIDE) pour une fille, SetWindowPos(SWP_HIDEWINDOW) sinon : ce qu'elle découvre se repeint) ; ses
  fenêtres possédées du même thread sont détruites d'abord, celles d'un autre thread perdent leur propriétaire ;
  active, une autre fenêtre devient active (`input::activate_other`, co_WinPosActivateOtherWindow : son
  propriétaire pour une fenêtre contextuelle, sinon la suivante de ses sœurs, sinon la première ; sans elle, la file
  n'a plus de fenêtre active, après WM_NCACTIVATE et WM_ACTIVATE inactifs) ; si elle a le clavier, son parent le
  prend (une fille), sinon personne (WM_KILLFOCUS). Puis WM_DESTROY à elle et à ses enfants, de haut en bas, tant
  qu'ils vivent ; puis co_UserFreeWindow : les enfants d'abord, chacun recevant WM_NCDESTROY après les siens. Une
  procédure qui redétruit sa fenêtre pendant WM_DESTROY réussit sans rien refaire.
- Ce que rend une fenêtre (`finish`) : ses minuteries (`timer::destroy_window_timers`), ses messages de la file
  (postés, entrées, et les messages envoyés, dont les envoyeurs sont réveillés : `SentMessage::abandon`), la
  fenêtre active, celle du clavier et la capture qu'elle était, sa région à mettre à jour (le compte des fenêtres à
  peindre de son thread suit), le menu de sa barre et ses sous-menus, les DC du cache pris pour elle
  (`dce::free_window_dcs`, DceFreeWindowDCE : un GetDC sans ReleaseDC, journalisé une fois), ses propriétés, sa place
  dans l'ordre Z ; `WNDS2_INDESTROY` dès le début de co_UserFreeWindow, puis `WNDS_DESTROYED` (0x80000000, ce que lit
  l'`IsWindow` de `user32`) et `FNID_FREED` ; enfin son handle (`window::release`). Son `WND` reste dans le tas jusqu'à
  la dernière référence du noyau, comme UserDeleteObject. Une fenêtre appartient à son thread dès qu'elle a un
  handle, et une création qui échoue après (WM_NCCREATE ou WM_CREATE refusé, le nom sans place) la détruit, avec
  WM_DESTROY et WM_NCDESTROY, comme ReactOS.
- NtUserDestroyMenu, sur `menu::destroy` (IntDestroyMenuObject, avec les sous-menus) ; un menu qui n'existe plus rend
  `ERROR_INVALID_MENU_HANDLE`. Un menu est au processus qui le crée (son `PROCESSINFO` dans la table des handles).
- La table des handles USER (`win32k::handles`) retient pour chaque entrée prise le processus de son objet et son
  type : GetGuiResources(GR_USEROBJECTS) compte ainsi les fenêtres (`ppi->UserHandleCount`), et la fin d'un processus
  trouve ce qui lui reste.
- Les rappels de Ps (`ps::set_win32_callouts`, PsEstablishWin32Callouts) : à la fin d'un thread qui a un
  `Win32Thread`, puis à celle d'un processus qui a un `Win32Process` (son dernier thread, ou NtTerminateProcess d'un
  processus sans thread), avant que ses handles soient fermés et son espace d'adresses rendu ; à PASSIVE_LEVEL, dans
  le thread qui se termine, rattaché à l'espace du système, sans rappel du mode utilisateur possible.
- La fin d'un thread GUI (`thread_exit`) : il quitte le premier plan ; ses fenêtres sont détruites sans message
  (`TIF_INCLEANUP` de ReactOS : il ne reçoit plus rien), celles de premier niveau d'abord ; ce qu'elles découvrent se
  repeint, et une fenêtre d'un autre thread devient active si l'une d'elles l'était ; une fenêtre dont la destruction
  a été interrompue (le thread fini pendant WM_DESTROY) est rendue aussi. Ses minuteries partent
  (`timer::destroy_thread_timers`), sa file est vidée (`QueueState::clear`), les messages qu'on lui avait envoyés
  reviennent à leurs envoyeurs (`sent::abandon_all`, sans attendre la vérification de 250 ms), il quitte son bureau
  (`gui::leave_desktop` : son `CLIENTTHREADINFO` rendu au tas, la vue du tas partie avec le dernier thread du
  processus sur ce bureau).
- La fin d'un processus GUI (`process_exit`) : ses objets USER qui restent (ses menus ; une fenêtre, s'il en restait)
  sont détruits, les DC du cache qu'il avait pris y reviennent (`dce::free_process_dcs`), ses objets GDI quittent la
  table (`gdi::cleanup_process`, GDI_CleanupForProcess : un DC en mémoire laisse son bitmap), son `PROCESSINFO` rend
  ses classes, ses vues des tas de bureau, son bureau de démarrage et sa station (`ProcessInfo::release`). Le noyau
  journalise ce qu'il a rendu, et ce qui resterait (« leaves N USER and M GDI objects »).

Corrigé en chemin : NtUserGetGuiResources prenait 1 pour les objets GDI et 2 pour les objets USER ; le SDK (et
ReactOS) disent `GR_GDIOBJECTS` 0 et `GR_USEROBJECTS` 1 (2 et 4, les pics, viennent après XP). Le scénario lit les
deux comptes d'un processus fils avec les valeurs du SDK.

Vu en chemin, déjà là : `user32` ne sait pas lire nos menus (le handle de la table USER ne désigne pas un `MENU` du
tas d'un bureau) ; IsMenu rend donc toujours FALSE, et AppendMenu(MF_POPUP) n'attache pas le sous-menu
(`MENU_mnu2mnuii` ne pose `MIIM_SUBMENU` que si `MENU_GetMenu` valide le handle) : l'item reçoit le handle du
sous-menu comme identifiant. Un tel sous-menu ne part donc pas avec sa barre, mais avec son processus. Corrigé à l'étape 20 :
les menus sont dans le tas du bureau.

Le banc d'essai : `tests/native/destroy1.c` (`DESTROY1.EXE` à la place de `winlogon.exe`, scénario `destroy`). Une
lettre et `-` est WM_DESTROY, une lettre et `.` WM_NCDESTROY (IsWindow est encore TRUE pendant ces deux messages,
comme le dit l'`IsWindow` de `user32` épinglé, qui ne lit que `WNDS_DESTROYED`), une lettre et `^` WM_PARENTNOTIFY de
WM_DESTROY :

- DestroyWindow(A), A possédant la fenêtre contextuelle D et parent de B, lui-même parent de C : `D-D.A-B-C-C.B.A.` ;
  les quatre handles invalides ensuite ; A de nouveau (1400), la fenêtre du bureau (5) ;
- une fille F seule (identifiant 7) : `E^F-F.`, son parent E vit et n'a plus d'enfant (GW_CHILD) ;
- WM_CLOSE et WM_SYSCOMMAND(SC_CLOSE) au DefWindowProc de `user32` : `G-G.`, `H-H.` ;
- une fenêtre détruite emporte sa minuterie de 10 ms et un message posté (aucun message pour elle 60 ms après,
  KillTimer échoue) ;
- une barre de menus part avec sa fenêtre (son DestroyMenu rend 1401), DestroyMenu une seule fois (1401 ensuite) ;
- un thread qui finit avec une fenêtre visible, sa fille, une minuterie et un DC de GetDC : refusé à un autre thread
  (5) ; à sa fin, les deux handles sont invalides, sa procédure n'a reçu aucun message, et le compte des objets USER du
  processus (GetGuiResources) est revenu ; à la fin du programme, il est revenu à celui du départ ;
- un processus fils (le même programme, `child` et le TID du parent sur sa ligne de commande) crée deux fenêtres
  (dont une barre de menus), trois menus, une minuterie, un DC du cache, un pinceau et un DC en mémoire, puis finit
  sans rien rendre : avant, GetGuiResources lui compte au moins 5 objets USER et 3 GDI ; après, 0 et 0, sa fenêtre est
  invalide et son menu détruit.

Ce qui manque : WM_ASYNC_DESTROYWINDOW aux enfants d'un autre thread (détruits sans message, journalisé une fois),
les crochets (HCBT_DESTROYWND, HSHELL_WINDOWDESTROYED), le WM_MOUSEMOVE que ReactOS insère pour la fenêtre sous le
curseur, le menu système, `spwndLastActive` d'un propriétaire, l'effacement de ce qu'une fille cachée découvre dans
son parent (l'étape 5 ne le fait pas non plus).

Les fenêtres d'un programme partent maintenant avec son processus, comme sous XP : les scénarios qui capturaient
l'écran après la fin de leur programme (`gui`, `text`, `bitmap`) n'y voyaient plus que le bureau. Leurs programmes,
comme ceux de `mouse` et `mouse-windows` (qui finissaient juste après leur dernier marqueur, une course), attendent
5 s après lui, comme `dialog` et `listview` : la capture se fait pendant ce temps, et `gui`, `text` et `bitmap`
n'attendent plus leur statut de sortie (leur marqueur `done` dit qu'ils sont allés au bout).

Tests : hôte (`handles` : processus et types des entrées ; `queue` : les messages d'une fenêtre détruite, la file
vidée ; `sent` : un message abandonné réveille son envoyeur sans valeur ; `gdi::handles` : les objets d'un
processus ; `gui` : l'adresse du serveur d'un `PROCESSINFO`) ; le scénario `destroy`, sur les deux CPU, et les
scénarios GUI existants (`send-messages` : l'envoi au thread fini échoue maintenant à sa fin, non plus 250 ms après).

## Étape 15 : les curseurs (objets curseur, curseurs du système, SetCursor, WM_SETCURSOR)

`user32` fait lui-même ses curseurs et ses icônes ; win32k n'en garde que l'objet et la forme. Les 21 scénarios GUI
appelaient tous NtUserFindExistingCursorIcon (non fait, 0), puis LoadCursor échouait plus loin, sans rien
journaliser : CURSORICON_GetCursorDataFromBMI ouvre l'écran (CreateDC("DISPLAY") : NtGdiOpenDCW), en fait un DC en
mémoire (NtGdiCreateCompatibleDC), qui refusait le DC de NtGdiOpenDCW, rendu sans propriétaire. Le chemin de
LoadImage (`cursoricon.c` de `user32` et de win32k, ReactOS comme spécification) :

| Étape de `user32` | Ce que fait Mino |
|---|---|
| NtUserFindExistingCursorIcon(module, ressource, {icône, cx, cy}) | un curseur LR_SHARED du processus de cette ressource de ce module, sinon un curseur du système qui en vient (`win32k::cursor::find_existing`) ; les noms sans casse, un identifiant (MAKEINTRESOURCE) comme ReactOS (un tampon sous 0x10000) |
| CreateDC("DISPLAY"), CreateCompatibleDC | NtGdiOpenDCW donne un DC de l'écran entier au processus, avec ses attributs (`gdi::dc::open_display_dc`) ; DeleteDC le rend (`gdi::dc::delete_dc`, qui prend maintenant tout DC du processus hors du cache) |
| CreateBitmap(cx, 2 cy, 1, 1, NULL), CreateCompatibleBitmap | un bitmap noir sans bits ; monochrome pour un bit par pixel (le drapeau `monochrome` d'une surface), de la couleur de l'écran sinon, monochrome aussi pour un DC en mémoire dont le bitmap l'est (`gdi::surface::create_compatible`) |
| StretchDIBits de la ressource dans le bitmap | NtGdiStretchDIBitsInternal (`gdi::dibits`) : DIB de 1, 4, 8, 16 (5-5-5), 24 ou 32 bits sans compression, BITMAPINFOHEADER ou BITMAPCOREHEADER, étirée au plus proche ; vers un bitmap monochrome, le noir ou le blanc le plus proche |
| NtUserCallOneParam(CREATEEMPTYCUROBJECT), NtUserSetCursorIconData | un objet `TYPE_CURSOR` de la table des handles USER ; ses données (CURSORDATA, `abi::user::CursorData32`) : le point chaud, la taille, le masque AND (sur le masque XOR pour un curseur monochrome), les couleurs, l'alpha ; les bitmaps deviennent publics, et le noyau tire la forme qu'il dessine (`win32k::cursor::Shape` : transparent, opaque, XOR, mélange) |

Les curseurs du système : la première fois qu'un bureau va à l'écran (NtUserSwitchDesktop), win32k fait le rappel
LOADDEFAULTCURSORS (n° 3, User32SetupDefaultCursors, co_IntLoadDefaultCursors) : `user32` charge les 16 curseurs
(LoadSystemCursors) et les pose par NtUserSetSystemCursor (ils ne sont plus à aucun processus, CURSORF_GLOBAL), puis
fait de la flèche le curseur du thread. Une application qui charge IDC_ARROW les retrouve (FindExistingCursorIcon,
second passage), sans objet à elle.

Le curseur de l'écran : chaque thread a le sien (SetCursor : NtUserSetCursor, GetCursor :
NtUserGetThreadState(THREADSTATE_GETCURSOR)) ; l'écran montre celui du thread de la fenêtre sous le pointeur
(gpqCursor : `cursor::pointer_over`, appelé par le thread d'entrée brute). Chaque message de la souris qui sort de la
file, hors capture, envoie WM_SETCURSOR à sa fenêtre (la fenêtre, le code de l'endroit, le message brut), après
WM_MOUSEACTIVATE, comme Wine ; DefWindowProc (`cursor::def_set_cursor`, DefWndHandleSetCursor) laisse d'abord le
parent d'une fille choisir hors des bords, met le curseur de la classe dans la zone cliente (FALSE), une flèche
double du système sur un bord ou un coin d'une fenêtre qui n'est pas agrandie (TRUE), rien sur HTERROR, la flèche
ailleurs (TRUE). Le curseur logiciel de `display` dessine n'importe quelle forme, son point chaud au pointeur ; la
flèche codée dans win32k ne sert qu'avant les curseurs du système. SetCursor(NULL) cache le curseur.

DestroyCursor (NtUserDestroyCursor) : un curseur du système reste (TRUE), comme un curseur LR_SHARED ; celui d'un
autre processus ou le curseur d'un thread refuse (FALSE) ; sinon il part, ses bitmaps supprimés. La fin d'un
processus détruit ses curseurs (`crate::destroy`). NtUserGetIconSize rend la taille.

Ce qui manque : CreateCursor, CreateIcon et CreateIconIndirect (`user32` y lit GetObject, CopyImage et GetDIBits :
NtGdiExtGetObjectW, NtGdiGetDIBitsInternal ne sont pas faits), GetIconInfo, DrawIconEx (l'icône du titre et des
boutons de la barre des tâches), les curseurs animés (refusés, journalisé une fois), ShowCursor, ClipCursor,
GetCursorInfo, le remplacement d'un curseur du système déjà posé (FALSE, comme ReactOS), GetClassLong(GCLP_HCURSOR)
(le `CLS` n'a pas de pointeur vers l'objet, et la table USER désigne l'objet du serveur, comme pour les menus), le
curseur réévalué quand une fenêtre bouge sous un pointeur immobile ; StretchDIBits sans les autres ROP que SRCCOPY,
DIB_PAL_COLORS, les compressions, les étendues négatives ; un curseur du système garde des bitmaps publics que
GetIconInfo rendrait après la fin du processus qui les a faits.

Le banc d'essai : `tests/native/cursor1.c` (`CURSOR1.EXE` à la place de `winlogon.exe`, scénario `cursor`) : après
SwitchDesktop, les 16 curseurs du système sont chargés et la flèche est le curseur du thread ; IDC_ARROW est le même
à chaque chargement ; IDC_CROSS et IDC_SIZEWE existent et diffèrent ; SetCursor rend l'ancien ; sa fenêtre
(WS_THICKFRAME, de 200,200 à 1000,700) a la croix pour curseur de classe. Le pointeur va dans sa zone cliente
(WM_SETCURSOR pour elle, de WM_MOUSEMOVE ; DefWindowProc 0, la croix), sur son bord gauche (DefWindowProc 1,
IDC_SIZEWE), puis revient (la croix) ; DestroyCursor(IDC_CROSS) rend TRUE et la croix reste. L'écran montre la croix
au pointeur (423,405), centrée sur lui, ses barres à 8 pixels, la fenêtre blanche à côté. Le scénario `mouse` vérifie
en plus un pixel que seule la flèche de `user32` noircit (659,403).

Tests : hôte (`abi::user` : CURSORDATA ; `gdi::dibits` : lecture des DIB, étirement, monochrome ; `cursor` : formes
monochromes, en couleurs, avec alpha, pixels sur l'écran, la flèche de win32k ; `handles` : le processus d'une
entrée changé). Mutations tuées : le curseur de la classe, l'envoi de WM_SETCURSOR, la recherche des
curseurs du système, la forme dessinée (toujours la flèche), le point chaud, la flèche double d'un bord. Mutation
équivalente dans les scénarios : le noir ou le blanc des masques (chaque curseur de `user32` a une variante de 1 bit
et une de 32 bits avec alpha ; sur un écran de 32 bits, LookupIconIdFromDirectoryEx prend la seconde, dont l'alpha
l'emporte sur les masques) : `gdi::dibits::to_monochrome` n'a qu'un test hôte.

## Étape 16 : les icônes (icônes du système, icône du titre, WM_SETICON, DrawIconEx, GetProp du client)

Les 12 scénarios dont les fenêtres ont un menu système journalisaient « the caption's icon (icons): not yet ». Une
icône est un objet curseur (étape 15) ; ce qui manquait, c'est d'où elle vient et qui la dessine (`cursoricon.c`,
`nonclient.c`, `painting.c`, `defwnd.c` de win32k et de `user32`, ReactOS comme spécification).

| Partie | Ce que fait Mino |
|---|---|
| Les icônes du système | au premier NtUserSwitchDesktop, après les curseurs, le rappel SETWNDICONS (n° 11, User32CallSetWndIconsFromKernel, co_IntSetWndIcons) : `user32` charge IDI_APPLICATION, IDI_HAND, IDI_QUESTION, IDI_EXCLAMATION, IDI_ASTERISK, IDI_WINLOGO et sa petite forme ; elles ne sont plus à aucun processus (IntLoadSystenIcons), et LoadIcon(NULL, IDI_*) d'une application les retrouve (FindExistingCursorIcon, second passage) |
| L'icône du titre (`cursor::caption_icon`, NC_IconForWindow) | la petite icône de la fenêtre (WM_SETICON), sinon la grande, sinon la petite de sa classe, sinon la grande, sinon la petite IDI_WINLOGO du système (pas pour WS_EX_DLGMODALFRAME) ; dessinée à SM_CXSMICON × SM_CYSMICON au début du titre d'une fenêtre qui a un menu système et n'est pas une fenêtre d'outils, centrée dans un carré de la hauteur du titre, le texte décalé d'autant (UserDrawCaption ; `Op::Icon` de `gdi::draw`) |
| WM_SETICON, WM_GETICON | DefWindowProc du noyau (DefWndSetIcon, DefWndGetIcon) : ICON_SMALL et ICON_BIG dans deux propriétés du système de la fenêtre (atomes `SysICS`, `SysIC`, publiés dans le `SERVERINFO` : `atomIconSmProp`, `atomIconProp`), le cadre repeint ; `user32` répond lui-même à WM_GETICON en lisant ces propriétés |
| Les propriétés lues par le client | `user32` lit GetProp (et WM_GETICON) dans la liste `PropListHead` du `WND`, des `PROPERTY` (`abi::user::Property32`) qu'il atteint par `ulSharedDelta` : elles sont maintenant dans un tas à la fin de la section partagée de USER (`shared::alloc`, UserHeapAlloc), réécrites à chaque SetProp (`window::publish_properties`) ; jusque-là, GetProp d'une application rendait toujours NULL |
| DrawIconEx | NtUserDrawIconEx (`cursor::draw_icon_ex`, UserDrawIconEx) : la forme à la taille demandée (0 : la sienne, ou SM_CXICON avec DI_DEFAULTSIZE), au plus proche, dans le DC là où il peint ; DI_NORMAL, DI_IMAGE, DI_MASK ; ERROR_INVALID_CURSOR_HANDLE pour un handle qui n'en est pas un |

Ce qui manque : le pinceau de DrawIconEx qui efface le fond (`hbrFlickerFreeDraw`, journalisé, sans effet),
ICON_SMALL2, `hIconSmWindows` et `hIconWindows` du `SERVERINFO` (gardées par win32k seul), GetIconInfo, CopyImage et
CreateIconIndirect (GetObject, GetDIBits), une petite icône de classe tirée de la grande par CopyImage (la grande est
réduite au dessin), le titre d'une fenêtre réduite, NtUserRemoveProp et l'énumération des propriétés
(NtUserBuildPropList). Le tas partagé tient environ 750 propriétés à la fois.

Le banc d'essai : `tests/native/icon1.c` (`ICON1.EXE` à la place de `winlogon.exe`, scénario `icons`) : les 7
icônes du système sont chargées ; IDI_APPLICATION est la même à chaque chargement ; trois fenêtres à menu système : A
(classe sans icône) montre la petite IDI_WINLOGO, B (classe à IDI_HAND) la montre et la dessine à 32 × 32 dans sa
zone cliente par DrawIconEx (TRUE ; un faux handle : FALSE, 1402), C reçoit IDI_ASTERISK par WM_SETICON (aucune
avant), que WM_GETICON rend (ICON_BIG : aucune) et que son titre montre. Neuf pixels vérifiés à l'écran.

Tests : hôte (`nonclient` : la place de l'icône, ni sans menu système ni dans une fenêtre d'outils ; `cursor` : une
forme dessinée à la taille demandée, DI_IMAGE, DI_MASK, coupée ; `window` : la chaîne des `PROPERTY` depuis le
`WND`) ; le scénario `icons` sur AMD et Intel, et les scénarios GUI. Dans `gui`, l'icône par défaut paraît au
début des titres, dont le texte se décale de 19 pixels (la hauteur du titre) : deux pixels vérifiés ont suivi, et
l'atome de la première classe devient `c00c` : comme InitUserAtoms, win32k crée `SysICS` et `SysIC` à son
initialisation, avant toute classe.

## Étape 17 : les barres de défilement des fenêtres (SetScrollInfo, ShowScrollBar, le dessin, le clic)

La console de `consrv`, `cmd`, la listview de `comctl32` et `desktop-launch` appelaient NtUserSetScrollInfo et
NtUserShowScrollBar, absents (0 rendu), et le cadre journalisait « scroll bars: not yet ». `scrollbar.c` et
`nonclient.c` de win32k, `controls/scrollbar.c` et `windows/defwnd.c` de `user32` (ReactOS comme spécification) ;
`win32k::scroll`, `sys::scroll`.

| Partie | Ce que fait Mino |
|---|---|
| L'état des barres | dès qu'on parle d'elles (co_IntCreateScrollBars : SetScrollInfo, GetScrollBarInfo, EnableScrollBar, le cadre peint avec une barre ; `user32` en donne à WM_NCCREATE d'une fenêtre qui en a le style), deux barres dans le noyau (`scroll::ScrollBars` : intervalle, page, position, position suivie, état des parties : le `SBINFOEX` de ReactOS) et leur `SBINFO` (`abi::user::SbInfo32`) dans le tas du bureau, en `WND.pSBInfo` : `user32` y lit lui-même GetScrollPos et GetScrollRange ; d'abord de 0 à 100 ; rendu au tas avec le `WND` |
| SetScrollInfo (`scroll::set_info`, co_IntSetScrollInfo) | la page ramenée à l'intervalle, la position entre le début et la fin moins la page ; SIF_PREVIOUSPOS (SetScrollPos) rend la position d'avant ; une barre qui n'a plus de quoi défiler se cache (ou, SIF_DISABLENOSCROLL, ses deux flèches se désactivent), une qui en a de nouveau se montre ; puis elle se repeint : par le cadre (RDW_INVALIDATE, RDW_FRAME) si ses flèches changent, sinon son intérieur aussitôt (IntRefeshScrollInterior) |
| ShowScrollBar (`scroll::show_scroll_bar`) | le style WS_HSCROLL ou WS_VSCROLL ; s'il change, SetWindowPos(SWP_FRAMECHANGED) recalcule la zone cliente et repeint le cadre ; rend s'il a changé |
| EnableScrollBar, NtUserSBGetParms, GetScrollBarInfo, NtUserSetScrollBarInfo | les flèches désactivées (`WSBflags`, l'état des flèches), ce que `fMask` demande, le rectangle de la barre dans la fenêtre (contre la zone cliente, d'un pixel plus long de chaque côté avec WS_BORDER), ses flèches et son curseur (IntCalculateThumb : la page dans l'intervalle, 8 pixels au moins ; SM_CXHTHUMB sans page), l'état de la barre (invisible, indisponible, hors de l'écran) et de ses parties ; ce que `user32` tient pendant un clic |
| Le dessin (`scroll::bar_ops`, `corner_ops`) | dans WM_NCPAINT après le bord client : les deux flèches (un bouton en relief, enfoncé et plat pendant un clic, `BF_FLAT` de DrawEdge ; le symbole de Marlett, grisé si la flèche est désactivée), le fond (le pinceau gris en damier, COLOR_3DFACE sur COLOR_3DHILIGHT depuis le coin de la fenêtre, `Op::Mono`, quand COLOR_3DHILIGHT est COLOR_WINDOW ; noir sur la page où l'on clique), le curseur en relief ; entre deux barres, le coin en COLOR_BTNFACE et la poignée de taille d'une fenêtre à cadre épais (o et p de Marlett) |
| Le clic | WM_NCHITTEST rend HTVSCROLL, HTHSCROLL, et HTSIZE dans le coin (GetNCHitEx) ; WM_NCLBUTTONDOWN dessus envoie WM_SYSCOMMAND SC_VSCROLL ou SC_HSCROLL, que `user32` traite lui-même (DefWndTrackScrollBar : la capture, sa boucle de messages, la minuterie du système qui répète, WM_VSCROLL ou WM_HSCROLL, SB_ENDSCROLL au relâchement) |

Deux écarts voulus avec ReactOS : ESB_DISABLE_LTUP désactive la flèche du haut d'une barre verticale, comme la
documentation de l'API et Wine (IntEnableScrollBar de ReactOS échange les deux flèches d'une barre verticale) ; l'état
de la barre elle-même (`rgstate[0]`) se calcule à chaque GetScrollBarInfo, ce que ReactOS écrit puis écrase par l'état
gardé. co_IntCreateScrollBars de ReactOS recalcule aussi la zone cliente (co_WinPosGetNonClientSize) : Mino ne le fait
pas, la zone cliente étant déjà celle du style.

Ce qui manque : les barres des contrôles (SB_CTL, la classe ScrollBar : leur SBCALC dans les octets de plus du `WND`,
journalisé une fois ; faites à l'étape 33), ScrollWindowEx et ScrollDC (le contenu ne défile pas encore : NtUserScrollWindowEx est le
prochain manque de `consrv` et de la listview), les barres d'une fenêtre de droite à gauche, les thèmes ; HideCaret et
ShowCaret, que `user32` appelle autour du clic (journalisés, sans effet). Les symboles que `user32` dessine lui-même
pendant un clic sont lissés, ceux du noyau monochromes (la qualité de la police Marlett de DrawFrameControl).

Le banc d'essai : `tests/native/scroll1.c` (`SCROLL1.EXE` à la place de `winlogon.exe`, scénario `scroll`) : une
fenêtre sans barres (ERROR_NO_SCROLLBARS) ; A et ses barres de WM_NCCREATE (0 à 100), SetScrollInfo puis
GetScrollPos, GetScrollRange (lus par `user32` dans le tas) et GetScrollInfo, SetScrollPos au-delà de la fin (90, la
position d'avant rendue), GetScrollBarInfo (le rectangle à l'écran, les flèches, le curseur) ; B, sa barre cachée
quand elle n'a rien à faire défiler (la zone cliente grandit de 16 pixels) et montrée de nouveau, désactivée avec
SIF_DISABLENOSCROLL, EnableScrollBar, ShowScrollBar ; un clic sur la flèche du bas de A (le moniteur de QEMU) :
WM_VSCROLL SB_LINEDOWN, puis SB_ENDSCROLL, le curseur plus bas ; quatorze pixels vérifiés à l'écran.

Tests : hôte (`scroll` : SetScrollInfo, la page et la position, cacher ou désactiver, le record vérifié,
GetScrollInfo, les flèches, le rectangle, le curseur, l'état, le dessin, la poignée de taille ; `nonclient` : le cadre
avec ses barres et leur coin ; `defwnd` : HTVSCROLL, HTHSCROLL, HTSIZE ; `gdi::draw` : `BF_FLAT`) ; le scénario
`scroll` sur AMD et Intel, et les scénarios où des barres paraissent (`console`, `cmd`, `listview`,
`desktop-launch`) ou dont le test d'atteinte compte (`gui`, `mouse`, `cursor`). Dans `console`, la fenêtre de
`consrv` a maintenant sa barre verticale (conwnd.c l'ajoute à sa largeur et la montre) : sa zone cliente fait les 640
pixels de ses 80 colonnes, plus 656.

## Étape 18 : le défilement d'une fenêtre ou d'un DC (ScrollWindowEx, ScrollDC)

Avec les barres de défilement (étape 17), `consrv` et la listview appelaient NtUserScrollWindowEx, absent (0 rendu) :
rien ne défilait. `scrollex.c` de win32k (ReactOS comme spécification) ; `win32k::scrollex`, `sys::scroll`.

| Partie | Ce que fait Mino |
|---|---|
| ScrollDC (`scrollex::scroll_dc`, UserScrollDC) | dans la surface du DC, la partie de `prcScroll` (sans lui, la boîte de découpage du DC) qui tombe dans le découpage et `prcClip` est copiée, décalée de (dx, dy) (BitBlt SRCCOPY sur le même DC) ; à repeindre (`scrollex::plan`) : la destination de tout `prcScroll` et la source, moins ce qui a été copié d'une source visible ; dans `hrgnUpdate` et `prcUpdate` (coordonnées logiques) |
| ScrollWindowEx (`scrollex::scroll_window`, IntScrollWindowEx) | la même chose sur la zone cliente, par un DC du cache (`dc_flags` : sans couper les filles avec SW_SCROLLCHILDREN) ; la région déjà à repeindre de la fenêtre se décale aussi ; SW_SCROLLCHILDREN déplace les filles (`window::move_tree`) et envoie WM_MOVE à celles que le rectangle touchait ; SW_INVALIDATE (et SW_ERASE) invalide ce qui est découvert ; rend sa complexité (NULLREGION, SIMPLEREGION, COMPLEXREGION ; ERROR pour une fenêtre qu'on ne voit pas) |
| BitBlt dans une même surface (`gdi::bitblt::overlap_order`) | les rectangles d'une région se copient dans le sens du décalage (les bandes, puis dans une bande), aucun n'écrasant la source d'un suivant : un défilement dont la région est découpée par une fille copie juste (le manque que notait `gdi::bitblt`) |

Un écart voulu avec ReactOS : WM_MOVE d'une fille déplacée par SW_SCROLLCHILDREN porte le coin de sa zone cliente dans
celle de son parent, comme la documentation de l'API.

Ce qui manque : le DC propre d'une fenêtre ou de sa classe pour ScrollWindow (le cache aussi), SW_SMOOTHSCROLL (ignoré,
comme ReactOS). Le caret est venu à l'étape 19.

Le banc d'essai : `tests/native/scrollx1.c` (`SCROLLX1.EXE` à la place de `winlogon.exe`, scénario `scrollex`) : une
fenêtre peinte en bandes de 20 pixels selon une position, qui ne peint que ce qu'on lui demande ; ScrollWindowEx vers le
haut de 30 (SIMPLEREGION, les 30 dernières lignes dans `hrgnUpdate`, `prcUpdate` et GetUpdateRect, et seules peintes),
ScrollDC vers le bas de 20 sur son DC (les 20 premières), une fille déplacée de 10 vers la gauche avec SW_SCROLLCHILDREN
(WM_MOVE 290, 100) ; sept pixels vérifiés (sans la copie, cinq sont faux).

Tests : hôte (`scrollex` : la région découverte, ce qui n'a pas pu être copié, le rectangle de défilement et celui de
découpage, les zones, les drapeaux du DC ; `gdi::bitblt` : l'ordre des copies dans une même surface, qui échoue dans
l'ordre de la région) ; le scénario `scrollex` sur AMD et Intel, et `listview`, `console`, `cmd`, `desktop-launch`,
`gui`, `bitmap`, `scroll` sur AMD.

## Étape 19 : le caret (CreateCaret, ShowCaret, HideCaret, SetCaretPos)

Le contrôle Edit (le Bloc-notes, les boîtes de dialogue) et la console de `consrv` montrent un caret ; NtUserCreateCaret,
NtUserShowCaret et NtUserHideCaret étaient absents (0 rendu). `caret.c` de win32k (ReactOS comme spécification) ;
`win32k::caret`, `sys::caret`.

| Partie | Ce que fait Mino |
|---|---|
| L'état (`caret::Caret`, dans la file du thread : `QueueState.caret`) | un caret par thread : sa fenêtre, sa forme (rectangle plein, gris pour `(HBITMAP)1`, ou bitmap), sa position dans la zone cliente, son niveau de masquage, s'il est dessiné ; GetCaretPos ; le temps de clignotement (`dtCaretBlink`, 530 ms par défaut, GetCaretBlinkTime, SetCaretBlinkTime ; négatif, INFINITE : fixe) |
| Le dessin (`caret::draw`) | une inversion de l'écran, dans la zone cliente de sa fenêtre là où elle se voit (découpée par les filles et les sœurs selon WS_CLIPCHILDREN et WS_CLIPSIBLINGS) : DSTINVERT pour un rectangle plein, PATINVERT du damier gris, SRCINVERT d'un bitmap ; dessiné deux fois, il s'efface |
| CreateCaret, DestroyCaret (`caret::create`, `destroy`) | le caret d'avant effacé et détruit ; le nouveau naît caché, en 0, 0 ; une largeur ou une hauteur nulle prend celle d'une bordure (SM_CXBORDER, SM_CYBORDER) ; une fenêtre d'un autre thread : `ERROR_ACCESS_DENIED` ; la destruction de la fenêtre le détruit (`destroy_in`, dans `destroy::finish`) |
| HideCaret, ShowCaret (`caret::hide`, `show`) | le masquage se compte : chaque HideCaret le cache une fois de plus, il ne se voit qu'avec autant de ShowCaret ; visible, il se dessine aussitôt et clignote ; une fenêtre qui ne l'a pas : `ERROR_ACCESS_DENIED` (`hWnd` NULL : celle du caret) |
| SetCaretPos (TWOPARAM_ROUTINE_SETCARETPOS, `caret::set_pos`) | effacé où il était, dessiné où il va s'il se voyait ; FALSE sans caret |
| Le clignotement (`caret::blink`) | une minuterie du système (IDCARETTIMER, 0xFFFF) dont la procédure est du noyau (`timer::set_kernel_timer`) : son WM_SYSTIMER porte `lParam` = KERNEL_PROCEDURE (0x80000000), que `user32` rend à NtUserDispatchMessage, qui appelle la procédure (`window::dispatch_message`) ; elle n'est armée que tant qu'il se voit |
| BeginPaint, EndPaint (`caret::hide_in`, `show_in`) | BeginPaint le cache avant que le fond soit effacé, EndPaint le remontre, s'il est dans la fenêtre peinte |
| ScrollWindowEx (`caret::before_scroll`, `after_scroll`, co_IntFixCaret) | caché pendant la copie s'il est dans le rectangle défilé (ou dans une fille déplacée), puis décalé comme le contenu et remontré |
| NtGdiGetPixel (`gdi::dc::get_pixel`) | la couleur d'un point logique du DC sur sa surface, s'il tombe là où le DC peint ; CLR_INVALID sinon |

Écarts voulus avec ReactOS : le masquage se compte (la documentation de l'API et Wine ; ReactOS n'a qu'un booléen) ; un
caret qui devient visible se dessine aussitôt (ReactOS attend la première échéance de la minuterie) ; un caret caché ne
clignote pas (ReactOS l'inverse à chaque échéance dès sa création).

Ce qui manque : les événements d'accessibilité (EVENT_OBJECT_*), le caret dans GetGUIThreadInfo, le temps de
clignotement lu dans le registre (`CursorBlinkRate`), le DC propre d'une fenêtre pour ScrollWindow.

Le banc d'essai : `tests/native/caret1.c` (`CARET1.EXE` à la place de `winlogon.exe`, scénario `caret`) : une fenêtre
blanche prend un caret de 2 × 16 pixels qu'elle relit sur l'écran à chaque pas (GetPixel : noir là où il inverse le
blanc) : sans caret, SetCaretPos échoue ; le caret part avec sa fenêtre ; il naît caché ; ShowCaret le dessine ;
WM_SYSTIMER arrive à la boucle de messages toutes les 100 ms ; INFINITE le laisse fixe ; caché deux fois et montré une,
il reste caché ; déplacé, il laisse sa place propre ; WM_PAINT et ScrollWindowEx le laissent dessiné ; cinq pixels de la
capture vérifiés. Sans le masquage de BeginPaint, avec un booléen à la place du compte, ou sans co_IntFixCaret, le
scénario échoue.

Tests : hôte (`caret` : la naissance cachée, le compte du masquage, le clignotement et le déplacement, une fenêtre
absente ; `timer` : une minuterie du système dont la procédure est du noyau ; `gdi::dc` : GetPixel ne lit que là où le DC
peint) ; le scénario `caret` sur AMD et Intel, et `scrollex`, `scroll`, `gui`, `text`, `console`, `destroy`, `keyboard`
sur AMD et Intel.

## Étape 20 : les menus dans le tas du bureau, lus par `user32`

`user32` lit lui-même les menus : GetMenuItemCount, GetSubMenu, GetMenuItemID, GetMenuState, GetMenuString,
GetMenuItemInfo, IsMenu, GetMenuDefaultItem, GetMenuInfo, GetMenuContextHelpId, et CheckMenuItem, CheckMenuRadioItem,
AppendMenu(MF_POPUP) avant d'appeler le noyau. Il valide le handle dans la table USER, prend l'adresse de l'objet
(DesktopPtrToUser : un menu est un objet du bureau, pas de la section partagée) et suit `rgItems`, `spSubMenu`,
`Xlpstr`. Jusqu'ici l'entrée de la table désignait un objet du noyau : IsMenu rendait FALSE, et un sous-menu ne
s'attachait pas (étape 14). `menu.c` de win32k et de `user32` (ReactOS comme spécification) ; `win32k::menu`,
`sys::menu`, `abi::menu`.

| Partie | Ce que fait Mino |
|---|---|
| Les enregistrements (`abi::menu`) | `MENU` (104 octets : `PROCDESKHEAD`, `fFlags`, `iItem`, `cAlloced`, `cItems`, `rgItems`, aide, données, fond, `hWnd`) et `ITEM` (84 octets : type, état, identifiant, `spSubMenu`, coches, `Xlpstr` et `cch`, données, place, bitmap, `lpstr`) de ReactOS sur i386, avec leurs tailles et positions vérifiées à la compilation ; MENUITEMINFOW (48 ou 44 octets), MENUINFO, les MF_, MFT_, MFS_, MIIM_, MIM_, MNS_, MNF_ |
| La table (`menu::Menus`) | la copie du noyau de chaque menu (`MenuState`, ses items) sous un seul verrou, comme le verrou de USER de ReactOS ; après chaque changement, les menus touchés sont republiés dans leur tas : le texte des items (NUL final) qui n'y est pas, le tableau des items (`cAlloced` par 8, rendu quand le menu se vide), puis le `MENU` ; les blocs remplacés sont rendus après. L'entrée de la table des handles porte l'adresse du serveur du `MENU`. `DesktopHeap::alloc` est utilisable jusqu'à DISPATCH_LEVEL (pool non paginé, `write_kernel`) |
| CreateMenu, CreatePopupMenu (`menu::create`) | dans le tas du bureau du thread, au processus (son `PROCESSINFO` en `hTaskWow`) ; MNF_POPUP pour un menu déroulant |
| Les items (IntSetMenuItemInfo, `Menus::set_item`) | type, état (UpdateMenuItemState ; MFS_DEFAULT retiré des autres items), identifiant, sous-menu (marqué MNF_POPUP ; un menu absent, lui-même, un ancêtre ou une branche de plus de 30 : `ERROR_INVALID_PARAMETER`), coches, données, bitmap (MFS_HBMMENUBMP pour un HBMMENU_*), texte (la légende capturée, `cch` caractères au plus) ; sans texte, sans données de texte, sans bitmap : un séparateur |
| La recherche (MENU_FindItem, `Menus::find`) | par position ; par identifiant, dans les sous-menus d'abord, sinon le dernier item à sous-menu qui le porte |
| NtUserThunkedMenuItemInfo | avec `bInsert` (MENU_InsertItem) : au bout (une position au-delà du dernier : AppendMenu), à la position, ou avant l'item de l'identifiant (dans le sous-menu où il est) ; les boutons MDI restent à droite ; sans : l'item mis à jour, `ERROR_MENU_ITEM_NOT_FOUND` sans lui (SC_TASKLIST passe, comme ReactOS) |
| NtUserEnableMenuItem, NtUserCheckMenuItem, NtUserSetMenuDefaultItem | l'état d'avant, -1 sans l'item ; l'item par défaut (-1 : aucun) |
| NtUserThunkedMenuInfo, NtUserSetMenuContextHelpId, NtUserSetMenuFlagRtoL | fond, aide, hauteur, données, style (MIM_APPLYTOSUBMENUS), de 28 octets à la taille d'un ROSMENUINFO |
| NtUserRemoveMenu, NtUserDeleteMenu | l'item quitte son menu ; DeleteMenu détruit son sous-menu |
| NtUserSetMenu (IntSetMenu, `window::set_menu`) | une fille n'a pas de barre (`ERROR_INVALID_WINDOW_HANDLE`) ; un menu est la barre d'une seule fenêtre (`MENU.hWnd`, `ERROR_INVALID_MENU_HANDLE`) ; le cadre se recalcule si la barre change ou avec `bRepaint` ; la création d'une fenêtre et le menu de sa classe rattachent la barre de même ; `WND.IDMenu` porte la barre d'une fenêtre qui n'est pas fille (GetMenu) |
| DestroyMenu (`menu::destroy`) | le menu et ses sous-menus quittent la table, leur tas et la table des handles |

Écarts voulus avec ReactOS : un sous-menu détruit quitte les items qui l'ouvraient (ReactOS le garde en vie tant
qu'ils le tiennent ; leurs `spSubMenu` seraient sinon des adresses libérées que `user32` suivrait) ; un menu qui
s'ouvrirait lui-même est refusé (ReactOS en crée un vide à sa place) ; InsertMenuItem garde les coches de
MIIM_CHECKMARKS (ReactOS les efface après les avoir posées).

Ce qui manque : la place et la taille des items (`xItem`…, `cxMenu`, `cyMenu` : la barre à l'étape 21, les menus
déroulants ensuite), le menu système (GetSystemMenu), MNS_NOTIFYBYPOS et les menus sans fenêtre.

Le banc d'essai : `tests/native/menu1.c` (`MENU1.EXE` à la place de `winlogon.exe`, scénario `menu`) : une barre
(File, Edit, Help) relue par `user32` : IsMenu, GetMenuItemCount, GetSubMenu, GetMenuItemID, GetMenuState (séparateur,
sous-menu, MF_HELP), GetMenuStringW, GetMenuItemInfoW ; InsertMenuW par position et par identifiant, ModifyMenuW,
CheckMenuItem, CheckMenuRadioItem, EnableMenuItem depuis la barre (le noyau descend dans File), l'item par défaut,
l'aide et les données du menu ; GetMenu, une barre refusée à une autre fenêtre et à une fille ; RemoveMenu, DeleteMenu ;
LoadMenuIndirectW ; DestroyMenu et ses sous-menus. Sans le texte dans le tas, sans `WND.IDMenu`, ou sans la descente
du noyau dans les sous-menus, le scénario échoue.

Tests : hôte (`menu` : ce que `user32` lit dans le tas, la recherche, l'insertion, le séparateur, un texte remplacé,
l'état et l'item par défaut, les boucles refusées, RemoveMenu et DeleteMenu, la destruction, une barre à une fenêtre,
MENUINFO, le tableau par 8 ; `abi::menu`) ; le scénario `menu` sur AMD et Intel, et `destroy`, `gui`, `tasklist`,
`desktop-ui`, `desktop-launch`, `console`, `cmd`, `listview`, `dialog` sur AMD et Intel.

## Étape 21 : la barre de menus (mise en page, dessin, GetMenuBarInfo, DrawMenuBar)

Jusqu'ici le cadre dessinait la barre lui-même (titres à huit pixels l'un de l'autre, sans préfixe), et WM_NCCALCSIZE
lui donnait SM_CYMENU. `menu.c` de win32k (MENU_MenuBarCalcSize, MENU_CalcItemSize, IntDrawMenuBarTemp,
MENU_DrawMenuItem) et `rtl/text.c` (les préfixes de DrawText), ReactOS comme spécification ; `win32k::menubar`.

| Partie | Ce que fait Mino |
|---|---|
| La mise en page (`menubar::layout`, MENU_MenuBarCalcSize) | les items de gauche à droite dans le rectangle sous le titre (coordonnées de la fenêtre) : chacun le texte montré (sans ses `&`, jusqu'à une tabulation) plus la largeur moyenne d'un caractère de chaque côté (MenuCharSize : l'alphabet / 26, arrondi), de SM_CYMENU - 1 de haut au moins ; une ligne de plus quand un item ne tient pas (un item seul sur sa ligne est coupé) ou porte MF_MENUBREAK ; les items depuis le premier MF_RIGHTJUSTIFY (MF_HELP) à droite de la dernière ligne ; la barre fait un pixel de plus que ses items. La place de chaque item (`xItem`, `yItem`, `cxItem`, `cyItem` : la droite et le bas, comme ReactOS) et la taille de la barre (`cxMenu`, `cyMenu`) vont dans le tas |
| WM_NCCALCSIZE (`defwnd::nc_calc_size`, `menubar::calc`) | la barre est mise en page dans ce qui reste sous le titre et prend sa hauteur (une barre vide : 0) ; un item changé remet `cyMenu` à 0, le dessin remet alors la barre en page |
| Le dessin (`menubar::bar_ops`, dans le cadre) | le fond COLOR_MENU, la dernière ligne COLOR_3DFACE ; chaque item : son texte centré en Tahoma (gras pour l'item par défaut), la lettre préfixée soulignée sous la ligne de base, de sa largeur moins un pixel (TEXT_DrawUnderscore) ; surligné (MF_HILITE) : un bord enfoncé (BDR_SUNKENOUTER) et le texte décalé d'un pixel ; grisé (MF_GRAYED) : le texte en relief (COLOR_BTNHIGHLIGHT décalé, puis COLOR_BTNSHADOW) |
| NtUserGetMenuBarInfo | OBJID_MENU : le rectangle de la barre à l'écran (`idItem` 0) ou d'un item, le menu, l'item qui a le focus |
| NtUserGetMenuItemRect, NtUserMenuItemFromPoint | la place d'un item à l'écran (dans la fenêtre de la barre, ou dans la zone cliente d'un menu déroulant) ; l'item sous un point, -1 ailleurs |
| NtUserHiliteMenuItem (`menubar::hilite`) | l'item surligné ou éteint, le cadre repeint s'il a changé |
| DrawMenuBar (NtUserCallHwndLock, HWNDLOCK_ROUTINE_DRAWMENUBAR = 0x55) | SetWindowPos(SWP_FRAMECHANGED) d'une fenêtre qui n'est pas fille : la barre est remise en page et repeinte |

Écarts voulus avec ReactOS : HiliteMenuItem surligne ou éteint l'item, comme la documentation de l'API (ReactOS le
sélectionne comme le suivi d'un menu, même pour MF_UNHILITE) ; MenuItemFromPoint rend -1 hors des items (ReactOS rend le
nombre d'items) ; une barre sans items n'est ni comptée ni dessinée (le calcul de ReactOS lui donne 0, son
dessin SM_CYMENU).

Ce qui manque : les items à bitmap (MDI) et dessinés par l'application (WM_MEASUREITEM, WM_DRAWITEM), le menu système,
les menus plats (SPI_GETFLATMENU), HTMENU et le clic dans la barre (le suivi des menus, étapes suivantes).

Vu en chemin : le scénario `gui` attendait d'une fenêtre au menu de classe MENU_001 de `shell32` une zone cliente de
SM_CYMENU de moins. Ce menu est celui d'un menu déroulant (cinq titres longs) : en barre, il ne tient pas dans 292
pixels et passe sur deux lignes (37 pixels), comme sous XP. `gui1.c` compte maintenant la hauteur de la barre
(GetMenuBarInfo) et ses lignes.

Le banc d'essai : `tests/native/menu1.c`, scénario `menu` (étape 20), avec la barre de W : GetMenuBarInfo (19 de haut,
entre les côtés du cadre, au-dessus de la zone cliente), GetMenuItemRect (File au bord gauche, Edit à sa suite, Help
au bord droit, 18 de haut), GetMenuBarInfo d'un item, MenuItemFromPoint ; le texte relu à l'écran, HiliteMenuItem (le
coin de l'item en COLOR_BTNSHADOW) puis éteint ; ModifyMenuW ne déplace Edit qu'après DrawMenuBar ; six pixels de la
capture (le fond de la barre, les soulignements de F, E et H). Sans le soulignement, sans Help à droite, sans
DrawMenuBar ou sans repeindre au surlignage, le scénario échoue.

Tests : hôte (`menubar` : les préfixes, la largeur moyenne, la mise en page, Help à droite, une barre longue sur
plusieurs lignes, l'item par défaut en gras, le soulignement, le dessin d'un item surligné ; `menu` : la place des items
et le surlignage dans le tas ; `abi::menu`) ; le scénario `menu` sur AMD et Intel, et `gui`, `destroy`, `tasklist`,
`desktop-ui`, `desktop-launch`, `console`, `cmd`, `listview`, `dialog`, `caret`, `icons`, `scroll`, `scrollex`, `text`
sur AMD et Intel.

## Étape 22 : les menus déroulants (TrackPopupMenuEx, la boucle du menu, EndMenu)

`user32` exporte TrackPopupMenuEx et EndMenu tels quels (NtUserTrackPopupMenuEx, NtUserEndMenu) ; TrackPopupMenu
appelle le premier sans TPMPARAMS. Tout le suivi est dans win32k, dans le service, au thread de la fenêtre
propriétaire. `menu.c` de win32k (IntTrackPopupMenuEx, MENU_InitPopup, MENU_ShowPopup, MENU_ShowSubPopup,
MENU_HideSubPopups, MENU_TrackMenu, MENU_ExecFocusedItem, MENU_FindItemByKey, PopupMenuWndProc) et `msgqueue.c` (les
coordonnées de la souris pendant le suivi), ReactOS comme spécification ; `win32k::menupopup`, `win32k::menutrack`.

| Partie | Ce que fait Mino |
|---|---|
| La fenêtre #32768 (`menutrack::init_popup`, `menupopup::window_proc`) | créée par win32k : WS_POPUP, WS_CLIPSIBLINGS, WS_BORDER ; WS_EX_TOOLWINDOW, WS_EX_WINDOWEDGE, WS_EX_TOPMOST, WS_EX_DLGMODALFRAME ; possédée par la propriétaire, du module de `user32`. Sa procédure est du serveur : `window::server_window_proc` la reconnaît à sa classe (FNID_MENU ; sa FNID n'est posée qu'à WM_NCCREATE) et lui passe le `lParam` emballé (WM_NCCALCSIZE). Zone cliente : le cadre de son style ; WM_PAINT peint le menu, WM_ERASEBKGND n'efface rien, WM_MOUSEACTIVATE rend MA_NOACTIVATE, MN_GETHMENU son menu |
| La mise en page (`menupopup::layout`, MENU_PopupMenuCalcSize) | une colonne d'items (une de plus à MF_MENUBREAK), chacun : la place d'une coche (SM_CXMENUCHECK, sauf MNS_NOCHECK), son texte, le raccourci après une tabulation aligné sur le plus long texte (`dxTab`), la flèche d'un sous-menu (OBM_MNARROW, 6 pixels) ; les places dans le tas (`xItem`…, `cxMenu`, `cyMenu`), où `user32` les lit |
| Le dessin (`menupopup::popup_ops`, MENU_DrawPopupMenu) | le fond COLOR_MENU ; l'item sélectionné en COLOR_HIGHLIGHT, son texte en COLOR_HIGHLIGHTTEXT ; grisé, en relief ; la coche, la puce (MFT_RADIOCHECK) et la flèche en Marlett ; un séparateur, un sillon (EDGE_ETCHED) |
| La place (`menutrack::popup_place`, MENU_ShowPopup) | selon TPM_RIGHTALIGN, TPM_CENTERALIGN, TPM_BOTTOMALIGN, TPM_VCENTERALIGN (TPM_LAYOUTRTL inverse la droite) ; gardée sur le moniteur (trop bas : son bas une barre de menus sous le point, sinon au-dessus) ; à côté du rectangle à éviter (TPMPARAMS, ou le menu parent d'un sous-menu) s'il le couvre : à droite, à gauche, dessous, dessus (MENU_MoveRect) ; montrée au-dessus de tout sans activation (HWND_TOPMOST, SWP_NOACTIVATE) et peinte |
| Le début et la fin (MENU_InitTracking, MENU_ExitTracking) | le caret du thread caché ; WM_ENTERMENULOOP ; la souris capturée par la fenêtre du menu, et le thread suit un menu (`MenuOwner` : `queue.menu_owner`) ; WM_SETCURSOR ; WM_INITMENU, WM_INITMENUPOPUP ; à la fin : la capture rendue, les sous-menus fermés, la fenêtre détruite, WM_UNINITMENUPOPUP, WM_MENUSELECT (0, 0xFFFF), WM_EXITMENULOOP, le caret remontré. TPM_NONOTIFY retire les notifications, sauf WM_MENUSELECT et WM_ENTERIDLE |
| La boucle (`menutrack::track_menu`, MENU_TrackMenu) | le premier message de la file du thread, laissé dedans tant que le suivi peut finir ; la file vide : WM_ENTERIDLE (MSGF_MENU, la fenêtre du menu courant) une fois, puis l'attente. La souris (sa place dans `lParam`, à l'écran : pendant le suivi, `mouse::resolve` ne la ramène pas à la zone cliente, et un message posté par le programme compte aussi) : le mouvement sélectionne l'item sous elle et ouvre son sous-menu, un bouton enfoncé hors des menus finit le suivi (le message reste à l'application), relâché sur l'item sélectionné il l'exécute ; le bouton droit seulement avec TPM_RIGHTBUTTON. Le clavier : ↑ ↓ (les séparateurs sautés), Début, Fin, → (le sous-menu), ← et Échap (le sous-menu le plus profond se ferme ; Échap sur le premier menu finit), Alt et F10 finissent ; les autres touches traduites (TranslateMessage) : Entrée et espace exécutent, une lettre l'item qu'elle souligne, sinon WM_MENUCHAR (MNC_EXECUTE : la position rendue ; MNC_CLOSE : la fin). WM_CANCELMODE finit ; les autres messages sont distribués |
| Les sous-menus (MENU_ShowSubPopup, MENU_HideSubPopups) | WM_INITMENUPOPUP d'abord ; à droite de l'item, le haut sur lui, le menu parent (moins 2 × SM_CXEDGE de chaque côté) évité ; le premier item sélectionné au clavier ; fermé : sa fenêtre détruite, WM_UNINITMENUPOPUP |
| L'exécution (MENU_ExecFocusedItem) | un item actif qui n'est pas un séparateur : son identifiant rendu avec TPM_RETURNCMD ; sinon WM_COMMAND posté (WM_MENUCOMMAND avec MNS_NOTIFYBYPOS, WM_SYSCOMMAND d'un menu système) |
| NtUserTrackPopupMenuEx | FALSE : des drapeaux hors de VALID_TPM_FLAGS (`ERROR_INVALID_FLAGS`), un menu (`ERROR_INVALID_MENU_HANDLE`) ou une fenêtre qui n'existe pas, un TPMPARAMS d'une autre taille (`ERROR_INVALID_PARAMETER`), une fenêtre d'un autre thread, un menu déjà montré (`ERROR_POPUP_ALREADY_ACTIVE`) ; un menu vide est montré, notifié, et le suivi rend 0 aussitôt |
| NtUserEndMenu | WM_CANCELMODE posté à la fenêtre du menu suivi (un à la fois dans le système, `top_popup`) |

Ce qui manque : le suivi de la barre (le clic, F10, Alt : l'étape suivante), le clavier entre colonnes
(MENU_GetStartOfNextColumn), WM_NEXTMENU, l'aide (F1, WM_HELP), le menu système, les menus trop hauts pour l'écran
(les flèches de défilement), les items à bitmap ou dessinés par l'application (WM_MEASUREITEM, WM_DRAWITEM),
l'ombre (CS_DROPSHADOW) et l'animation, TPM_LAYOUTRTL pour la fenêtre (WS_EX_LAYOUTRTL), QF_CAPTURELOCKED.

Vu en chemin :
- un WM_NCPAINT pour une partie du cadre le repeint en entier (`paint::nc_paint`, limite connue) : la fermeture d'un
  menu au-dessus de W repeint sa barre, qui montre alors l'état de son menu (Edit supprimé par DeleteMenu sans
  DrawMenuBar ne s'y voit plus). Le scénario ne vérifie plus le soulignement d'Edit à l'écran ;
- `menu1.c` charge la disposition de clavier `00000409`, sans quoi les touches tapées par QEMU sont ignorées ;
- WM_ENTERIDLE désigne la fenêtre du menu courant : des clics postés à celle d'un sous-menu disparaissent avec elle
  quand il se ferme (comme sous XP) ; le banc poste à la fenêtre du premier menu.

Le banc d'essai : `tests/native/menu1.c`, scénario `menu` (étapes 20 et 21), avec un menu déroulant (Open avec un
raccourci, un séparateur, Gray grisé, Sub et son sous-menu Inner, Exit) suivi pour W : les refus de
TrackPopupMenuEx ; un menu vide ; au clavier (les touches tapées par QEMU quand « [menu] tracking N » paraît) :
↓ ↓ ↓ → Entrée choisit Inner (TPM_RETURNCMD, aucun WM_COMMAND), avec les notifications comptées et le second
TrackPopupMenuEx refusé ; → Échap → ← ferment le sous-menu sans finir, `q` donne WM_MENUCHAR, `x` exécute Exit
(WM_COMMAND posté, TrackPopupMenu) ; à la souris, par des messages que W poste : Open surligné (relu à l'écran, son
texte, le sillon du séparateur), Sub ouvre son sous-menu à droite, un clic sur Open le choisit ; TPM_NONOTIFY et le
rectangle évité, EndMenu ; enfin la vraie souris (QEMU) ouvre le sous-menu de Sub, et la capture vérifie huit pixels
du menu ouvert (son cadre, le sillon, Sub surligné et sa flèche, le sous-menu).

Tests : hôte (`menutrack` : la place d'un menu sur l'écran, le rectangle évité, la lettre soulignée ; `menupopup` :
la mise en page, le raccourci aligné, les colonnes, le dessin ; `menu` : une seule sélection, jamais un séparateur) ;
le scénario `menu` sur AMD et Intel, que dix-huit mutations du suivi font échouer (dont les coordonnées de la souris
ramenées à la zone cliente pendant le suivi) ; et `gui`, `destroy`, `desktop-ui`, `desktop-launch`, `desktop-click`,
`cursor`, `mouse`, `mouse-windows`, `keyboard`, `caret`, `scroll`, `scrollex`, `dialog`, `listview`, `tasklist`, `text`,
`icons`, `console`, `bitmap`, `send-messages`, `activate-app`, `cmd` sur AMD et Intel.

## Étape 23 : la barre de menus suivie (le clic, F10, Alt, les flèches)

Le clic sur la barre et le clavier passent par DefWindowProc : `user32` donne au noyau WM_NCLBUTTONDOWN,
WM_SYSCOMMAND (SC_MOUSEMENU, SC_KEYMENU), WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_SYSCHAR et WM_CANCELMODE.
`defwnd.c`, `nonclient.c` et `menu.c` de win32k (IntDefWindowProc, DefWndHandleSysCommand, GetNCHitEx,
NC_HandleNCLButtonDown, MENU_TrackMouseMenuBar, MENU_TrackKbdMenuBar, MENU_KeyLeft, MENU_KeyRight, MENU_ButtonUp,
MENU_EndMenu, NtUserGetMenuBarInfo), ReactOS comme spécification ; `win32k::defwnd`, `win32k::sizemove`,
`win32k::menutrack`.

| Partie | Ce que fait Mino |
|---|---|
| HTMENU (`defwnd::nc_hit_test`, `window_hit_test`) | au-dessus de la zone cliente, entre ses côtés, pour une fenêtre qui n'est pas fille et a un menu (HAS_MENU) |
| Le clic (`sizemove::nc_lbutton_down`) | WM_NCLBUTTONDOWN sur HTMENU envoie WM_SYSCOMMAND SC_MOUSEMENU + HTMENU, que DefWindowProc fait suivre (`menutrack::track_mouse_menu_bar`) : TPM_BUTTONDOWN, TPM_VERTICAL ; l'item sous la souris sélectionné et son menu ouvert sous lui ; la fenêtre en est la propriétaire et a la souris (ses messages en coordonnées d'écran, comme pour un menu déroulant) |
| Le relâchement (MENU_ButtonUp) | sur l'item ouvert, le menu reste ouvert ; un second clic sur lui ferme la barre (`TimeToHide`) ; sur un item sans menu, il est exécuté (WM_COMMAND posté) ; hors des menus, le suivi finit |
| Les touches (`defwnd::key_menu`) | Alt enfoncé seul, sans répétition, puis relâché, ou F10 enfoncé puis relâché : SC_KEYMENU (0) à la fenêtre de premier niveau ; Alt et une lettre (WM_SYSCHAR) : SC_KEYMENU (la lettre) ; ce qu'il en reste dans la file du thread (QF_FMENUSTATUS, QF_FF10STATUS : `queue.menu_keys`) |
| SC_KEYMENU (`menutrack::track_kbd_menu_bar`) | la barre de la fenêtre de premier niveau ; sans lettre, le premier item sélectionné ; avec une lettre, l'item qu'elle souligne sélectionné et un VK_RETURN posté (son menu s'ouvre) ; sans item (WM_MENUCHAR ignoré), le suivi finit aussitôt (TF_ENDMENU) |
| Les flèches sur la barre (MENU_KeyLeft, MENU_KeyRight) | ← et → passent à l'item voisin de la barre (du premier au dernier et retour) ; si un menu était ouvert, celui du nouvel item s'ouvre, son premier item sélectionné ; → ouvre d'abord le sous-menu de l'item sélectionné d'un menu ouvert ; ↑ et ↓ ouvrent le menu de l'item ; Échap ferme le menu ouvert, puis la barre |
| WM_CANCELMODE (`menutrack::end_menu_of`) | Alt oublié (QF_FMENUSTATUS ; F10 enfoncé reste retenu, comme ReactOS) ; le suivi finit si la fenêtre est celle du menu suivi ou sa propriétaire (MENU_EndMenu) ; la souris rendue si elle l'avait |
| NtUserGetMenuBarInfo | fBarFocused : la barre est le menu suivi ; fFocused : l'item sélectionné (la barre suivie pour `idItem` 0) ; `hwndMenu` : la fenêtre du menu ouvert de l'item |

Écarts avec ReactOS, faute du menu de la fenêtre : aux bouts de la barre, la sélection fait le tour au lieu de passer
au menu de la fenêtre (MENU_DoNextMenu, WM_NEXTMENU) ; Alt+Espace, Maj+Échap, une fenêtre réduite ou sans barre ne
suivent rien (HTSYSMENU non plus).

Ce qui manque : le menu de la fenêtre (GetSystemMenu, HTSYSMENU, SC_KEYMENU ' '), WM_NEXTMENU, MENU_SuspendPopup
(une flèche répétée ouvre chaque menu), Alt+F4, Alt+Tab, Alt+Échap, Maj+F10 (WM_CONTEXTMENU), le premier plan du
clavier pendant le suivi (KF_MENUMODE).

Vu en chemin : la file simplifie déjà la touche (VK_LMENU devient VK_MENU, `queue.rs`) ; la barre suivie se repeint
entière (WM_NCPAINT, limite connue de `paint::nc_paint`).

Le banc d'essai : `tests/native/menu1.c`, scénario `menu` (étapes 20 à 22), avec la barre de W (Fichier, Help) :
WM_NCHITTEST (HTMENU au-dessus de la zone cliente) ; WM_NCLBUTTONDOWN sur Fichier (son menu ouvert, la barre et
l'item « focalisés » pour GetMenuBarInfo, le menu ouvert après le relâchement, fermé quand la souris passe à Help,
dont le clic poste WM_COMMAND) ; deux clics sur Fichier ; WM_CANCELMODE ; les touches de QEMU : Alt+F puis x (Exit),
Alt seul puis ← et Entrée (Help), F10 ↓ → Entrée, Alt+F Échap → Entrée, Alt+Q (WM_MENUCHAR, fin aussitôt) ; enfin le
vrai clic de QEMU sur Fichier, dont le menu reste ouvert pour la capture (l'item enfoncé, son texte décalé, le menu
dessous, son sillon).

Tests : hôte (`defwnd` : HTMENU, les touches du menu) ; le scénario `menu` sur AMD et Intel, que quatorze mutations
font échouer (HTMENU, SC_MOUSEMENU, Alt ou F10 relâché, WM_SYSCHAR, `TimeToHide`, ← et → sur la barre, le VK_RETURN
d'une lettre, TF_ENDMENU, WM_CANCELMODE, fBarFocused, le premier item sans lettre, `menu_owner` pour la barre) ;
et `desktop-launch`, `desktop-ui`, `desktop-click`, `gui`, `destroy`, `mouse`, `mouse-windows`, `keyboard`, `caret`,
`text`, `dialog`, `listview`, `tasklist`, `scroll`, `icons`, `bitmap`, `console`, `cursor`, `send-messages`,
`activate-app`, `cmd` sur AMD et Intel.

## Étape 24 : le Bloc-notes s'affiche (GetWindowPlacement, SetWindowPlacement)

Le banc d'essai : `tests/native/notepad1.c` (`NOTEPAD1.EXE`, MinGW), scénario `notepad`. Il prend la place de
`winlogon.exe`, prend `WinSta0\Default` comme lui, lance le vrai `notepad.exe` de ReactOS par CreateProcessW, puis
liste chaque seconde les fenêtres de premier niveau et leur titre (8 s : la sonde de `smss` arrête tout 10 s après
le démarrage ou la dernière touche). `xtask` met `notepad.exe` sur le disque, avec la fermeture de ses imports
(`comdlg32`, `shell32`, `shlwapi`, `comctl32`…).

Au démarrage, le Bloc-notes lit ses réglages (`HKCU\Software\Microsoft\Notepad`), crée sa fenêtre
(`WS_OVERLAPPEDWINDOW`, `CW_USEDEFAULT`) et, dans WM_CREATE, son contrôle Edit et sa barre d'état ; sans place
enregistrée, il prend celle que donne GetWindowPlacement, et c'est SetWindowPlacement qui montre la fenêtre. Sans
ces deux services, la fenêtre existait, cachée.

`winpos.c` de win32k (IntGetWindowPlacement, make_rect_onscreen, IntSetWindowPlacement, NtUserGetWindowPlacement,
NtUserSetWindowPlacement), ReactOS comme spécification ; `win32k::winpos`, `abi::user::WindowPlacement32`.

| Partie | Ce que fait Mino |
|---|---|
| GetWindowPlacement (`winpos::placement`) | la commande qui montre la fenêtre telle qu'elle est (SW_SHOWMINIMIZED, SW_SHOWMAXIMIZED ou SW_SHOWNORMAL) ; le rectangle normal : celui de la fenêtre dans la zone cliente de son parent, décalé dans la zone de travail pour une fenêtre de premier niveau qui n'est pas une fenêtre d'outils ; les points de l'icône et de la fenêtre agrandie à (−1, −1) ; WPF_RESTORETOMAXIMIZED d'une fenêtre agrandie ; la longueur mise à 44 quelle qu'elle soit |
| SetWindowPlacement (`winpos::set_placement`) | une longueur autre que 44 : ERROR_INVALID_PARAMETER ; la fenêtre du bureau : FALSE ; le rectangle normal ramené sur la zone de travail du moniteur le plus proche s'il en sort tout entier (make_rect_onscreen) ; la fenêtre placée là sans changer son rang ni l'activer, puis montrée par ShowWindow avec la commande donnée |

Écarts, faute de réduire et d'agrandir : pas de place gardée à part (`InternalPos` : le rectangle normal d'une
fenêtre réduite ou agrandie, les places de l'icône et de la fenêtre agrandie) ; une fenêtre réduite ou agrandie
n'est pas déplacée (journalisé une fois) ; WPF_ASYNCWINDOWPLACEMENT est fait tout de suite (journalisé une fois) ;
la tolérance de longueur pour un module qui attend Windows 3.x manque. Les deux premiers sont levés à l'étape 35
(réduire, agrandir, rétablir) ; les deux derniers restent.

Ce que le Bloc-notes montre ensuite (journal du scénario) : NtUserRegisterWindowMessage (FINDMSGSTRING : rendu 0,
la procédure du Bloc-notes prend alors WM_NULL pour le message de la recherche), NtUserCreateAcceleratorTable (ses
raccourcis), NtQueryDefaultUILanguage, NtSetInformationThread (classe 9), NtUserCallOneParam (0x28),
NtUserSystemParametersInfo (0x2006), SetWindowLong de GWL_EXSTYLE, CS_PARENTDC, et un « SendMessageW Error » de
`user32` pendant la création (un NtUserMessageCall FNID_SENDMESSAGE qui rend FALSE ; expliqué à l'étape 25). La
sonde appelle NtUserQueryWindow (GetWindowTextW). Le manifeste de `comctl32` 6 manque (toléré : la version 5 sert).

Tests : hôte (`winpos` : le placement d'une fenêtre normale, agrandie, réduite, d'outils, fille ; make_rect_onscreen
des quatre côtés ; les octets du `WINDOWPLACEMENT`) ; le scénario `notepad` sur AMD et Intel (le titre « Untitled -
Notepad », le contrôle Edit blanc, le titre actif, « Line 1 » de la barre d'état de `comctl32`), qui échoue quand
SetWindowPlacement ne montre plus la fenêtre (mutation).

## Étape 25 : RegisterWindowMessage, GetWindowThreadProcessId, les accélérateurs (Ctrl+G dans le Bloc-notes)

`window.c` (NtUserRegisterWindowMessage, NtUserQueryWindow), `useratom.c` (IntAddAtom) et `accelerator.c`
(NtUserCreateAcceleratorTable, NtUserCopyAcceleratorTable, NtUserDestroyAcceleratorTable, NtUserTranslateAccelerator,
co_IntTranslateAccelerator) de win32k, ReactOS comme spécification ; Wine (`dlls/user32/menu.c`,
translate_accelerator) pour la recherche de l'item ; `win32k::accel`, `win32k::window::query`, `sys::accel`.

| Partie | Ce que fait Mino |
|---|---|
| RegisterWindowMessage | l'atome du nom dans la table des atomes de USER (`win32k::atom`) : un message de 0xC000 à 0xFFFF, le même pour le même nom sans tenir compte de la casse ; 0 pour un nom nul (ERROR_INVALID_PARAMETER) ou un thread sans bureau. Sans lui, le Bloc-notes avait FINDMSGSTRING = 0 et aurait pris WM_NULL pour le message de sa recherche |
| NtUserQueryWindow | le PID et le TID du thread de la fenêtre (GetWindowThreadProcessId) ; pour une fenêtre console de `csrss` (sa classe est celle que `consrv` donne par NtUserConsoleControl), ceux du processus qui mène la console, dans ses octets de plus (0 et 4) ; la fenêtre active et celle qui a le clavier dans la file de son thread ; le PID (REAL_ID) ; si sa file est au premier plan ; 0 pour ISHUNG et l'IME |
| Les tables (`accel::create`, `entries`, `destroy`) | un objet USER du processus (TYPE_ACCELTABLE), rendu par DestroyAcceleratorTable ou à la fin du processus ; `fVirt` sans FVIRT_TBL_END ; la touche d'une entrée sans FVIRTKEY est un caractère ANSI (son octet bas) ; CopyAcceleratorTable rend le nombre d'entrées sans tampon ; au plus 65 536 entrées (au-delà, NULL et ERROR_NOT_ENOUGH_MEMORY, comme une allocation qui échoue chez ReactOS), la plage de l'appelant sondée et le compte borné avant toute allocation, les allocations faillibles |
| TranslateAccelerator (`accel::translate`) | WM_KEYDOWN, WM_SYSKEYDOWN : une entrée FVIRTKEY de même touche, Maj, Ctrl et Alt du thread exactement ; WM_CHAR, WM_SYSCHAR : une entrée de caractère de même code, Alt seul comparé ; la commande, si c'est un item du menu de la fenêtre (non fille) : WM_INITMENU, puis WM_INITMENUPOPUP du menu qui porte l'item et sa position, sauf souris capturée ; WM_COMMAND (HIWORD 1) sauf fenêtre désactivée, item désactivé ou grisé (après WM_INITMENUPOPUP), fenêtre réduite ; le message est alors traduit |

Écarts voulus avec ReactOS : il cherche l'item du menu à la position égale à la commande (MF_BYPOSITION), et donne
WM_INITMENUPOPUP comme pour le menu de la fenêtre (HIWORD 1) ; Mino suit Wine et la documentation de l'API (par
identifiant, HIWORD 0, pas de WM_INITMENUPOPUP pour un item de la barre elle-même).

Ce qui manque : le menu de la fenêtre (WM_SYSCOMMAND d'une commande qui y est) ; la conversion d'un caractère ANSI
au-delà de l'ASCII par la page de code (l'octet est gardé, journalisé une fois) ; MsqIsHung.

Vu en chemin : le « SendMessageW Error » de `user32` à l'étape 24 vient du Bloc-notes lui-même : il lit ses réglages
et envoie WM_SETFONT à son contrôle Edit avant de l'avoir créé (`hEdit` nul) ; Mino rend
ERROR_INVALID_WINDOW_HANDLE, comme ReactOS.

Le Bloc-notes, avec la boîte « Goto line » ouverte puis fermée, montre ensuite : NtUserIsClipboardFormatAvailable
(son WM_INITMENUPOPUP, pour Coller), NtUserGetAncestor, NtGdiGetOutlineTextMetricsInternalW, NtGdiGetFontData,
NtGdiGetGlyphIndicesW, NtGdiGetCharABCWidthsW (la police de la boîte, son contrôle Edit), WinPosDoOwnedPopups,
NtUserCallTwoParam (0x60), NtUserSetActiveWindow et NtUserSetThreadState (la fin de la boîte).

Le banc d'essai : `tests/native/notepad1.c`, scénario `notepad` : RegisterWindowMessage (un message par nom, sans
casse) ; GetWindowThreadProcessId de la fenêtre du Bloc-notes (le processus et le thread que CreateProcessW a
rendus) ; Ctrl+G tapé par QEMU (« ^G » : WM_CHAR 7 par TranslateMessage, puis TranslateAccelerator) ouvre « Goto
line », Échap la ferme, et le contrôle Edit est repeint là où elle était.

Tests : hôte (`accel` : touches virtuelles et modificateurs, caractères et Alt, FVIRT_TBL_END et l'ANSI, les
messages du menu, ce qui empêche WM_COMMAND) ; la sonde crée, copie et détruit une table d'une entrée, et
CreateAcceleratorTableW d'un compte de 0xFFFFFFFF est refusé (la revue de la PR 125 : le noyau allouait 24 Gio
avant de regarder le compte, et l'échec de l'allocation arrêtait le système ; le scénario le reproduit sans le
correctif) ; `notepad` sur AMD et Intel, qui échoue sans le WM_COMMAND de
l'accélérateur (mutation) ; `cmd`, `desktop-launch`, `console` (qui appelaient NtUserQueryWindow) sur AMD et Intel.

## Étape 26 : le texte d'Uniscribe (GetFontData, GetGlyphIndicesW, GetCharABCWidths, ETO_GLYPH_INDEX)

Le contrôle Edit de `user32` (repris de Wine) place et dessine son texte par Uniscribe (`usp10` :
ScriptStringAnalyse, ScriptShape, ScriptPlace, ScriptTextOut). Uniscribe lit la police du DC : GetTextMetricsW,
GetOutlineTextMetricsW (facultatif), GetFontData de la table `head` (une police TrueType : les glyphes viennent de
sa `cmap`), GetGlyphIndicesW, GetCharABCWidthsI (une police TMPF_TRUETYPE), puis dessine par ExtTextOutW avec
ETO_GLYPH_INDEX. Sans ces services, il prenait la police pour une police bitmap : les codes des caractères passaient
pour des glyphes, leurs avances valaient 0, et tout le texte d'une ligne se superposait.

`freetype.c` et `font.c` de win32k (ftGdiGetFontData, GreGetGlyphIndicesW, NtGdiGetGlyphIndicesWInternal,
GreGetCharABCWidthsW, NtGdiGetCharABCWidthsW, NtGdiGetFontData), ReactOS comme spécification ; `libs/glyph`
(`Font::table`, `glyph_count`, `default_char`, `abc`), `win32k::font` (`font_data`, `glyph_indices`, `glyph_count`,
`abc_widths`, `glyph_run`), `sys::gdi`.

| Partie | Ce que fait Mino |
|---|---|
| GetFontData | la table demandée (MS_MAKE_TAG : son premier caractère dans l'octet bas), ou le fichier entier pour 0 : sa taille sans tampon, sinon ses octets depuis `Offset`, au plus sa taille ; GDI_ERROR sans la table ou au-delà d'elle |
| GetGlyphIndicesW | le glyphe de chaque unité UTF-16 par la `cmap` (Unicode, sinon symboles) ; une moitié de paire de substitution est un caractère absent ; un caractère absent a 0xFFFF (GGI_MARK_NONEXISTING_GLYPHS) ou le glyphe du caractère par défaut (`OS/2` usDefaultChar dès la version 2, 0 avant) ; sans rien, le nombre de glyphes |
| GetCharABCWidths(I) | A : du stylo au bord gauche du glyphe, arrondi vers le bas ; B : jusqu'au bord droit arrondi vers le haut ; C : ce que l'avance arrondie laisse ; tout en avance pour un glyphe sans contour ; des caractères ou des indices (GCABCW_INDICES) ; des entiers pour tout drapeau, des ABCFLOAT sans drapeau (comme ReactOS) |
| ExtTextOut ETO_GLYPH_INDEX | le texte est fait d'indices de glyphes, rendus et placés comme les caractères |

Ce qui manque : GetOutlineTextMetricsW (rend 0 : Uniscribe s'en passe), GetTextExtentExPointI (GTEF_INDICES), les
collections TrueType (`ttcf`) dans GetFontData, le hinting des largeurs ABC (ReactOS les prend de FreeType, avec
hinting ; Mino des contours, sans).

Le banc d'essai : le scénario `notepad` tape « Hello, Mino! », Entrée, « Line 2 » dans le contrôle Edit du
Bloc-notes : le texte est à sa place (la hampe du H, le « ! » douze caractères plus loin, le L de la seconde ligne),
et la barre d'état dit « Line 2, column 7 ».

Tests : hôte (`font` : glyphes absents marqués ou par défaut, A + B + C = l'avance, par caractère ou par glyphe,
`head` et le fichier entier ; `gdi::text` : des indices dessinent ce que dessinent leurs caractères) ; `notepad` et
`desktop-launch` (le gestionnaire des tâches passait par ces services) sur AMD et Intel.

## Étape 27 : la boîte Enregistrer sous trouve ses dossiers (KeyNameInformation, ObjectBasicInformation, ProcessDeviceMap)

Ctrl+S ouvre la boîte « Save As » de `comdlg32`, qui parcourt le shell (`shell32`, `browseui`). Elle s'affichait,
mais vide (« Save in » sans dossier, la liste sans fichiers), et un nom tapé rendait « Path does not exist ». Trois
services du noyau manquaient en chemin :

| Service | Ce que fait Mino | Qui le demande |
|---|---|---|
| NtQueryKey(KeyNameInformation) | le chemin complet de la clé depuis `\REGISTRY`, avec la casse des clés (celui de la cible pour une clé ouverte par un lien) : `cm::Key::full_name`, `cm::info::name_information` ; NtQueryKey seul (à l'énumération, ReactOS refuse la classe) | `advapi32` (`hkcr.c`) : les clés de HKEY_CLASSES_ROOT, HKCU d'abord, HKLM sinon |
| NtQueryObject(ObjectBasicInformation) | OBJECT_BASIC_INFORMATION (56 octets exactement) : attributs du handle et OBJ_PERMANENT, droits accordés, comptes de handles et de pointeurs, place du nom complet et du type, celle du descripteur de sécurité avec READ_CONTROL | `advapi32` (`hkcr.c`, GetKeySam) |
| NtQueryInformationProcess(ProcessDeviceMap) | la carte des lecteurs DOS : un bit par lien « X: » de `\GLOBAL??`, le type de chaque lecteur d'après le périphérique cible (`io_manager::device::dos_drive_type`, comme ObpProcessDosDeviceSymbolicLink : disque fixe ou amovible, virtuel, CD-ROM, réseau) ; la taille de Query exactement (36) ; la forme EX demande les cartes par LUID (STATUS_INVALID_PARAMETER) | `kernel32` : GetLogicalDrives (rendait 0 : « My Computer » n'avait aucun lecteur, et `C:\` n'était pas un chemin), GetDriveTypeW |

Écart : Mino calcule la carte à chaque demande, à partir des liens présents, au lieu de la tenir à jour à leur
création ; le résultat est le même tant qu'il n'y a qu'une carte (celle de tous).

Vu en chemin : la fin du processus du Bloc-notes, après la boîte, arrêtait le système (« buddy free list overflow »)
: les listes libres de `mm::buddy` sont désormais chaînées, sans limite (commit `mm`, voir la passation).

Ce qui manque encore pour enregistrer (journal du scénario, Ctrl+S puis « hello.txt » et Entrée) : une assertion
d'ATL dans le shell (`atlwin.h:1118`, `::IsWindow(m_hWnd)` dans CWindow::SendMessage : une fenêtre ATL qui n'a pas
été créée ; à identifier, peut-être la liste d'autocomplétion de `browseui`), les fenêtres message seul
(HWND_MESSAGE : la fenêtre d'appartement de `combase`), NtUserSetParent, NtUserGetIconInfo, StretchDIBits d'une DIB à
palette (les icônes du shell), NtUserGetClassName, NtUserGetSystemMenu, NtUserSetActiveWindow, NtUserSetThreadState,
les barres de défilement des contrôles (SB_CTL). Le Bloc-notes se termine alors avec le code 3 (abort).

Tests : hôte (`cm` : le chemin complet par ouverture sans casse, lien, nom relatif, énumération, création ;
`cm::info` : l'encodage de KEY_NAME_INFORMATION) ; la sonde de `notepad` appelle GetLogicalDrives, GetDriveTypeW,
NtQueryInformationProcess(ProcessDeviceMap), NtOpenKey puis NtQueryKey(KeyNameInformation) sur
`\Registry\Machine\Software\Classes` (taille d'abord, puis le nom `\REGISTRY\MACHINE\SOFTWARE\Classes`) et
NtQueryObject(ObjectBasicInformation) (une mauvaise taille refusée, les droits KEY_READ, un handle) ; une carte des
lecteurs vide la fait échouer (mutation). `notepad` sur AMD et Intel, et toute la suite sur AMD (54 sur 55 ; `gui`
échouait par l'ordre de peinture des sœurs, corrigé à l'étape 28).

## Étape 28 : SetWindowLong du style (GWL_STYLE, GWL_EXSTYLE)

La page Applications du gestionnaire des tâches se repeignait en gris. Son contrôle d'onglets (`SysTabControl32`,
sœur de la page, sous elle dans l'ordre Z) ne traite pas WM_ERASEBKGND : DefWindowProc efface sa région à mettre à
jour du pinceau de sa classe (COLOR_BTNFACE), et cette région couvre la page quand une autre page se cache. Les sœurs
se repeignent de haut en bas de l'ordre Z (IntFindWindowToRepaint) : l'onglet passe après la page. Dans ReactOS, son
DC est coupé par la page, parce que `comctl32` (TAB_Create) se donne `WS_CLIPSIBLINGS` par SetWindowLongW(GWL_STYLE)
à sa création ; Mino refusait GWL_STYLE (`ERROR_CALL_NOT_IMPLEMENTED`), l'onglet restait sans le style et peignait
sur la page.

Un premier correctif avait inversé l'ordre de peinture des sœurs (du bas vers le haut, écart avec ReactOS) : la page
passait, mais le premier WM_PAINT n'allait plus au popup qu'attend le scénario `gui`. L'ordre de ReactOS est rétabli,
et la cause corrigée :

- `win32k::window::set_style` (co_IntSetWindowLongPtr, GWL_STYLE et GWL_EXSTYLE) : WM_STYLECHANGING porte un
  STYLESTRUCT (`abi::user::StyleStruct32`) dont la procédure peut changer le nouveau style ; puis le style change, et
  WM_STYLECHANGED le dit. Rend l'ancien style.
- `restyle` (GWL_STYLE) : une fenêtre de premier niveau garde `WS_CLIPSIBLINGS`, une fenêtre réduite `WS_MINIMIZE` ;
  `WS_EX_WINDOWEDGE` suit le cadre (IntCheckFrameEdge, d'après la valeur de l'appelant) ; une fille qui cesse de
  l'être perd son identifiant, une fenêtre qui devient fille sa barre de menus (`WNDS_HASMENU`), son `IDMenu` gardant
  la valeur de la barre comme dans ReactOS, qui n'a qu'un champ pour les deux.
- `restyle_ex` (GWL_EXSTYLE) : `WS_EX_WINDOWEDGE` d'après le style et la valeur de l'appelant. Pas encore :
  `WS_EX_TOPMOST` ôté à la fenêtre du shell (SetShellWindow manque) ; les fenêtres en couches.
- Rien à refaire pour les DC : un DC du cache tire du style ce qui le coupe à chaque GetDCEx
  (`dce::effective_flags`), et Mino ne garde pas de DC propre (DceResetActiveDCEs de ReactOS, au changement de
  `WS_VISIBLE`).

À cette étape, GWLP_WNDPROC et GWLP_HWNDPARENT restaient à faire (suite ci-dessous).

Tests : hôte (`window` : le style d'une fille, `WS_CLIPSIBLINGS` et `WS_MINIMIZE` gardés, le bord de fenêtre, la
fille qui cesse ou devient fille) ; `desktop-launch` sur AMD et Intel, qui échoue avec l'ordre de ReactOS sans
GWL_STYLE (la page grise, ses quatre pixels) ; `gui` passe de nouveau sur AMD et Intel ; toute la suite sur AMD (55
sur 55).

## Étape 29 : sauvegarder, fermer et rouvrir ; petites applications x86

Le parcours Bloc-notes est complet dans `notepad-save` (PR #127) : saisie
QEMU, vrai dialogue Enregistrer sous, contrôle des 20 octets du fichier,
Alt+F4, sortie normale, puis nouveau processus et texte relu à l'écran.
Le remplacement de GWLP_WNDPROC pour une procédure cliente de même encodage
débloque les fenêtres ATL du shell. Alt+F4 poste SC_CLOSE à la fenêtre de
premier niveau ; CS_NOCLOSE est respecté. Les ponts ANSI/Unicode et les
procédures serveur restent refusés ; GWLP_HWNDPARENT reste à faire.

La Calculatrice demandait ensuite GetClassName avant de transformer une
touche en clic sur un bouton. NtUserGetClassName rend maintenant le nom
non versionné, avec troncature et NUL dans le tampon UTF-16 de l'appelant.
`calculator` vérifie `12+30=42`, ferme le processus, relance et vérifie
`6*7=42`, avec contrôle du texte et du rendu. `minesweeper` contrôle un
drapeau posé au clic droit, F2, la fermeture et la relance. Les détails,
résultats, captures et limites sont dans [applications.md](applications.md).

Ces scénarios utilisent les vrais exécutables ReactOS épinglés, sans les
modifier. Le test Bloc-notes vérifie une relance sur le même volume RAM ;
la persistance après redémarrage de l'OS n'est pas couverte par ce parcours.
## Étape 30 : la vue des fichiers de la boîte Enregistrer sous (GetIconInfo, GetDIBits, StretchBlt ; GetAtomName et SendMessage corrigés)

Sous VirtualBox, la boîte « Save As » du Bloc-notes restait figée : sa vue des fichiers vide, le thread du Bloc-notes
bouclait (environ 25 lignes par seconde : « GetIconInfo Failed », « Failed to add IDI_SHELL_DOCUMENT icon to cache »,
« Imagelist no longer valid », puis `shell32.dll` rechargé). Sous QEMU la boucle tournait aussi (18 tours avant la
saisie) ; `notepad-save` passait parce qu'il tapait un chemin complet sans attendre la vue. Ce que la boîte demandait,
dans l'ordre où elle bloquait :

1. **NtUserGetIconInfo.** Le cache d'icônes de `shell32` (SIC_Initialize) met IDI_SHELL_DOCUMENT dans deux listes
   d'images de `comctl32` (ILC_COLOR32 | ILC_MASK). ImageList_ReplaceIcon demande d'abord CopyImage(LR_COPYFROMRESOURCE),
   qui veut le module et la ressource de l'icône (NtUserGetIconInfo, deux fois : la place, puis les noms) pour la
   recharger à la taille de la liste ; puis GetIconInfo, des copies de ses bitmaps. Sans le service, l'ajout échouait,
   le cache était détruit, et chaque icône demandée le refaisait. Fait : `win32k::cursor::icon_info` (ICONINFO, `pbpp`
   tiré de CURSORDATA.bpp, désormais gardé) ; les copies par `gdi::surface::copy_bitmap` (BITMAP_CopyBitmap : un
   bitmap du noyau de la même taille, monochrome ou non, les pixels et leur octet haut, au processus appelant, qui les
   supprime) ; `module_reply` et `resource_reply` (la place qu'il faut quand le tampon est trop petit, un identifiant
   MAKEINTRESOURCE dans `Buffer`) ; `abi::user::IconInfo32` ; `sys::cursor::nt_user_get_icon_info`. Écarts : le nom
   d'une ressource revient en majuscules (Mino le garde ainsi pour la recherche sans casse) ; sa place compte un NUL,
   que `user32` écrit lui-même au bout.
2. **NtUserGetAtomName écrasait la pile.** Son second argument est un PUNICODE_STRING : `user32` (ClassNameToVersion,
   à CreateWindowEx d'une classe désignée par son atome) y donne un tampon de MAX_PATH caractères. Mino écrivait le nom
   par-dessus la structure elle-même : « SHELLDLL_DefView » écrasait les registres sauvés de l'appelant, et
   SHGetSetSettings de `shell32` partait avec des arguments faits de texte UTF-16 (une exception dans le WM_INITDIALOG
   de la boîte). Le nom va dans `Buffer`, tronqué à `MaximumLength` avec son nul, comme NtUserGetAtomName de
   ReactOS ; `Length` n'est pas touché. `main` l'a corrigé en même temps (`win32k::atom::copied_name_units`,
   « #n » d'un atome entier) : c'est sa correction qui reste à la fusion.
3. **SendMessage à une fenêtre qui n'existe pas.** NtUserMessageCall(FNID_SENDMESSAGE) rendait FALSE sans écrire
   `ResultInfo`, et `user32` (SendMessageW) rend alors sa variable non initialisée. CDefView::LoadColumns demande
   Header_GetItemCount de l'en-tête de sa liste, qui n'existe pas encore en vue liste (`comctl32` le crée à la
   première colonne) : il croyait avoir deux millions de colonnes, les changeait au lieu de les insérer, et
   l'assertion `MapFolderColumnToListColumn(0)` (CDefView.cpp:1178) arrêtait le Bloc-notes (abort, code 3). Comme
   ReactOS (co_IntDoSendMessage rend 0, l'appel réussit) : 0 en `ResultInfo`, l'erreur posée
   (`ERROR_INVALID_WINDOW_HANDLE`), TRUE. SendMessageTimeout et SendNotifyMessage rendent toujours FALSE. Là
   aussi, la correction de `main` (`sys::message::send_message_result`) reste à la fusion.
4. **Les icônes de la liste.** ImageList_ReplaceIcon lit les copies de GetIconInfo par GetDIBits (add_with_alpha), et
   la liste se dessine par StretchBlt :
   - GetDIBits (`gdi::dibits::get_dibits`, NtGdiGetDIBitsInternal) : en 1 bit (noir 0, blanc 1, la table de deux
     couleurs) et en 32 bits (l'octet haut gardé, les masques écrits pour BI_BITFIELDS) ; un en-tête de 0 bit demande
     le format seul (BI_BITFIELDS en 32 bits, comme ReactOS ; la hauteur négative d'une DIB section descendante) ; les
     lignes comptées depuis le bas, une DIB moins haute que le bitmap prenant son haut, comme ReactOS
     (`scan_window`, `encode_lines`). Pas encore : les autres profondeurs (journalisé), DIB_PAL_COLORS, un
     BITMAPCOREHEADER.
   - StretchBlt (`gdi::bitblt::stretch_blt`, NtGdiStretchBlt) : aux mêmes tailles, BitBlt ; sinon le pixel le plus
     proche, la source lue d'abord dans un tampon (`read_area`, `stretch_part`). Pas encore : une étendue négative.
   - GetNearestColor (NtGdiGetNearestColor) : sur 32 bits, la couleur elle-même.
5. **La barre d'outils.** Ses bitmaps (ceux de `comctl32`, LoadImage) sont de 32 bits en BI_BITFIELDS, avec un en-tête
   V4 : StretchDIBits lit maintenant les masques de 16 et 32 bits, derrière un BITMAPINFOHEADER ou dans un en-tête V4
   ou V5 (`DibFormat::masks`). Son « not yet » dit désormais la profondeur, la compression et l'usage (le « DIB à
   palette » vu sous VirtualBox était ce BI_BITFIELDS).

La boîte montre maintenant `C:\` filtré sur `*.txt` : Documents and Settings, MINODIR, WINDOWS, A long name.txt,
MINOTEST.TXT, avec leurs icônes ; Alt+N et le chemin tapé enregistrent le fichier. Le scénario `notepad-save` attend
que la vue soit remplie avant de taper (`app_file_view` : GetDlgItem de `lst2`, puis de la liste, LVM_GETITEMCOUNT) :
tapées plus tôt, les touches allaient au premier contrôle de la boîte encore en construction.

Vu, pas fait (fait à l'étape 31) : l'alpha des images de 32 bits (StretchDIBits le perd ; NtGdiCreateDIBitmapInternal, le bitmap d'alpha
d'une icône, create_alpha_bitmap de `user32` ; NtGdiAlphaBlend) et la conversion couleur ↔ monochrome de BitBlt
(ImageList_AddMasked de `comctl32` en tire le masque : la couleur de fond du DC source devient le blanc) : les boutons
de la barre d'outils et la barre des emplacements ont un fond noir et des images fausses. La DIB section de 4 bits
vue sous VirtualBox paraît sous QEMU dans le gestionnaire des tâches (`desktop-launch`) : sa liste d'images est de
4 bits par pixel (GetDIBits de 4 bits pour la table par défaut, puis CreateDIBSection, tous deux « not yet ») ; ses
tâches, sans icône avant (ImageList_ReplaceIcon échouait), en ont maintenant une, noire, qui décale le texte de la
ligne : le scénario vérifie la ligne choisie après son texte. NtUserGetClassName, NtUserSetWindowsHookEx (le WH_MSGFILTER de
`comdlg32`), NtUserCallTwoParam 0x60 ; NtQueryDebugFilterState rend TRUE, ce qui fait évaluer les TRACE des DLL de
ReactOS (des fautes gérées dans leurs `debugstr`).

Tests : hôte (`cursor` : ce que GetIconInfo dit d'une icône, d'un curseur monochrome, d'un curseur sans données ;
la place du module et du nom de ressource, un identifiant ; `atom` : le nom tronqué à la place du tampon ; `dibits`
: les lignes de GetDIBits depuis le bas, l'encodage en 1 et 32 bits, les masques de BI_BITFIELDS en 16 et 32 bits ;
`bitblt` : StretchBlt plus grand, plus petit, plus haut, SRCAND). Sondes : `icons` (GetIconInfo de IDI_HAND, ses
copies lues par GetDIBits puis supprimées, une icône qui n'existe pas, CopyImage(LR_COPYFROMRESOURCE) à 16 × 16),
`bitmap` (StretchBlt, GetNearestColor, GetDIBits d'un bitmap de 32 bits et d'un monochrome, StretchDIBits en 5-6-5),
`listview` (une fenêtre « Files » dont le WM_CREATE fait ce que fait la vue de `shell32` : SendMessage à l'en-tête
absent rend 0 et `ERROR_INVALID_WINDOW_HANDLE`, la colonne Name insérée crée l'en-tête et se relit en sous-élément 0),
`notepad-saveas` (nouveau : `tests/native/notepad3.c`, la vue liste 5 éléments ; l'icône de dossier de la première
ligne, un coin transparent de sa case blanc et non noir, une ligne grise de l'icône de document ; les messages de la
boucle et de l'assertion interdits), `notepad-save` (la sonde attend la vue avant de taper). Quatorze mutations, une
par correction, font chacune échouer un test (sans NtUserGetIconInfo, sans copie, la copie qui perd « monochrome »,
la place du NUL oubliée, l'ancien NtUserGetAtomName — l'exception revient dans `notepad-saveas` —, MaximumLength
ignoré, SendMessage sans `ResultInfo`, sans GetDIBits, GetDIBits toujours descendant ou sans le décalage de ReactOS,
sans StretchBlt, StretchBlt sur le mauvais axe, sans GetNearestColor, BI_BITFIELDS refusé). 1107 tests hôte ;
`notepad`, `notepad-save`, `notepad-saveas`, `gui`, `icons`, `cursor`, `bitmap`, `desktop-launch`, `listview` sur AMD
et Intel.

## Étape 31 : les images de `comctl32` (BitBlt monochrome, alpha, DIB sections de 4 et 8 bits)

Après l'étape 30, la barre d'outils de la boîte Enregistrer sous et sa barre des emplacements montraient leurs images
sur un fond noir, et les icônes des tâches du gestionnaire des tâches étaient des carrés noirs. Trois manques du
moteur GDI, dans l'ordre où ils jouaient :

1. **BitBlt entre un bitmap monochrome et des couleurs** (`gdi::bitblt::Convert`, comme EXLATEOBJ_vInitXlateFromDCs
   de ReactOS) : vers un bitmap monochrome, la couleur de fond du DC source donne le blanc et toute autre le noir ;
   d'une source monochrome, le noir donne la couleur du texte du DC de destination et le blanc sa couleur de fond.
   ImageList_AddMasked en tire le masque d'une image, puis l'ôte de l'image par NOTSRCAND. Un bitmap monochrome de
   Mino garde des pixels de 32 bits, et le texte lissé qu'on y dessine laisse des gris : la source se lit au plus
   proche du noir ou du blanc (DrawState peint ainsi le texte désactivé des boutons, en relief). StretchBlt convertit
   de même.
2. **L'alpha des images de 32 bits.** StretchDIBits garde l'octet alpha d'une DIB de 32 bits (BI_RGB, ou les masques
   de BI_RGB) sur un bitmap de 32 bits, comme EngCopyBits avec une traduction triviale ; les ROP avec une source
   (BitBlt, défilement, StretchBlt) portent sur les 32 bits, comme le moteur de 32 bits de ReactOS (le NOTSRCAND
   d'ImageList_AddMasked effaçait l'alpha : `comctl32` ne voyait plus l'alpha de la barre d'outils et la dessinait par
   un masque tout noir) ; PatBlt garde l'octet haut à zéro. NtGdiCreateDIBitmapInternal
   (`gdi::dibits::create_dibitmap`, IntCreateDIBitmap : monochrome pour une DIB d'un bit noir puis blanc, ou sans
   CBM_CREATDIB pour un DC dont le bitmap est monochrome ; CBM_INIT) : `user32` en fait le bitmap d'alpha d'une icône
   (create_alpha_bitmap). NtGdiAlphaBlend (`gdi::bitblt::alpha_blend`, `blend` : DIB_32BPP_AlphaBlend, AC_SRC_OVER,
   l'alpha constant et, avec AC_SRC_ALPHA, celui de chaque pixel, couleurs prémultipliées ; le pixel le plus proche
   pour étirer) : les listes d'images ILC_COLOR32 dessinent ainsi une image qui a son alpha (alpha_blend_image). Le
   pixel d'une icône à alpha (`cursor::Pixel::Blend`) se mélange de même, prémultiplié, comme le bitmap d'alpha de
   `user32`. Jusqu'ici, CreateDIBitmap manquant, `user32` ne faisait aucun bitmap d'alpha : les curseurs et icônes de
   32 bits se dessinaient par leurs masques (ce que l'étape 15 dit de l'alpha qui l'emporte sur les masques ne valait
   pas encore). Ils se mélangent maintenant par leur alpha, comme UserDrawIconEx de ReactOS : les bords et les ombres
   des icônes des titres changent. Les pixels attendus de `gui` (le contour de WINLOGO) et d'`icons` (ceux de WINLOGO
   et d'IDI_ASTERISK) ont été recalculés à part, des images de 32 bits des ressources de `user32.dll` mélangées sur
   le fond du titre : toute l'icône est identique au pixel près.
3. **Les DIB sections de 4 et 8 bits** (`gdi::surface::Format::Indexed`) : la section garde des index dans la table
   de la DIB, comme le processus les lit ; le moteur dessine sur leurs couleurs décodées en 32 bits
   (`decode_indexed`) puis réécrit les pixels changés par l'index de la couleur la plus proche (`encode_indexed`,
   `nearest_index`). GetObject dit leurs bits et leur table ; GetDIBits rend en 4 et 8 bits la table de la DIB section
   de même profondeur, sinon la table par défaut (`gdi::dibits::default_palette` : les 16 couleurs de la VGA, ou 256 :
   les 20 couleurs fixes et le cube de 6 × 6 × 6), que ImageList_CreateImage demande pour une liste ILC_COLOR4 ou
   ILC_COLOR8. La liste du gestionnaire des tâches est de 4 bits : ses icônes y prennent les 16 couleurs.

Pas encore : les DIB sections de 1, 16 et 24 bits, une table DIB_PAL_COLORS, SetDIBits, la couleur de fond d'un DC
dans StretchDIBits vers le monochrome, StretchBlt et AlphaBlend d'une étendue négative, MaskBlt ; « My Documents » et
« My Computer » de la barre des emplacements montrent l'icône de document par défaut (fait à l'étape 32 : `shell32`
n'était pas enregistré).

Tests : hôte (`surface` : l'index le plus proche, décodage et réécriture d'une DIB de 4 et 8 bits, la géométrie ;
`object` : le DIBSECTION d'une DIB de 4 bits ; `dibits` : l'alpha d'une DIB de 32 bits, le choix monochrome de
CreateDIBitmap, les tables par défaut, GetDIBits de 4 et 8 bits ; `bitblt` : la conversion monochrome, le texte
lissé, AlphaBlend ; `dib` : un ROP garde l'alpha ; `cursor` : le pixel prémultiplié). Sonde `bitmap` : BitBlt vers le
monochrome et retour, une DIB section de 4 bits (peinte presque rouge : l'index du rouge ; GetObject ; GetDIBits : sa
table, ou celle de la VGA), CreateDIBitmap qui garde l'alpha, GdiAlphaBlend. `notepad-saveas` : la flèche verte du
bouton « Up » et un pixel transparent de son image (noir avant), un coin transparent de l'icône « Desktop ».
`desktop-launch` : le teal de la barre de titre de l'icône de `cmd` (noire avant), et l'ombre du T de « End Task »,
dans la lettre (le texte désactivé, lu au noir exact, disparaissait). Douze mutations, une par correction, font
chacune échouer un test.

## Étape 32 : la barre des emplacements de la boîte Enregistrer sous (`shell32` enregistré)

Après l'étape 31, la barre des emplacements montrait trois emplacements au lieu des cinq de ReactOS (Recent, Desktop,
My Documents, My Computer, My Network Places : filedlg_collect_places_pidls de `comdlg32`), et « My Documents » et
« My Computer » y avaient le papier blanc d'IDI_SHELL_DOCUMENT. `shell32` tire l'icône d'un dossier à CLSID de
`HKCR\CLSID\{…}\DefaultIcon` (CGuidItemExtractIcon_CreateInstance), et prend le papier blanc faute de mieux. Ces
clés n'existaient pas : elles viennent des scripts que DllRegisterServer de `shell32` applique (ses ressources
`REGISTRY` : My Computer, My Documents, My Network Places…), et c'est l'installation de ReactOS qui l'appelle
(`syssetup.inf`, RegistrationPhase2 ; `setup -mini` du LiveCD aussi). `minoinit.exe`, qui tient ce rôle chez Mino,
ne le faisait pas (ADR-023 : l'enregistrement des DLL restait à faire).

1. **NtQueryKey(KeyNameInformation) pour un handle sans KEY_QUERY_VALUE** (`sys::registry`,
   `ob::HandleTable::reference_as_with_any_access`) : comme NtQueryKey de ReactOS, le nom d'une clé se lit avec un
   droit quelconque, pas aucun ; les autres classes demandent KEY_QUERY_VALUE. L'émulation de HKCR d'`advapi32`
   (`hkcr.c`) demande le nom de chaque clé qu'elle crée avec KEY_WRITE : elle recevait `STATUS_ACCESS_DENIED`, et
   DllRegisterServer de `shell32` rendait E_FAIL.
2. **`minoinit.exe` enregistre `shell32`** (`tests/native/minoinit.c`, son étape 3, entre les profils et la ruche de
   `Default User`, comme RegistrationPhase2 vient après les profils) : les CLSID des dossiers du shell et leurs
   icônes sous HKCR, les dossiers du shell de l'utilisateur (SHELL_RegisterShellFolders). Un échec se journalise sans
   arrêter, comme dans `syssetup`. Des DLL de RegistrationPhase2, seul `shell32` est enregistré : les autres ne sont
   pas sur le disque ou ne servent pas encore.
3. **NtSetInformationFile(FileBasicInformation) d'un tampon aligné sur 4** (`sys::file`) : la sonde demandait 8, ReactOS
   `sizeof(ULONG)`, comme notre NtQueryInformationFile. CopyFileW de `kernel32` pose les dates de la copie depuis une
   variable locale qu'une pile i386 n'aligne que sur 4 : ses cadres déplacés, la copie du `NTUSER.DAT` de
   `Default User` par `minoinit` échouait (`STATUS_DATATYPE_MISALIGNMENT`, ERROR_NOACCESS).

Un Mino installé montre ainsi les cinq emplacements avec leurs icônes. Le dossier « My Documents » existant, la boîte
s'ouvre dedans, comme sous XP quand l'application ne donne pas de répertoire (CSIDL_PERSONAL).

Vu, pas fait : « Recent » s'affiche « RECENT » : Io crée un nom que le format 8.3 tient sans entrée de nom long, donc
en majuscules (`io::fat_volume`, `create`) ; le pilote FAT de ReactOS garde la casse d'un nom mixte par une entrée
de nom long (fait à l'étape 34).

Tests : hôte (`ob` : un droit quelconque suffit, aucun ne suffit pas). La sonde de `dir` pose les dates de
`KERNEL.BIN` depuis un tampon à 4 octets d'un multiple de 8. La sonde de `notepad-saveas` enregistre
`shell32` comme `minoinit` (DllRegisterServer rend 0), puis tape `C:\` dans le nom de fichier pour revenir à la
racine ; le bleu du dossier de « My Documents » et l'écran de « My Computer » (les icônes 235 et 16 de `shell32`,
recalculées à part depuis ses ressources : identiques au pixel près) ; le coin transparent vérifié est maintenant
celui de « Recent ». `logon` : `[minoinit] shell32.dll registered`. Quatre mutations font chacune échouer un test :
NtQueryKey qui demande KEY_QUERY_VALUE pour le nom (`notepad-saveas`), une référence sans aucun droit acceptée
(hôte), FileBasicInformation aligné sur 8 (`dir`), `minoinit` sans l'enregistrement (`logon`).

## Étape 33 : les contrôles ScrollBar (SB_CTL) et le sous-classement d'une fenêtre à procédure du serveur

Un item de dossier du menu Démarrer (« My Documents ») tuait `explorer` (voir [`m6-logon.md`](m6-logon.md)) : la
barre d'adresse de la fenêtre de dossier demande l'autocomplétion (SHAutoComplete de `shlwapi`), dont la liste
déroulante (CAutoComplete de `browseui`) crée dans son WM_CREATE une ListView, puis une poignée de taille et une barre
de défilement, deux contrôles de la classe ScrollBar. Deux manques, dans l'ordre où le second masquait le premier :

1. **Les barres des contrôles (SB_CTL)** (`win32k::scroll`, la troisième barre) : la fenêtre d'un contrôle ScrollBar
   garde l'état de sa barre dans ses octets de plus, un `SBWND` de ReactOS (`abi::user::SbWndExtra32` : `fVert`,
   `wDisableFlags`, puis un `SBCALC` dont les quatre premiers champs sont le `SBDATA`), que `user32` lit lui-même
   (GetScrollPos, SBM_GETPOS, SBM_GETRANGE ; `Window::write_extra`). SetScrollInfo et GetScrollInfo de SB_CTL ;
   GetScrollBarInfo(OBJID_CLIENT) : la barre est la zone cliente du contrôle (SBS_VERT), ses flèches et son curseur,
   l'état « indisponible » quand il n'y a rien à faire défiler ou que le contrôle est désactivé ; EnableScrollBar(SB_CTL)
   change les flèches (l'activation de la fenêtre, EnableWindow, journalisée : pas encore) ; ShowScrollBar(SB_CTL)
   montre ou cache le contrôle (ShowWindow). Le dessin est celui de `user32` (IntDrawScrollBar, son WM_PAINT).
   Un écart voulu : ReactOS marque la barre indisponible quand le contrôle n'est *pas* désactivé ; Mino suit Wine.
2. **GWLP_WNDPROC d'une fenêtre à procédure du serveur** (`win32k::window::replace_procedure`, IntSetWindowProc ;
   `window_procedure`, IntGetWindowProc). ATL sous-classe la poignée de taille (SubclassWindow : SetWindowLongPtr de
   GWLP_WNDPROC) ; la classe ScrollBar est une classe du serveur (`CSF_SERVERSIDEPROC`), et win32k refusait
   (`ERROR_CALL_NOT_IMPLEMENTED`). OnCreate rendait alors -1 et la liste n'était pas créée ; OnFinalMessage relâchait
   CAutoComplete sans l'AddRef de OnCreate, si bien qu'à la seconde tentative (SetOptions) l'objet était détruit, et
   SHAutoComplete appelait une méthode virtuelle pure (l'emplacement `__cxa_pure_virtual` de la vtable de
   CAutoComplete, `int 3` dans `browseui`, 80000003). Comme ReactOS : l'ancienne procédure d'une fenêtre à procédure
   du serveur est celle du client de son FNID, ANSI ou non, sans CALLPROCDATA ; la nouvelle en fait une procédure du
   client, dans son jeu de caractères (NULL garde l'actuelle) ; la procédure du client d'un FNID qui a une procédure
   du serveur rend celle-ci à la fenêtre (`WNDS_SERVERSIDEWINDOWPROC`, Unicode). Un contrôle (de FNID_BUTTON à
   FNID_GHOST, sauf Edit) passe d'un jeu de caractères à l'autre par ses deux procédures du client. Reste refusée
   l'ancienne procédure d'une fenêtre du client demandée dans l'autre jeu de caractères : ReactOS rend un
   CALLPROCDATA (UserGetCPD), que Mino n'a pas encore. `win32k::client` cherche dans une copie des procédures du
   client (`procedures`, `client_procedure_in`, `server_procedure_in`, `server_fnid_in`).

La fenêtre « My Documents » s'ouvre alors (titre, menus, barre d'outils) ; sa barre d'adresse et sa vue des fichiers
restent vides : voir l'étape 36.

Tests : hôte (`win32k::window` : une procédure du client remplacée, rendue, NULL qui la garde, l'autre jeu de
caractères refusé ; une procédure du serveur sous-classée en Unicode puis en ANSI et rendue ; un contrôle qui passe
d'un jeu de caractères à l'autre, Edit refusé ; `win32k::scroll`). Scénario `scroll-control`
(`tests/native/sbctl1.c`, AMD et Intel) : un contrôle ScrollBar vertical dans une fenêtre blanche ; SetScrollInfo et
GetScrollInfo, GetScrollPos et SBM_GETRANGE (lus par `user32` dans les octets de plus), SetScrollPos au-delà de la
fin, GetScrollBarInfo(OBJID_CLIENT), EnableScrollBar(ESB_DISABLE_UP), ShowScrollBar ; sous-classé comme par ATL
(SetWindowLongW : l'ancienne procédure est celle de la classe, ses messages passent par la nouvelle, la procédure
rendue), puis en ANSI (SetWindowLongA : celle, ANSI, de la classe ; rendue, la procédure du serveur revient) ; le
contrôle peint par `user32` (quatre pixels : la face et le symbole de la flèche du haut, le curseur au bout).
Deux mutations font échouer le scénario : SB_CTL refusé (les étapes 1 à 6), une procédure du serveur refusée (les
étapes 7 et 8).

## Étape 34 : la casse des noms que le format 8.3 tient (Io)

La barre des emplacements de l'étape 32 montrait « RECENT » : `shell32` crée le dossier `Recent` du profil
(CreateDirectoryW), et Io créait tout nom que le format 8.3 tient avec sa seule entrée 8.3, en majuscules
(`io::fat::FatVolume::add_entry_long`) ; la boîte relit le nom par NtQueryDirectoryFile. Io fait maintenant comme
`vfatfs`, le pilote FAT de ReactOS 0.4.16 (FATAddEntry de `dirwr.c`, vfat8Dot3ToString de `create.c`, lus comme
spécification ; le `drivers/filesystems/fastfat` de l'arbre de ReactOS est l'exemple FastFAT du WDK de Microsoft, qu'on
ne lit pas) :

- un nom tout en majuscules (`NTUSER.DAT`) garde son entrée 8.3 seule ;
- une base ou une extension toute en minuscules (`readme.txt`, `lower.TXT`) prend les drapeaux de casse de NT dans
  l'octet 12 de l'entrée 8.3 (`fat::CASE_LOWER_BASE` 0x08, `fat::CASE_LOWER_EXT` 0x10), sans nom long ; une partie
  sans lettre (`123`) n'en prend pas ;
- une base ou une extension à casse mixte (`Recent`, `MIXEXT.Txt`) reçoit des entrées de nom long (VFAT) devant son
  entrée 8.3, qui est le nom en majuscules, sans `~N` ;
- à la lecture (`FatVolume::dir_entries`, donc `Volume::list` et `Volume::entries`), une entrée sans nom long rend
  la partie que son drapeau dit en minuscules, comme son nom 8.3 ; la recherche reste sans casse.

Un caractère hors de l'ASCII n'entre déjà pas dans un nom 8.3 chez Io : il prend un nom long et un alias `~N`, comme
chez `vfatfs`. Les dossiers du profil que `minoinit` et `shell32` créent (`Desktop`, `Recent`, `NetHood`, `SendTo`,
`Cookies`…) gardent ainsi leur casse.

Tests : hôte (`io` : les sept règles de casse et ce qu'elles relisent, octet 12 et entrées de nom long compris ;
`Recent` créé par `Volume::create`, relu après un nouveau montage, une collision dans toute casse ; `fsck.vfat` quand
il est là). `notepad-saveas` vérifie deux pixels du texte « Recent » de la barre des emplacements (un trait du premier « e »,
et le fond au-dessus des minuscules, où était le haut du « C » de « RECENT »). Mutations : la règle
réduite à l'entrée 8.3 seule (les deux tests hôte, `notepad-saveas`), les drapeaux non relus (les deux tests hôte).

Les images des outils de l'hôte suivent la même règle : `libs/fatfs` (ADR-022, la source unique du format FAT32 de
Mino) la tient (`fatfs::image::case_flags`, `CASE_LOWER_BASE`, `CASE_LOWER_EXT`), Io la reprend (`io::fat` les
réexporte), et `fatfs::build` (les images de `tools/mkfat`, l'ESP et le volume système de l'image GPT de `xtask`)
écrit les drapeaux de casse ou le nom long. `xtask` met déjà en majuscules les noms de l'espace utilisateur qu'il
donne ; l'ESP de l'image GPT tient `kernel.elf` et `fat.img`, maintenant en minuscules (drapeaux 0x18), que le
micrologiciel et Io ouvrent sans casse. Tests : hôte (`fatfs` : les sept règles dans une image, relues par le
lecteur du noyau ; le lecteur à part de `xtask/src/fat32.rs` parcourt un dossier `Recent` et un `readme.txt`) ; trois
mutations (règle réduite à l'entrée seule : les tests de `fatfs` et d'Io ; octet 12 non écrit ; casse mixte sans nom
long).

Le nom 8.3 de toute entrée FAT est rendu dans FileBothDirectoryInformation (`io::FatMount::entries`,
`Listed::short_name`), comme `vfatfs` le rend (DirContext->ShortNameU, drapeaux de casse appliqués, `.` et `..`
compris) : `NTDLL.DLL` rend `NTDLL.DLL`, `readme.txt` rend `readme.txt`, `Recent` rend `RECENT`. Il ne venait
qu'à côté d'un nom long depuis le 2026-11-06 (commit `8e5103f`, la sonde de `dir` voulait un nom vide pour un nom
déjà en 8.3) ; le mainteneur a choisi de suivre `vfatfs`. NTFS garde son nom DOS apparié à un nom long. Tests : hôte
(`a_directory_is_enumerated` : `.`, `..`, `NTDLL.DLL`, `CONFIG` avec leur nom 8.3 ; `notes.txt` dans sa casse) ; la
sonde de `dir` (`tests/native/dir1.c`) attend `alternate NTDLL.DLL` et crée `readme.txt` et `Recent`, relus par
FindFirstFileW avec leur nom et leur nom de remplacement exacts ; une mutation (le nom 8.3 seulement à côté d'un nom
long : les deux tests hôte et `dir`).

## Étape 35 : réduire, agrandir et rétablir (ShowWindow, les boutons du titre, le double-clic)

Sous VirtualBox, les boutons Réduire et Agrandir du Bloc-notes et du gestionnaire des tâches étaient sans effet :
ShowWindow journalisait « minimizing and maximizing (co_WinPosMinMaximize): not yet » et rendait FALSE.

`winpos.c` de win32k (WinPosInitInternalPos, IntGetWindowPlacement, IntSetWindowPlacement, co_WinPosMinMaximize,
WinPosFindIconPos, co_WinPosArrangeIconicWindows, co_WinPosShowWindow, ActivateOtherWindowMin, co_WinPosGetMinMaxInfo),
`window.c` (la création d'une fenêtre réduite ou agrandie), `nonclient.c` (NC_DoButton, UserDrawCaptionButton,
NC_HandleNCLButtonDblClk, GetNCHitEx), `defwnd.c` (DefWndHandleSysCommand), `draw.c` (UITOOLS95_DrawFrameCaption),
`sysparams.c` (MINIMIZEDMETRICS), ReactOS comme spécification ; `win32k::winpos`, `win32k::defwnd`,
`win32k::sizemove`, `win32k::nonclient`, `win32k::paint::draw_caption_button`, `win32k::input::activate_other_min`.

| Partie | Ce que fait Mino |
|---|---|
| La place gardée (`winpos::InternalPos`, WinPosInitInternalPos) | dans la zone cliente du parent : le rectangle normal, pris la première fois qu'on regarde la fenêtre puis tant qu'elle n'est ni réduite ni agrandie ; la place de l'icône d'une fenêtre réduite (WPF_MININIT) ; la place d'une fenêtre agrandie (WPF_MAXINIT), depuis la zone de travail de son moniteur pour une fenêtre de premier niveau, aucune si elle couvre son moniteur (WNDS_MAXIMIZESTOMONITOR) ; WPF_SETMINPOSITION, WPF_RESTORETOMAXIMIZED |
| Réduire (`winpos::min_maximize`, SW_MINIMIZE, SW_SHOWMINIMIZED, SW_SHOWMINNOACTIVE, SW_FORCEMINIMIZE) | WPF_RESTORETOMAXIMIZED si elle était agrandie ; `WS_MINIMIZE` ; plus rien à peindre (RDW_VALIDATE) ; la place de son icône (`find_icon_pos`), de SM_CXMINIMIZED × SM_CYMINIMIZED ; SWP_STATECHANGED : WM_SIZE SIZE_MINIMIZED (0) par DefWindowProc de WM_WINDOWPOSCHANGED, sa zone cliente vide (WM_NCCALCSIZE) ; ni activée ni montée (SWP_NOACTIVATE ; SW_SHOWMINNOACTIVE garde aussi son rang) ; SW_SHOWMINIMIZED rend d'abord le clavier ; après SW_MINIMIZE, la fenêtre active du premier plan cède l'activation : à la première de ses sœurs visible, activée, ni réduite ni d'outils, sous les fenêtres toujours au-dessus puis depuis la première (ActivateOtherWindowMin), sinon comme à sa destruction (co_WinPosActivateOtherWindow) ; le clavier revient à son parent |
| Agrandir (SW_SHOWMAXIMIZED, SW_MAXIMIZE) | la place et la taille de WM_GETMINMAXINFO (`window::min_max_info` : sa place agrandie gardée en `ptMaxPosition` s'il en a une ; ce que la procédure laisse s'adapte à la zone de travail) : son cadre épais et ses bords hors de l'écran (−4, −4, 1288 × 808 sur 1280 × 800) ; `WS_MAXIMIZE` ; SWP_STATECHANGED : WM_SIZE SIZE_MAXIMIZED ; pas de WM_SHOWWINDOW (comme ReactOS) ; rien pour une fenêtre déjà agrandie et visible |
| Rétablir (SW_RESTORE, SW_SHOWNORMAL, SW_SHOWDEFAULT, SW_SHOWNOACTIVATE) | d'une fenêtre réduite : WM_QUERYOPEN d'abord (FALSE : elle le reste ; DefWindowProc rend TRUE), puis agrandie si elle l'était (WPF_RESTORETOMAXIMIZED, pas par SW_SHOWNOACTIVATE), sinon à son rectangle normal ; elle prend le clavier et, de premier niveau, WM_ACTIVATE ; d'une fenêtre agrandie : son rectangle normal, SWP_STATECHANGED, WM_SIZE SIZE_RESTORED |
| Créée réduite ou agrandie (`window::create_window`) | le style ôté puis rendu par co_WinPosMinMaximize, la fenêtre placée là sans être activée ; montrée ensuite par SW_SHOWMINIMIZED ou SW_SHOW si elle a WS_VISIBLE |
| Une fenêtre réduite sans shell (`winpos::icon_slot`) | une barre de titre de 166 × 25 (son bord, son titre, ses boutons Rétablir, Agrandir et Fermer), à la première case libre de la zone cliente de son parent, d'après MINIMIZEDMETRICS (SM_ARRANGE) : depuis le coin de `iArrange`, de côté ou (ARW_UP) vers le haut ou le bas, des cases pleines seulement, à un pixel du bord ; ARW_HIDE (ce que demande un shell qui montre lui-même les fenêtres réduites) : hors de l'écran, en (−32000, −32000), comme ReactOS. Une place donnée par SetWindowPlacement (WPF_SETMINPOSITION) est gardée |
| GetWindowPlacement (`winpos::placement`) | la place gardée, mise à jour d'abord ; les points de l'icône et de la fenêtre agrandie quand ils sont pris (pas la place agrandie d'une fenêtre qui couvre son moniteur), sinon (−1, −1) ; l'icône décalée dans la zone de travail comme le rectangle normal ; WPF_RESTORETOMAXIMIZED d'une fenêtre agrandie ou qui se rétablira agrandie ; WPF_SETMINPOSITION d'une fenêtre fille qui l'a reçu |
| SetWindowPlacement (`winpos::set_placement`) | les places données (l'icône seulement avec WPF_SETMINPOSITION) ramenées sur la zone de travail du moniteur le plus proche et gardées ; la fenêtre va à celle de son état (réduite : son icône, si elle a été donnée ; agrandie : sa place agrandie, si elle a été donnée ; sinon son rectangle normal), puis ShowWindow ; réduite alors, elle garde WPF_SETMINPOSITION et WPF_RESTORETOMAXIMIZED |
| Les boutons du titre (`sizemove::track_button`, NC_DoButton) | les fenêtres à peindre le sont d'abord ; le bouton peint enfoncé (creux, son symbole décalé d'un pixel : `nonclient::caption_button_ops`, `paint::draw_caption_button`) tant que la souris est dessus, relevé quand elle en sort et au relâchement ; relâché dessus : SC_MINIMIZE, SC_MAXIMIZE ou SC_RESTORE (le bouton Réduire d'une fenêtre réduite, Agrandir d'une fenêtre agrandie), SC_CLOSE |
| Le cadre (`nonclient`) | le glyphe Rétablir (Marlett `2`) pour Agrandir d'une fenêtre agrandie et Réduire d'une fenêtre réduite ; réduite, ni cadre épais ni trait sous le titre, son bord en relief autour |
| Le double-clic (`defwnd::double_click`, NC_HandleNCLButtonDblClk) | sur le titre d'une fenêtre à titre et bouton d'agrandissement : SC_RESTORE d'une fenêtre réduite ou agrandie, sinon SC_MAXIMIZE ; sur un bouton ou ailleurs, comme un appui |
| WM_NCHITTEST d'une fenêtre réduite (`defwnd::nc_hit_test`) | ses bords sont son titre (HTCAPTION), ses boutons répondent (HTCLOSE, HTMAXBUTTON, HTMINBUTTON) |

Écarts voulus avec ReactOS :
- **Les fenêtres réduites restent à l'écran.** ReactOS met MINIMIZEDMETRICS `iArrange` à ARW_HIDE (sa valeur par
  défaut dans `sysparams.c`) et WinPosFindIconPos envoie toute fenêtre de premier niveau réduite en (−32000, −32000) :
  son explorateur les montre dans sa barre des tâches. Mino n'a pas de shell qui le fasse (le bureau de
  `DESKTOP1.EXE` dessine sa barre) : réduite, une fenêtre y disparaîtrait sans retour. Mino prend donc
  `ARW_BOTTOMLEFT | ARW_RIGHT` (SM_ARRANGE vaut 0), comme un système sans shell, et suit `iArrange` comme le
  prévoient MINIMIZEDMETRICS et co_WinPosArrangeIconicWindows (« FIXME: Support Minimize Metrics » chez ReactOS, qui
  part toujours d'en bas à gauche) ; un shell demandera ARW_HIDE par SPI_SETMINIMIZEDMETRICS (pas encore).
- **Les boutons d'une fenêtre réduite répondent.** GetNCHitEx de ReactOS rend HTCAPTION sur toute une fenêtre
  réduite ; sa version d'avant (DefWndNCHitTest, gardée sous `#if 0`) et XP donnent les boutons de sa barre. Sans
  shell, le bouton Rétablir est le chemin d'une fenêtre réduite à la souris (le double-clic sur sa barre aussi).
- **La première case libre.** WinPosFindIconPos s'arrête à la première icône sœur qui n'est pas à la case qu'il
  essaie ; co_WinPosArrangeIconicWindows passe au-delà du bord droit. Mino prend la première case qu'aucune autre
  icône n'occupe, en cases pleines.
- **SW_FORCEMINIMIZE réduit**, comme le dit l'API (même si le thread de la fenêtre ne répond pas) ; ReactOS cache la
  fenêtre (IntForceMinimizeWindow, pour ses fenêtres fantômes).
- **Un rectangle, pas une taille.** co_WinPosMinMaximize rend à co_WinPosShowWindow un rectangle dont il passe la
  droite et le bas comme taille ; il y met tantôt la taille, tantôt le coin opposé (rétablie agrandie depuis réduite,
  une fenêtre y gagnait sa place en taille). Mino rend un rectangle et l'appelant en tire la taille.
- **Le rectangle normal de `InternalPos`.** ReactOS rétablit au rectangle de GetWindowPlacement, décalé dans la zone
  de travail (faux quand elle ne commence pas au coin du moniteur) ; Mino prend celui qu'il garde, dans la zone
  cliente du parent.
- **(−1, −1) n'est pas une place.** SetWindowPlacement ramène chaque point sur l'écran (make_point_onscreen), et
  ReactOS fait de (−1, −1) le point (0, 0) : le Bloc-notes, qui rend ce que GetWindowPlacement lui donne, agrandi,
  aurait son cadre à l'écran en haut à gauche et débordé à droite et en bas. Mino garde (−1, −1) comme « pas donné ».
- **SetWindowPlacement d'une fenêtre jamais regardée.** ReactOS ne marque pas la place comme prise ; la première
  lecture d'après (co_WinPosMinMaximize) écrasait le rectangle normal donné par celui de la fenêtre. Mino prend
  d'abord la place présente, puis les places données.

Pas encore (journalisé une fois) : cacher et remontrer les fenêtres possédées d'une fenêtre réduite
(IntShowOwnedPopups) ; le crochet CBT (HCBT_MINMAX) ; la fenêtre active d'avant (`spwndActivePrev`) qu'essaie
d'abord ActivateOtherWindowMin ; SW_HIDE de la fenêtre active ne cède toujours pas l'activation (comme avant) ; le
double-clic sur le bord du haut ou du bas (ReactOS agrandit en hauteur) ; SPI_SETMINIMIZEDMETRICS et
SPI_GETMINIMIZEDMETRICS ; le menu de la fenêtre (Réduire, Agrandir, Restaurer y sont des commandes).

Vu en chemin, pas fait : `window::link` met une fenêtre placée par HWND_TOP au-dessus de la dernière de ses sœurs
quand toutes les autres sont toujours au-dessus (WS_EX_TOPMOST), comme IntLinkHwnd de ReactOS (sa boucle s'arrête
à la dernière sœur au lieu de passer après elle) : agrandie, une fenêtre y passait sur une fenêtre toujours
au-dessus réduite. Le banc d'essai garde une fenêtre cachée sous les autres.

Le banc d'essai : `tests/native/minmax1.c` (`MINMAX1.EXE`, MinGW), scénario `minmax`, à la place de
`winlogon.exe`. E est créée agrandie, F réduite ; B (toujours au-dessus), T (une fenêtre d'outils) et W (active,
100, 100, 400 × 300). ShowWindow de W : SW_MINIMIZE (sa barre à la case libre à côté de celle de F, WM_SIZE
SIZE_MINIMIZED, B activée plutôt que T, le clavier avec elle), SW_RESTORE refusé par WM_QUERYOPEN, puis accepté,
SW_SHOWMAXIMIZED (−4, −4, 1288 × 808 ; zone cliente 1280 × 780), réduite depuis agrandie puis rétablie agrandie,
rétablie ; une place agrandie à elle (WM_GETMINMAXINFO), gardée ensuite ; SetWindowPlacement d'un rectangle normal
pendant qu'elle est agrandie, d'une place d'icône (WPF_SETMINPOSITION) pour D. Chaque fois l'état (IsIconic,
IsZoomed, GetWindowRect), GetWindowPlacement et, pour SW_MINIMIZE, SW_RESTORE et SW_SHOWMAXIMIZED, les messages
reçus. Puis la souris de QEMU : le bouton Agrandir, Rétablir de la fenêtre agrandie, Réduire, Rétablir de la barre
réduite, un double-clic sur le titre, un autre sur le titre de la fenêtre agrandie, un appui sur Agrandir relâché
dans la zone cliente (rien) ; enfin B réduite, W agrandie, son bouton Rétablir enfoncé et tenu pendant la capture.
L'écran : W agrandie, son titre et sa zone cliente jusqu'aux bords (son cadre hors de l'écran), son bouton
Rétablir creux, son symbole décalé ; la barre réduite de B en bas à gauche, au-dessus, inactive, avec le symbole
Rétablir.

Tests : hôte (`winpos` : les commandes de ShowWindow, WinPosInitInternalPos, GetWindowPlacement d'une fenêtre
réduite ou agrandie, les cases des fenêtres réduites selon MINIMIZEDMETRICS, make_point_onscreen et (−1, −1) ;
`defwnd` : WM_NCHITTEST d'une fenêtre réduite, le double-clic ; `sizemove` : les commandes des boutons ;
`nonclient` : le bouton enfoncé, seul, sur le cadre ; la barre d'une fenêtre réduite et ses symboles) ; `minmax`
sur AMD et Intel. Chacune de ces mutations le fait échouer : pas de `WS_MINIMIZE` ; MINIMIZEDMETRICS à ARW_HIDE ;
la première case même prise ; la fenêtre agrandie ailleurs qu'à la place de WM_GETMINMAXINFO ; rétablie ailleurs
qu'à son rectangle normal ; pas de WPF_RESTORETOMAXIMIZED ; WM_QUERYOPEN ignoré ; l'activation gardée par la
fenêtre réduite ; ActivateOtherWindowMin sauté ; GetWindowPlacement qui prend le rectangle présent pour normal ;
SetWindowPlacement qui ne garde pas le rectangle normal ; WPF_SETMINPOSITION pris trop tard ; la place agrandie pas
gardée ; rien pour une fenêtre créée réduite ou agrandie ; le bouton pas peint enfoncé ; le bouton Réduire d'une
fenêtre réduite qui la réduit ; une fenêtre réduite toute en titre ; le double-clic sans effet ; le symbole
Agrandir sur une fenêtre agrandie, Réduire sur une fenêtre réduite. `menu`, `notepad`, `desktop-launch` passent sur
AMD et Intel ; `gui` échoue comme au commit de départ (l'ordre des WM_PAINT des sœurs, de bas en haut depuis
l'étape 24 : voir la passation).

## Étape 36 : la fenêtre de dossier montre ses fichiers (SPI_GETNONCLIENTMETRICS de Vista, GetComboBoxInfo, LockWindowUpdate, DrawCaption)

La fenêtre de dossier d'`explorer` (CShellBrowser de `browseui` : « My Documents » du menu Démarrer, ou Win+R puis
`C:\WINDOWS`) s'ouvrait avec son titre, ses menus et sa barre d'outils, mais sans barre d'adresse et sur une vue grise.
NtUserLockWindowUpdate et NtUserDrawCaption, journalisés absents en chemin, n'y étaient pour rien. Une trace
temporaire des services de win32k appelés par le thread de la fenêtre (le nom de la classe de chaque fenêtre créée,
retirée depuis) montrait que SHELLDLL_DefView, la vue, était bien créée et listait le dossier, mais placée en
y = 32767 avec une hauteur négative, et que le ReBar de la barre d'adresse avait 32767 pixels de haut.

Le banc `tests/native/rebar1.c` reproduit la barre d'adresse : un ReBar de `comctl32` avec deux bandes de barres
d'outils, puis une bande ComboBoxEx titrée « Address » (CDockSite::GetRBBandInfo). L'en-tête de la bande, la place du
titre, faisait des millions de pixels de large : la police du ReBar (REBAR_Create : `lfMenuFont` de
SPI_GETNONCLIENTMETRICS) était faite de n'importe quoi. Le `comctl32` de ReactOS est compilé pour Vista et passe à
SPI_GETNONCLIENTMETRICS une NONCLIENTMETRICSW de 504 octets (`iPaddedBorderWidth` après les 500 d'XP). Mino la
refusait, comme XP, et `comctl32` ne vérifie pas le résultat : sa structure restait non initialisée. Le SpiGet de
ReactOS copie `sizeof(NONCLIENTMETRICSW)` sans lire `cbSize`. **Écart voulu avec XP** : Mino accepte 500 et 504
octets (`uiParam` nul ou égal à `cbSize`), remplit les 500 d'XP, met `iPaddedBorderWidth` à 0 et rend `cbSize` tel
quel ; une autre taille est refusée (`ERROR_INVALID_PARAMETER`). La bande d'adresse se place alors à (540, 21)-(696,
51) à côté des liens, ou sur sa propre ligne avec `RBBS_BREAK`, le ReBar a 55 pixels de haut, et la vue de la
fenêtre de dossier montre les fichiers.

En chemin :

- NtUserGetComboBoxInfo (`sys::message::nt_user_get_combo_box_info`) : `cbSize` de 52 octets au moins, sinon
  `ERROR_INVALID_PARAMETER`, puis CB_GETCOMBOBOXINFO envoyé au contrôle, qui remplit lui-même sa COMBOBOXINFO. La
  boîte « Run » et la barre d'adresse le demandent. **Écart voulu** : ReactOS lit lui-même la HEADCOMBO d'un ComboBox
  du système et n'envoie le message qu'aux autres. Mino l'envoie à tous : la structure est celle de `user32`, qui y
  répond. Pas encore : un ComboBox d'un autre processus (le message y irait avec une adresse de l'appelant).
- NtUserLockWindowUpdate (`win32k::dce::lock_window_update`). ReactOS n'a qu'un stub qui rend FALSE, et
  CShellBrowser::BrowseToPath ne déverrouille que s'il a pu verrouiller. Une seule fenêtre est verrouillée à la fois
  (une autre : FALSE). Les DC de cette fenêtre et de ses filles, même pris avant le verrou, ont une région visible
  vide (sauf `DCX_LOCKWINDOWUPDATE`), et son cadre peint par le noyau aussi (`paint::draw_frame_ops`). Une fenêtre
  détruite rend le verrou. Au déverrouillage, la fenêtre est invalidée en entier, cadre, effacement et filles
  compris. XP n'invalide que ce qu'on a tenté d'y peindre, un rectangle que Mino ne tient pas encore. Sans fenêtre
  verrouillée, LockWindowUpdate(NULL) rend TRUE, comme Wine.
- NtUserDrawCaption (`win32k::paint::draw_caption`, `nonclient::caption_ops` ; UserDrawCaption et
  UserDrawCaptionBar de ReactOS comme spécification). Après WM_SETTEXT, DefWindowProc de `user32` (UserPaintCaption)
  repeint le titre par NtUserDrawCaption(`DC_DRAWCAPTIONMD`, rectangle vide) : sans lui, le titre gardait l'ancien
  texte jusqu'au WM_NCPAINT suivant. Mino repeint alors tout le cadre, actif ou non selon `DC_ACTIVE`, et ReactOS le
  titre et le bord seulement. Avec un rectangle, le titre est dessiné dans le DC donné : le fond (la couleur du titre
  actif ou inactif, le dégradé avec `DC_GRADIENT`, la face d'un bouton avec `DC_INBUTTON`), l'icône (`DC_ICON`) et
  le texte de la fenêtre (`DC_TEXT`, en Tahoma normal avec `DC_SMALLCAP`). Les erreurs : sans rectangle,
  `ERROR_NOACCESS` ; une fenêtre inconnue, `ERROR_INVALID_WINDOW_HANDLE` ; un DC inconnu, `ERROR_INVALID_HANDLE`.
  Pas encore : NtUserDrawCaptionTemp (une police, une icône ou un texte donnés), `WNDS2_CAPTIONTEXTTRUNCATED`.
- `xtask` : le jeton `pause:MS` dans `keys` attend avant le jeton suivant (une fenêtre que les touches d'avant
  ouvrent).

Vus en chemin, pas faits : NtUserSetActiveWindow, EnableWindow (NtUserCallTwoParam 0x60), NtUserCallOneParam 0x20 et
0x28, NtUserSetParent, NtUserEnumDisplayMonitors, NtGdiBeginPath, NtGdiEndPath, NtGdiPathToRegion,
NtQueryInformationThread (classe 0x10), NtNotifyChangeDirectoryFile (« ReadDirectoryChangesW … failed »),
NtUserFindWindowEx.

Tests : scénario `rebar` (`tests/native/rebar1.c`, AMD et Intel) : SPI_GETNONCLIENTMETRICS de 500, 504 et 503
octets, GetComboBoxInfo d'un ComboBox de `user32` (et un `cbSize` trop petit), la police du ReBar, la place de la
bande d'adresse et la hauteur du ReBar. Scénario `caption` (`tests/native/caption1.c`, AMD et Intel) : le titre effacé
repeint par SetWindowText ; LockWindowUpdate (une autre fenêtre refusée, les boîtes de découpage des DC de la fenêtre,
d'un DC pris avant, de sa fille, avec `DCX_LOCKWINDOWUPDATE`, d'une autre fenêtre ; un PatBlt sans effet ; le titre
pas repeint), le déverrouillage (la zone cliente à mettre à jour, WM_PAINT, le titre repeint), les cas limites ;
DrawCaption dans un rectangle de l'écran (les couleurs, le dégradé, le texte, l'icône, les erreurs). Scénario
`folder-view` (`disk = system`, deux démarrages) : après le logon, Win+R puis `C:\WINDOWS` ; l'écran montre la barre
d'adresse blanche, la vue des fichiers blanche (elle était grise) et la barre d'état.

Hôte : `nonclient::caption_ops` (le fond, le dégradé, la face d'un bouton, un rectangle remis en ordre, le
texte et sa couleur, rien sans police), `xtask::screen::pause_ms`. Chacune de ces neuf mutations fait échouer
`rebar` ou `caption` : 504 octets refusés ; NtUserGetComboBoxInfo retiré ; les DC de la fenêtre verrouillée qui
peignent ; son cadre qui peint ; rien d'invalidé au déverrouillage ; les DC pris avant le verrou gardés tels
quels ; le titre pas repeint (`DC_DRAWCAPTIONMD`) ; `DC_INBUTTON` ignoré ; une seconde fenêtre verrouillée.

La barre d'état de `comctl32` prend aussi sa police de SPI_GETNONCLIENTMETRICS (`lfStatusFont`, demandée avec
504 octets) : refusée, elle avait elle aussi une police de n'importe quoi, et les pixels attendus du scénario
`notepad` en venaient. Ils sont refaits d'après les avances de Tahoma à 11 pixels, lues dans la police : le texte
part de x = 6, le 2 de « Line 2 » est un pixel plus à droite qu'avant. La suite de démarrage : 128 runs sur 132
passent, `ntfs-readonly` est sauté (pas de `mkntfs`). `notepad` échouait sur AMD et Intel avec ses anciens
pixels et passe avec les nouveaux. `rostests` (43/84) et `rostests-kernel32` (15/29) restent sous leurs
planchers, comme `main` (`93197f3`) sur la même machine : NtProtectVirtualMemory y dépasse son délai, et
l'apitest Pipes est une course (son lecteur lit l'extrémité serveur avant que le client se connecte :
ERROR_PIPE_LISTENING).

## Étape 37 : le menu de la fenêtre (le menu système) ; cacher la fenêtre active

Demandés après l'étape 35 : le menu de la fenêtre (l'icône du titre, Alt+Espace : Restaurer, Réduire, Agrandir,
Fermer) n'existait pas, et cacher la fenêtre active (ShowWindow SW_HIDE) ne passait l'activation à aucune autre.

`menu.c` de win32k (IntGetSystemMenu, MENU_GetSystemMenu, IntSetSystemMenu, MENU_InitSysMenuPopup,
MENU_TrackMouseMenuBar, MENU_TrackKbdMenuBar, MENU_ShowSubPopup, MENU_ButtonDown, MENU_PtMenu, MENU_TrackMenu,
MENU_DrawPopupGlyph, MENU_GetBitmapItemSize, MENU_CalcItemSize, MENU_DrawMenuItem, NtUserGetSystemMenu,
NtUserSetSystemMenu), `nonclient.c` (GetNCHitEx, NC_GetSysPopupPos, NC_HandleNCLButtonDown,
NC_HandleNCLButtonDblClk), `winpos.c` (co_WinPosShowWindow), `window.c` (co_UserFreeWindow), ReactOS comme
spécification ; `win32k::sysmenu`, `win32k::menutrack`, `win32k::menupopup`, `win32k::defwnd`,
`win32k::sizemove`, `win32k::winpos`.

| Partie | Ce que fait Mino |
|---|---|
| Cacher la fenêtre active (`winpos::show_window`) | comme pour SW_MINIMIZE, la fenêtre active du premier plan cachée par SW_HIDE cède l'activation (`give_up_activation` : ActivateOtherWindowMin, sinon co_WinPosActivateOtherWindow) et le clavier revient à son parent ; ShowWindow rendait avant d'y arriver. Seule fenêtre de son thread, elle est désactivée (WM_NCACTIVATE, WM_ACTIVATE WA_INACTIVE, WM_KILLFOCUS après WM_WINDOWPOSCHANGED, comme WmHideOverlappedSeq de Wine) : le scénario `gui` attend maintenant ces trois messages |
| Le menu système (`sysmenu::get`, IntGetSystemMenu, MENU_GetSystemMenu) | un menu d'un seul item (MNF_SYSMENU), dans `WND.SystemMenu` ; son sous-menu, ce que rend GetSystemMenu (MNF_SYSSUBMENU), est le gabarit SYSMENU de `user32` (SYSMENUMDI d'une fenêtre fille MDI) chargé par le rappel LoadMenu (`callback::load_menu`) : Restore, Move, Size, Minimize, Maximize, un séparateur, Close ; MNS_CHECKORBMP, les glyphes HBMMENU_POPUP_RESTORE, _MINIMIZE, _MAXIMIZE, _CLOSE, Close par défaut, retiré d'une classe CS_NOCLOSE ; créé au premier besoin pour une fenêtre WS_SYSMENU ; GetSystemMenu(TRUE) le détruit et ne rend rien ; détruit avec la fenêtre (`destroy::finish`) |
| NtUserGetSystemMenu, NtUserSetSystemMenu (`sys::menu`) | le menu déroulant du menu système ; un menu déroulant de l'application à la place (IntSetSystemMenu : l'ancien détruit, le nouveau dans un menu d'un item neuf) |
| Les items selon la fenêtre (`sysmenu::popup_states`, MENU_InitSysMenuPopup) | avant d'être montré : Size grisé sans cadre épais ou pour une fenêtre réduite ou agrandie, Move pour une fenêtre réduite ou agrandie, Minimize sans WS_MINIMIZEBOX ou pour une fenêtre réduite, Maximize sans WS_MAXIMIZEBOX ou pour une fenêtre agrandie, Restore pour une fenêtre ni réduite ni agrandie, Close pour une classe CS_NOCLOSE (sinon il garde l'état qu'on lui a donné) ; l'item par défaut : Restore d'une fenêtre réduite, depuis le titre Restore ou Maximize, Close depuis l'icône ou le clavier |
| L'icône du titre (`defwnd::nc_hit_test`, GetNCHitEx) | HTSYSMENU sur la hauteur du titre moins un depuis le bord gauche, pour une fenêtre WS_SYSMENU qui a une icône (NC_IconForWindow : `cursor::caption_icon`), pas une fenêtre d'outils ; une fenêtre réduite aussi (sa barre sans shell) |
| Ouvrir à la souris (`sizemove::nc_lbutton_down`, `menutrack::track_mouse_menu_bar`) | WM_NCLBUTTONDOWN sur HTSYSMENU : WM_SYSCOMMAND SC_MOUSEMENU + HTSYSMENU ; le suivi du menu d'un item (son item est l'icône : MENU_ButtonDown, MENU_PtMenu), son menu ouvert sous l'icône (`sysmenu::icon_rect`, NC_GetSysPopupPos ; toute la fenêtre réduite), WM_INITMENUPOPUP (le mot haut de lParam TRUE), WM_MENUSELECT (MF_SYSMENU) ; un second clic sur l'icône le referme ; un double-clic sur l'icône ferme la fenêtre (SC_CLOSE si Close est actif ; aussi par WM_NCLBUTTONDBLCLK, `defwnd::DoubleClick::Close`) |
| Ouvrir au clavier (`menutrack::track_kbd_menu_bar`) | Alt+Espace (SC_KEYMENU ' ') ; Alt, F10 ou Alt et une lettre d'une fenêtre réduite ou sans barre : le menu système à la place de la barre (rien sans WS_SYSMENU), son icône sélectionnée ; Alt+Espace ouvre aussi son menu (un VK_RETURN posté) ; les lettres soulignées choisissent (Mi**n**imize…) |
| Choisir | l'item choisi poste WM_SYSCOMMAND de son identifiant à la fenêtre (`menutrack::exec_focused`) ; DefWindowProc exécute SC_MINIMIZE, SC_MAXIMIZE, SC_RESTORE et SC_CLOSE (`sizemove::sys_command`) ; un item ajouté par l'application (AppendMenu sur GetSystemMenu) lui envoie le sien |
| Le dessin (`menupopup`) | la place d'un glyphe de SM_CXSIZE - 2 × SM_CYSIZE - 4 avant les deux places de coche (MENU_CalcItemSize) ; le symbole de Marlett (`2`, `0`, `1`, `r`) dedans moins deux pixels, grisé en relief (COLOR_HIGHLIGHTTEXT décalé d'un pixel) ; avec MNS_CHECKORBMP, le texte de tous les items après le plus large des glyphes (`cxTextAlign`) |

Écarts voulus avec ReactOS : le menu système est créé au premier besoin (GetSystemMenu, le suivi), pas au premier
dessin du bouton de fermeture, qui lit chez ReactOS l'état de SC_CLOSE : le cadre se peint aussi hors du
processus de la fenêtre, où le rappel LoadMenu est impossible ; le gabarit chargé est gardé tel quel, ReactOS le
clone (IntCloneMenu) avant de détruire l'original ; WM_INITMENU porte au clavier aussi le menu de GetSystemMenu
(ReactOS y met le menu d'un item, à la souris celui de GetSystemMenu) ; pendant le suivi, le double-clic sur
l'icône finit le suivi et poste SC_CLOSE lui-même : ReactOS laisse le message à DefWindowProc
(WM_NCLBUTTONDBLCLK), qu'ici la capture du menu a fait message de la zone cliente.

Pas encore : le clic droit sur le titre (fait à l'étape 38), SC_MOVE et
SC_SIZE au clavier (faits à l'étape 39), ←/→ entre le menu système et la barre (fait à l'étape 40),
le bouton de fermeture grisé quand Close l'est, WM_POPUPSYSTEMMENU (la barre des tâches), le menu système d'un
bureau (MNF_SYSDESKMN). Vu, pas fait : SetForegroundWindow refuse une fenêtre réduite (`input::can_activate`,
la règle de co_WinPosActivateOtherWindow), ReactOS l'active.

Le banc d'essai : `tests/native/sysmenu1.c` (`SYSMENU1.EXE`, MinGW), scénario `window-menu`, à la place de
`winlogon.exe`. W (100, 100, 400 × 300) et B. SW_HIDE de W active : B active, au premier plan, avec le clavier ;
SW_SHOW : W active. GetSystemMenu : sept items de Restore à Close, le même handle, le glyphe de Restore, Close par
défaut ; GetSystemMenu(TRUE) n'en rend pas, le suivant est neuf ; aucun sans WS_SYSMENU ; un item « Min&o »
(0x0110) ajouté. Puis QEMU : Alt+Espace et n (W réduite, B active ; Restore était grisé, Close par défaut) ; un
clic sur l'icône de W réduite (en bas à gauche) et r (rétablie ; Minimize était grisé, Restore par défaut) ; un
clic sur l'icône de W et x (agrandie) ; Alt+Espace et o (WM_SYSCOMMAND 0x0110) ; un double-clic sur l'icône de W
agrandie (SC_CLOSE, W détruite). Chaque menu ouvert envoie WM_INITMENUPOPUP du menu de GetSystemMenu, le mot haut
de lParam TRUE. Une capture pendant le suivi montre le menu sous l'icône : Restore grisé en relief, les glyphes de
Minimize, Maximize et Close, Close en gras avec « Alt+F4 », puis « Mino ».

Tests : hôte (`sysmenu` : les items et l'item par défaut d'une fenêtre normale, agrandie, réduite, d'un dialogue
CS_NOCLOSE ; la place du menu sous l'icône ; `menupopup` : la place d'un glyphe et des items qui n'en ont pas ;
`defwnd` : le double-clic sur l'icône) ; `window-menu` sur AMD et Intel. Cinq mutations le font échouer
chacune : SW_HIDE qui ne cède pas l'activation, pas de HTSYSMENU, Alt+Espace ignoré, Restore grisé à l'envers, le
double-clic sur l'icône sans effet.

## Étape 38 : le clic droit sur le titre

Demandé après l'étape 37 : un clic droit sur le titre d'une fenêtre (ou sur son icône) n'ouvrait pas le menu de la
fenêtre ; DefWindowProc journalisait WM_NCRBUTTONDOWN et WM_CONTEXTMENU comme « pas encore ».

`nonclient.c` (NC_HandleNCRButtonDown), `defwnd.c` de win32k (IntDefWindowProc : WM_NCRBUTTONDOWN, WM_CONTEXTMENU),
`menu.c` (IntTrackPopupMenuEx), `defwnd.c` de `user32` (User32DefWindowProc : WM_RBUTTONUP, WM_CONTEXTMENU d'une
fenêtre fille), ReactOS comme spécification ; `win32k::sysmenu`, `win32k::defwnd`, `win32k::menutrack`.

| Partie | Ce que fait Mino |
|---|---|
| Qui fait quoi | `user32` fait de WM_RBUTTONUP dans la zone cliente un WM_CONTEXTMENU (la fenêtre, le point à l'écran) et passe celui d'une fenêtre fille à son parent ; il confie au noyau (NtUserMessageCall, FNID_DEFWINDOWPROC) WM_NCRBUTTONDOWN et le WM_CONTEXTMENU d'une fenêtre de premier niveau |
| WM_NCRBUTTONDOWN (`sysmenu::nc_rbutton_down`, NC_HandleNCRButtonDown) | sur le titre ou son icône d'une fenêtre qui a un menu système, la fenêtre prend la souris ; les messages de la souris sortent de la file sans être distribués (après WH_SYSMSGFILTER et WH_MSGFILTER, MSGF_MAX) jusqu'au relâchement du bouton droit ; si elle perd la souris, rien ; relâché sur le titre, l'icône ou une barre de défilement, WM_CONTEXTMENU (elle, le point du relâchement) |
| WM_CONTEXTMENU (`sysmenu::context_menu`) | une fenêtre fille le passe à son parent ; sinon, au point sur le titre ou son icône (GetNCHitEx), le menu système (IntGetSystemMenu) mis à l'état de la fenêtre depuis cet endroit (MENU_InitSysMenuPopup), puis suivi comme un menu déroulant au point (`menutrack::track_popup_menu`), TPM_LEFTBUTTON et TPM_RIGHTBUTTON depuis le titre, TPM_LEFTBUTTON seul depuis l'icône (`sysmenu::context_menu_buttons`) ; ailleurs (la zone cliente, (−1, −1) du clavier), rien ; DefWindowProc ne revient qu'à la fin du suivi |
| TrackPopupMenu d'un menu système (`menutrack::track_popup_menu`, IntTrackPopupMenuEx) | après WM_INITMENUPOPUP, un menu MNF_SYSMENU prend l'état de sa fenêtre comme ouvert de l'icône (HTSYSMENU) : Close par défaut, aussi depuis le titre, comme chez ReactOS ; vaut aussi pour TrackPopupMenu(GetSystemMenu(…)) d'une application |
| Choisir | comme à l'étape 37 : WM_SYSCOMMAND posté de l'item (`menutrack::exec_focused`), que DefWindowProc exécute |

Écart voulu avec ReactOS : un WM_QUIT pendant la boucle du bouton droit la finit, reposté, sans WM_CONTEXTMENU
(ReactOS l'envoie alors, au point du WM_QUIT), comme la boucle des boutons du titre (`sizemove::track_button`).

Pas encore : TPM_SYSTEM_MENU (GUI_SYSTEMMENUMODE de GetGUIThreadInfo, que Mino ne fait pas), le menu des barres de
défilement (pas plus chez ReactOS : « Scroll Menu Not Supported »), Maj+F10 et VK_APPS (WM_CONTEXTMENU du clavier,
qui n'ouvre de toute façon pas le menu système). Vu, pas fait : DefWindowProc de WM_LBUTTONDOWN, WM_RBUTTONDOWN et
WM_MBUTTONDOWN oublie chez ReactOS un Alt enfoncé (QF_FMENUSTATUS) ; Mino ne le fait pas et journalise le message
(« message 0x0204 not yet »).

Le banc d'essai : `tests/native/sysmenu1.c`, scénario `window-menu`, trois étapes de plus avant le double-clic qui
ferme W (étape 10). W agrandie : un clic droit dans la zone cliente (400, 300) donne WM_CONTEXTMENU (W, (400, 300))
et aucun menu (étape 7) ; un clic droit sur le titre (400, 10) ouvre le menu là (sa fenêtre en (400, 10),
WM_ENTERIDLE ; Maximize en (403, 81)-(555, 98) selon GetMenuItemRect sans fenêtre), WM_CONTEXTMENU revient après
le suivi, r rétablit W ; le menu montrait Maximize grisé, Close par défaut (étape 8). W rétablie : un clic droit
sur son titre (250, 110) ouvre le menu là, et le bouton droit sur Maximize l'agrandit (TPM_RIGHTBUTTON, étape 9).

Tests : hôte (`sysmenu` : les endroits qui demandent WM_CONTEXTMENU au relâchement, les boutons du menu depuis le
titre et l'icône, rien dans la zone cliente) ; `window-menu` sur AMD et Intel. Six mutations le font échouer
chacune : WM_NCRBUTTONDOWN ignoré, le relâchement sur le titre qui ne demande rien, le menu ouvert aussi depuis la
zone cliente, le menu sous l'icône au lieu du point, le bouton droit refusé depuis le titre, TrackPopupMenu qui ne
met pas le menu système à l'état de la fenêtre (Restore par défaut au lieu de Close).

## Étape 39 : déplacer et redimensionner au clavier (SC_MOVE, SC_SIZE)

Demandé après l'étape 38 : Move et Size du menu de la fenêtre ne faisaient rien. WM_SYSCOMMAND SC_MOVE ou SC_SIZE
sans endroit (les quatre bits bas à 0) arrivait à DefWindowProc, qui journalisait « moving or sizing with the
keyboard: not yet ».

`nonclient.c` de win32k (DefWndStartSizeMove, DefWndDoSizeMove), `cursoricon.c` (UserSetCursorPos), ReactOS comme
spécification ; `win32k::sizemove`, `win32k::mouse`.

| Partie | Ce que fait Mino |
|---|---|
| Quand (`sizemove::can_size_move`) | une fenêtre visible et pas agrandie ; Size demande en plus un cadre épais (UserHasThickFrameStyle : pas un cadre de dialogue seul) et une fenêtre pas réduite ; sinon WM_SYSCOMMAND revient tout de suite, sans WM_ENTERSIZEMOVE |
| Déplacer (`sizemove::keyboard_start`, `move_start_point`) | le curseur va au milieu du titre, sans l'icône (SM_CXSIZE + 1 avec WS_SYSMENU) ni les boutons Réduire et Agrandir (autant chacun), à SM_CYSIZE / 2 sous le haut de la fenêtre ; puis WM_SETCURSOR (HTCAPTION, WM_MOUSEMOVE) |
| Redimensionner (`sizemove::keyboard_start`, `size_start_edge`) | la fenêtre prend la souris et une boucle attend un bord : une flèche le choisit (le curseur va au milieu de ce bord, à mi-épaisseur du cadre), ou la souris, ramenée dans la fenêtre, en atteint un ; Entrée, Échap ou un clic relâché renoncent, sans WM_ENTERSIZEMOVE ; les autres messages sont distribués |
| La boucle (`sizemove::size_move`) | celle de la souris : WM_ENTERSIZEMOVE, la fenêtre suit le curseur, son contenu avec elle ; une flèche déplace le curseur de 8 pixels (`sizemove::arrow_step`), et le WM_MOUSEMOVE qui en vient fait le reste ; la souris aussi déplace ou redimensionne ; Entrée ou un clic relâché finit, Échap rend la place de départ ; les autres touches enfoncées sont mangées, comme chez ReactOS (aussi pendant un déplacement à la souris, où les flèches déplacent elles aussi le curseur) |
| Placer le curseur (`mouse::set_cursor_pos`, UserSetCursorPos sans les crochets) | le curseur va au point, borné à l'écran, et un WM_MOUSEMOVE brut part comme d'un mouvement de la souris (à la fenêtre qui a la capture, sinon à celle sous le curseur). La boucle tient sa propre idée de la place du curseur : deux flèches lues avant le mouvement de la première comptent toutes les deux |

Écart voulu avec ReactOS : sa boucle finit aussi sur un WM_MOUSEMOVE sans le bouton gauche (les deux branches de
`g_bWindowSnapEnabled`) ; au clavier, le mouvement que produit UserSetCursorPos la finirait aussitôt. Mino ne la
finit qu'au relâchement du bouton gauche, à Entrée ou à Échap.

Pas encore : le cadre en pointillés (sans le contenu), WM_MOVING et WM_SIZING, WH_MSGFILTER (MSGF_SIZE) dans les
boucles, le curseur borné à la zone de travail (ReactOS borne le point à SPI_GETWORKAREA), un coin choisi au clavier
(ReactOS ne prend qu'un bord), le déplacement d'une fenêtre agrandie (ReactOS le permet pour la détacher de son bord ;
Move y est grisé), SetCursorPos des applications (TWOPARAM_ROUTINE_SETCURSORPOS, que `mouse::set_cursor_pos`
servira).

Le banc d'essai : `tests/native/kbdmove1.c` (`KBDMOVE1.EXE`, MinGW), scénario `keyboard-move`, à la place de
`winlogon.exe`. W (100, 100, 400 × 300), un dialogue D sans cadre épais, une fenêtre cachée H. SC_SIZE à D et SC_MOVE
à H reviennent sans WM_ENTERSIZEMOVE (étape 1). Puis QEMU : Alt+Espace et m, le curseur au milieu du titre (290, 109),
→ → ↓ et Entrée : W en (116, 108) (étape 2) ; Alt+Espace, m, ← ← ← et Échap : W reste en (116, 108) (étape 3) ;
Alt+Espace, m, la souris de (30, 20) et Entrée : W en (146, 128) (étape 4) ; Alt+Espace, s et Échap : rien, pas de
WM_ENTERSIZEMOVE (étape 5) ; Alt+Espace, s, → (le bord droit, le curseur en (544, 278)), → → et Entrée : 16 pixels de
plus en largeur (étape 6) ; Alt+Espace, s, ↓ (le bord du bas, le curseur en (354, 426)), ↑ ↑ ↑ et Entrée : 24 pixels de
moins en hauteur (étape 7).

Tests : hôte (`sizemove` : quand déplacer ou redimensionner, le point du titre, le bord de chaque flèche, le pas des
flèches, le point ramené dans la fenêtre, même vide : `i32::clamp` y paniquait avant le commit) ; `keyboard-move` sur AMD et Intel. Sept mutations le font échouer chacune : le curseur ailleurs qu'au
milieu du titre ; les flèches ignorées ; Échap qui ne rend pas la place ; Size sans cadre épais ou une fenêtre cachée
qui entrent dans la boucle ; aucune flèche ne choisit de bord ; Échap qui ne renonce pas au choix du bord ;
`mouse::set_cursor_pos` sans son WM_MOUSEMOVE.

## Étape 40 : ← et → entre le menu de la fenêtre et la barre (WM_NEXTMENU)

Demandé après l'étape 39 : aux bouts de la barre suivie, ← et → faisaient le tour de ses items (du premier au
dernier et retour), et le menu de la fenêtre ouvert par Alt+Espace n'en sortait pas.

`menu.c` de win32k (MENU_DoNextMenu, MENU_KeyLeft, MENU_KeyRight), ReactOS comme spécification ;
`win32k::menutrack`.

| Partie | Ce que fait Mino |
|---|---|
| Le bout (`menutrack::at_menu_end`) | ← sur le premier item ; → sur le dernier item du menu de la fenêtre, ou sur une barre quand il n'y a plus après la sélection que des items de MDI (les identifiants de SC_SIZE à SC_RESTORE : l'icône et les boutons d'une fille agrandie dans la barre du cadre) ; sans sélection, → ne sort pas ; ailleurs, la flèche change d'item comme avant |
| WM_NEXTMENU (`menutrack::do_next_menu`) | envoyé à la propriétaire avec la flèche et un MDINEXTMENU (`abi::menu::MdiNextMenu32`, que sa procédure peut remplir) : le menu quitté, le menu de GetSystemMenu pour le menu de la fenêtre ; DefWindowProc n'y répond pas |
| Sans réponse | du menu de la fenêtre à la barre (← : son dernier item avant ceux de MDI, `menutrack::last_bar_item` ; → : son premier), rien pour une fenêtre fille ou sans barre ; de la barre au menu de la fenêtre (WS_SYSMENU, créé s'il le faut), rien sans lui |
| Une réponse | le menu et la fenêtre donnés : la barre d'une fenêtre qui n'est pas fille, ou son menu de la fenêtre ; un autre menu, rien. Le suivi passe à cette fenêtre, qui devient la propriétaire (ses notifications, la souris, `queue.menu_owner`) ; WM_EXITMENULOOP va toujours à la fenêtre du début |
| Le passage | l'ancien menu perd sa sélection, ses sous-menus se ferment ; le menu suivi (`Top`) change ; le nouveau menu sélectionne son item (WM_MENUSELECT) ; si un menu était ouvert, celui du nouvel item s'ouvre (le menu de la fenêtre sous l'icône du titre) |

Écart voulu avec ReactOS : quand l'application répond par un menu de la fenêtre, ReactOS compare sa réponse au
menu d'un seul item de cette fenêtre (`get_win_sys_menu`) puis la remplace par ce même menu (« get the real system
menu ») ; la comparaison n'a de sens qu'avec le sous-menu, ce que rend GetSystemMenu, le seul handle qu'une
application connaisse. Mino accepte l'un et l'autre.

Pas encore : MENU_SuspendPopup (le menu s'ouvre à chaque flèche, même répétée), les colonnes
(MENU_GetStartOfPrevColumn, MENU_GetStartOfNextColumn). Sans banc : DefFrameProc et DefMDIChildProc (MDI, dans
`user32`, qui répondent à WM_NEXTMENU) ; une réponse par une fenêtre d'un autre thread, que ReactOS ne refuse pas
(Mino non plus) : elle devient la propriétaire, mais la souris reste à la fenêtre du thread (`mouse::set_capture`
refuse une fenêtre d'un autre thread).

Le scénario `menu` (étape 23) attendait que ←, depuis File, fasse le tour de la barre jusqu'à Help : sa fenêtre W
a WS_SYSMENU, et ← y va maintenant au menu de la fenêtre, comme chez ReactOS. Ses touches 10 sont devenues
`alt left left ret` (le second ← va à Help).

Le banc d'essai : `tests/native/nextmenu1.c` (`NEXTMENU1.EXE`, MinGW), scénario `next-menu`, à la place de
`winlogon.exe`. W et sa barre File, Edit, Help ; W2 et sa barre Other. QEMU : F10, ← (du premier item au menu de la
fenêtre, WM_NEXTMENU VK_LEFT depuis la barre), ↓ l'ouvre (étape 1) ; Alt+Espace, → (File s'ouvre ; WM_NEXTMENU
depuis le menu de GetSystemMenu), ← (le menu de la fenêtre), ← (Help, le dernier), → (le menu de la fenêtre)
(étape 2) ; F10, → : Edit, sans WM_NEXTMENU (étape 3) ; F10, ← : W répond par W2 et sa barre, ↓ ouvre Other
(WM_INITMENUPOPUP à W2), k envoie WM_COMMAND à W2 (étape 4) ; F10, ← : W répond par W2 et GetSystemMenu(W2), ↓ ouvre
le menu de la fenêtre de W2 (étape 5). Une capture de l'étape 2 montre le menu de la fenêtre sous l'icône, aucun
item de la barre surligné, puis Help enfoncé et ouvert.

Tests : hôte (`menutrack` : les bouts d'une barre, d'une barre de MDI, du menu de la fenêtre, sans sélection ;
l'item d'arrivée sur la barre) ; `next-menu` sur AMD et Intel. Sept mutations le font échouer chacune : ← qui ne
sort pas du premier item ; → qui ne sort pas du menu de la fenêtre ; WM_NEXTMENU pas envoyé ; la réponse par
GetSystemMenu refusée (la règle de ReactOS) ; la réponse par une barre refusée ; ← qui arrive sur le premier item de
la barre ; la propriétaire gardée après une réponse. Une huitième a montré une ligne inutile, retirée avant le
commit : poser la fenêtre de la barre au passage, que SetMenu lui donne déjà (`menu::attach`).
