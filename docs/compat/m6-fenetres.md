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
sous-menu comme identifiant. Un tel sous-menu ne part donc pas avec sa barre, mais avec son processus.

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
journalisé une fois), ScrollWindowEx et ScrollDC (le contenu ne défile pas encore : NtUserScrollWindowEx est le
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

Ce qui manque : le caret (co_IntFixCaret le cache pendant le défilement, puis le décale), le DC propre d'une fenêtre ou
de sa classe pour ScrollWindow (le cache aussi), SW_SMOOTHSCROLL (ignoré, comme ReactOS).

Le banc d'essai : `tests/native/scrollx1.c` (`SCROLLX1.EXE` à la place de `winlogon.exe`, scénario `scrollex`) : une
fenêtre peinte en bandes de 20 pixels selon une position, qui ne peint que ce qu'on lui demande ; ScrollWindowEx vers le
haut de 30 (SIMPLEREGION, les 30 dernières lignes dans `hrgnUpdate`, `prcUpdate` et GetUpdateRect, et seules peintes),
ScrollDC vers le bas de 20 sur son DC (les 20 premières), une fille déplacée de 10 vers la gauche avec SW_SCROLLCHILDREN
(WM_MOVE 290, 100) ; sept pixels vérifiés (sans la copie, cinq sont faux).

Tests : hôte (`scrollex` : la région découverte, ce qui n'a pas pu être copié, le rectangle de défilement et celui de
découpage, les zones, les drapeaux du DC ; `gdi::bitblt` : l'ordre des copies dans une même surface, qui échoue dans
l'ordre de la région) ; le scénario `scrollex` sur AMD et Intel, et `listview`, `console`, `cmd`, `desktop-launch`,
`gui`, `bitmap`, `scroll` sur AMD.
