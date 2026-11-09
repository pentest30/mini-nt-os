#pragma once
#ifndef _WINNT_
#define _WINNT_
/* L'overlay de compilation autonome : le psdk/winnt.h de ReactOS est généré
 * au build (le préambule de xdk/winnt.template.h, le corps complet
 * xdk/winnt_old.h) ; ce shim tient lieu du fichier généré, avec les
 * définitions de base que le vrai ntdef.h généré apporte et que le corps
 * suppose. */
#include <ctype.h>
#include <excpt.h>
#include <basetsd.h>

#ifndef VOID
typedef void VOID;
#endif
typedef void *PVOID, *LPVOID;
#define NTAPI __stdcall
#ifndef DECLSPEC_ALIGN
#if defined(__GNUC__)
#define DECLSPEC_ALIGN(x) __attribute__((aligned(x)))
#else
#define DECLSPEC_ALIGN(x) __declspec(align(x))
#endif
#endif
#ifndef DECLSPEC_SELECTANY
#if defined(__GNUC__)
#define DECLSPEC_SELECTANY __attribute__((selectany))
#else
#define DECLSPEC_SELECTANY __declspec(selectany)
#endif
#endif
typedef long LONG, *PLONG;
typedef unsigned long ULONG, *PULONG;
typedef short SHORT, *PSHORT;
typedef unsigned short USHORT, *PUSHORT;
typedef char CHAR, *PCHAR;
typedef unsigned char UCHAR, *PUCHAR;
#ifndef WCHAR_DEFINED
typedef unsigned short WCHAR, *PWCHAR;
#endif
typedef CONST void *PCVOID;

#include <xdk/winnt_old.h>
#endif
