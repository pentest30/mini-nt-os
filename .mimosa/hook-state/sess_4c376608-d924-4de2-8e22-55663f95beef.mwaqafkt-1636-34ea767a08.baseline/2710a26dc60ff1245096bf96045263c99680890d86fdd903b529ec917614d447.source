#pragma once
/* Les macros de test que wine/test.h ne définit que sous STANDALONE —
 * les fichiers de test individuels se compilent sans lui (chaque
 * START_TEST y poserait winetest_testlist) ; ce shim, forcé en tête de
 * chaque fichier (--include), les définit en termes des externes du
 * framework. */
#ifndef _APITEST_MACROS_SHIM_H_
#define _APITEST_MACROS_SHIM_H_

#include <wine/test.h> /* les types de base et les externes */

#define ok_hex_(expr, value, fmt) ok((expr) == (value), #expr " = " fmt ", expected " fmt "\n", (expr), (value))
#define ok_hex(expression, value) ok_hex_(expression, value, "%lx")
#define ok_long(expression, value) ok_hex_(expression, value, "%ld")
#define ok_ulong(expression, value) ok_hex_(expression, value, "%lu")
#define ok_dec ok_long
#define ok_ntstatus(status, expected) ok_hex(status, expected)
#define ok_char(expression, value) ok_hex_(expression, value, "%x")
#define ok_int(expression, value) ok_hex_(expression, value, "%d")
#define ok_ptr_(expr, value) ok((expr) == (value), #expr " = %p, expected %p\n", (expr), (void *)(value))
#define ok_ptr(expression, value) ok_ptr_(expression, value)
#define ok_win32err(error, expected) ok_hex((unsigned long)(error), (unsigned long)(expected))
#define ok_str(x, y) ok(strcmp(x, y) == 0, "%s: '%s' != '%s'\n", #x, x, y)
#define ok_wstr(x, y) ok(wcscmp(x, y) == 0, "%s: '%ls' != '%ls'\n", #x, x, y)

#endif
