/* Linux stand-in for illumos <sys/types.h>: glibc's, plus the illumos spellings nvpair uses. */
#ifndef _MAYHEM_NVSHIM_SYS_TYPES_H
#define	_MAYHEM_NVSHIM_SYS_TYPES_H
#include_next <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef unsigned char uchar_t;
typedef unsigned short ushort_t;
typedef unsigned int uint_t;
typedef unsigned long ulong_t;
typedef unsigned long long u_longlong_t;
typedef long long longlong_t;
typedef int boolean_t;
typedef long long hrtime_t;
#define	B_TRUE	1
#define	B_FALSE	0
#endif
