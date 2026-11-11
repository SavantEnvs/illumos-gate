#ifndef _MAYHEM_SHIM_SYS_SYSMACROS_H
#define	_MAYHEM_SHIM_SYS_SYSMACROS_H
#include <sys/types.h>
#ifndef MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define	MAX(a, b)	((a) > (b) ? (a) : (b))
#endif
#define	P2ROUNDUP(x, align)	(-(-(x) & -(align)))
#define	ARRAY_SIZE(a)	(sizeof (a) / sizeof ((a)[0]))
#ifndef __unused
#define	__unused	__attribute__((unused))
#endif
#endif
