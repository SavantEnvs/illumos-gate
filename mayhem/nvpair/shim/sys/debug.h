#ifndef _MAYHEM_NVSHIM_SYS_DEBUG_H
#define	_MAYHEM_NVSHIM_SYS_DEBUG_H
#include <stdlib.h>
/* Non-DEBUG illumos build: ASSERTs compile away, VERIFYs stay. */
#define	ASSERT3P(a, op, b)	((void)0)
#define	ASSERT3U(a, op, b)	((void)0)
#define	ASSERT0(x)		((void)0)
#define	ASSERT(x)		((void)0)
#define	VERIFY0(x)		do { if ((x) != 0) abort(); } while (0)
#define	VERIFY3U(a, op, b)	do { if (!((a) op (b))) abort(); } while (0)
#endif
