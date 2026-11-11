#ifndef _MAYHEM_SHIM_SYS_DEBUG_H
#define	_MAYHEM_SHIM_SYS_DEBUG_H
/* Non-DEBUG illumos build: ASSERTs compile away. */
#define	ASSERT3P(a, op, b)	((void)0)
#define	ASSERT(x)		((void)0)
#endif
