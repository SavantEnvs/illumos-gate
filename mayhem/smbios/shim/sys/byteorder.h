#ifndef _MAYHEM_SHIM_SYS_BYTEORDER_H
#define	_MAYHEM_SHIM_SYS_BYTEORDER_H
#include <stdint.h>
/* x86-64 is little-endian: SMBIOS fields are little-endian already. */
#define	LE_16(x)	((uint16_t)(x))
#define	LE_32(x)	((uint32_t)(x))
#define	LE_64(x)	((uint64_t)(x))
#endif
