/*
 * illumos' <rpc/xdr.h> is Sun RPC; Linux gets the same API from libtirpc. The one extension nvpair.c
 * uses, xdr_control(XDR_GET_BYTES_AVAIL), is provided here for xdrmem streams (bytes left in the buffer).
 */
#ifndef _MAYHEM_NVSHIM_RPC_XDR_H
#define	_MAYHEM_NVSHIM_RPC_XDR_H
#include_next <rpc/xdr.h>

struct xdr_bytesrec {
	bool_t xc_is_last_record;
	u_int xc_num_avail;
};
#define	XDR_GET_BYTES_AVAIL	2000

#undef xdr_control
static inline bool_t
xdr_control(XDR *xdrs, int req, void *info)
{
	struct xdr_bytesrec *br = info;

	if (req != XDR_GET_BYTES_AVAIL)
		return (FALSE);
	br->xc_is_last_record = TRUE;
	br->xc_num_avail = xdrs->x_handy;
	return (TRUE);
}
#endif
