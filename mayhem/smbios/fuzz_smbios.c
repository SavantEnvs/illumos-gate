/*
 * Fuzz harness for illumos' SMBIOS table parser (common/smbios, shared by the kernel and libsmbios).
 *
 * Input layout:
 *   byte 0      entry-point flavour: even = SMBIOS 3.0 (64-bit) entry point, odd = SMBIOS 2.1
 *   byte 1,2    major / minor SMBIOS version the entry point declares
 *   bytes 3..   the structure table, handed to smbios_bufopen() in an exactly-sized heap copy
 *
 * The entry point is the envelope firmware provides next to the table (the kernel passes it to the
 * parser the same way); it is synthesized to describe the table and carries no magic that the
 * fuzzer would otherwise have to guess. Everything inside the table is fuzzer-controlled.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/smbios.h>

static volatile size_t sink;

static void
touch(const char *s)
{
	if (s != NULL)
		sink += strlen(s);
}

#define	TRY(call, ...)	do { (void) call(shp, __VA_ARGS__); } while (0)

static int
visit(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	id_t id = sp->smbstr_id;
	smbios_info_t info;
	smbios_processor_t proc;
	smbios_processor_ext_t eproc;
	smbios_chassis_t chassis;
	smbios_port_t port;
	smbios_port_ext_t eport;
	smbios_slot_t slot;
	smbios_memdevice_t md;
	smbios_memdevice_ext_t emd;
	smbios_battery_t bat;
	smbios_cache_t cache;
	smbios_pointdev_t pd;
	smbios_bboard_t bb;
	smbios_memarray_t ma;
	smbios_memarray_ext_t ema;
	smbios_memarrmap_t mam;
	smbios_memdevmap_t mdm;
	smbios_vprobe_t vp;
	smbios_cooldev_t cd;
	smbios_tprobe_t tp;
	smbios_iprobe_t ip;
	smbios_mgmtdev_t mgd;
	smbios_mgmtcomp_t mgc;
	smbios_powersup_t ps;
	smbios_obdev_ext_t oe;
	smbios_pciexrc_t rc;
	smbios_processor_info_t pi;
	smbios_processor_info_riscv_t pir;
	smbios_tpm_t tpm;
	smbios_strprop_t sprop;
	smbios_fwinfo_t fw;
	smbios_obdev_t obd[16];
	const char *strv[16];
	int n;

	(void) arg;
	if (smbios_info_common(shp, id, &info) == 0) {
		touch(info.smbi_manufacturer);
		touch(info.smbi_product);
		touch(info.smbi_version);
		touch(info.smbi_serial);
		touch(info.smbi_asset);
		touch(info.smbi_location);
		touch(info.smbi_part);
	}
	if ((n = smbios_info_contains(shp, id, 0, NULL)) > 0) {
		id_t ids[16];

		if (n > 16)
			n = 16;
		(void) smbios_info_contains(shp, id, n, ids);
	}
	if (smbios_info_bboard(shp, id, &bb) == 0)
		sink += bb.smbb_contn;
	if (smbios_info_chassis(shp, id, &chassis) == 0)
		touch(chassis.smbc_sku);
	if (smbios_info_processor(shp, id, &proc) == 0)
		touch(proc.smbp_socktype);
	TRY(smbios_info_extprocessor, id, &eproc);
	TRY(smbios_info_cache, id, &cache);
	TRY(smbios_info_pointdev, id, &pd);
	if (smbios_info_battery(shp, id, &bat) == 0) {
		touch(bat.smbb_date);
		touch(bat.smbb_serial);
		touch(bat.smbb_version);
		touch(bat.smbb_schem);
	}
	if (smbios_info_port(shp, id, &port) == 0) {
		touch(port.smbo_iref);
		touch(port.smbo_eref);
	}
	TRY(smbios_info_extport, id, &eport);
	if (smbios_info_slot(shp, id, &slot) == 0)
		touch(slot.smbl_name);
	TRY(smbios_info_obdevs_ext, id, &oe);
	if (smbios_info_memdevice(shp, id, &md) == 0) {
		touch(md.smbmd_dloc);
		touch(md.smbmd_bloc);
		touch(md.smbmd_firmware_rev);
	}
	TRY(smbios_info_extmemdevice, id, &emd);
	TRY(smbios_info_memarray, id, &ma);
	TRY(smbios_info_extmemarray, id, &ema);
	TRY(smbios_info_memarrmap, id, &mam);
	TRY(smbios_info_memdevmap, id, &mdm);
	if (smbios_info_vprobe(shp, id, &vp) == 0)
		touch(vp.smbvp_description);
	if (smbios_info_cooldev(shp, id, &cd) == 0)
		touch(cd.smbcd_descr);
	if (smbios_info_tprobe(shp, id, &tp) == 0)
		touch(tp.smbtp_description);
	if (smbios_info_iprobe(shp, id, &ip) == 0)
		touch(ip.smbip_description);
	if (smbios_info_mgmtdev(shp, id, &mgd) == 0)
		touch(mgd.smbmd_desc);
	if (smbios_info_mgmtcomp(shp, id, &mgc) == 0)
		touch(mgc.smbmc_desc);
	TRY(smbios_info_powersup, id, &ps);
	TRY(smbios_info_pciexrc, id, &rc);
	TRY(smbios_info_processor_info, id, &pi);
	TRY(smbios_info_processor_riscv, id, &pir);
	if (smbios_info_tpm(shp, id, &tpm) == 0)
		touch(tpm.smbtpm_desc);
	if (smbios_info_strprop(shp, id, &sprop) == 0)
		touch(sprop.smbsp_prop_val);

	if ((n = smbios_info_obdevs(shp, id, 0, NULL)) > 0) {
		if (n > 16)
			n = 16;
		if (smbios_info_obdevs(shp, id, n, obd) > 0) {
			for (int i = 0; i < n; i++)
				touch(obd[i].smbd_name);
		}
	}
	if ((n = smbios_info_strtab(shp, id, 0, NULL)) > 0) {
		if (n > 16)
			n = 16;
		if (smbios_info_strtab(shp, id, n, strv) > 0) {
			for (int i = 0; i < n; i++)
				touch(strv[i]);
		}
	}

	{
		uint_t cnt;
		smbios_chassis_entry_t *ce;
		smbios_slot_peer_t *peers;
		uint8_t *cs;
		smbios_fwinfo_comp_t *comps;
		smbios_addinfo_ent_t *ae;

		if (smbios_info_chassis_elts(shp, id, &cnt, &ce) == 0)
			smbios_info_chassis_elts_free(shp, cnt, ce);
		if (smbios_info_slot_peers(shp, id, &cnt, &peers) == 0)
			smbios_info_slot_peers_free(shp, cnt, peers);
		if (smbios_info_extmemdevice_cs(shp, id, &cnt, &cs) == 0)
			smbios_info_extmemdevice_cs_free(shp, cnt, cs);
		if (smbios_info_fwinfo(shp, id, &fw) == 0) {
			touch(fw.smbfw_name);
			touch(fw.smbfw_id);
			touch(fw.smbfw_reldate);
			touch(fw.smbfw_lsv);
		}
		if (smbios_info_fwinfo_comps(shp, id, &cnt, &comps) == 0) {
			smbios_info_fwinfo_comps_free(shp, cnt, comps);
		}
		if (smbios_info_addinfo_nents(shp, id, &cnt) == 0) {
			for (uint_t i = 0; i < cnt && i < 16; i++) {
				if (smbios_info_addinfo_ent(shp, id, i, &ae) == 0) {
					touch(ae->smbai_str);
					smbios_info_addinfo_ent_free(shp, ae);
				}
			}
		}
	}
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	smbios_entry_t ent;
	smbios_hdl_t *shp;
	uint8_t *table;
	int err;

	if (size < 4)
		return (-1);

	table = malloc(size - 3);
	if (table == NULL)
		return (0);
	memcpy(table, data + 3, size - 3);

	memset(&ent, 0, sizeof (ent));
	if (data[0] & 1) {
		smbios_21_entry_t *e = &ent.ep21;

		memcpy(e->smbe_eanchor, SMB_ENTRY_EANCHOR, SMB_ENTRY_EANCHORLEN);
		memcpy(e->smbe_ianchor, SMB_ENTRY_IANCHOR, SMB_ENTRY_IANCHORLEN);
		e->smbe_elen = sizeof (*e);
		e->smbe_major = data[1];
		e->smbe_minor = data[2];
		e->smbe_stlen = size - 3 > UINT16_MAX ? UINT16_MAX : size - 3;
		e->smbe_stnum = e->smbe_stlen / 4;
	} else {
		smbios_30_entry_t *e = &ent.ep30;

		memcpy(e->smbe_eanchor, SMB3_ENTRY_EANCHOR, SMB3_ENTRY_EANCHORLEN);
		e->smbe_elen = sizeof (*e);
		e->smbe_major = data[1];
		e->smbe_minor = data[2];
		e->smbe_stlen = size - 3;
	}

	shp = smbios_bufopen(&ent, table, size - 3, SMB_VERSION,
	    SMB_O_NOCKSUM | SMB_O_NOVERS, &err);
	if (shp == NULL) {
		free(table);
		return (-1);
	}

	(void) smbios_iter(shp, visit, NULL);
	{
		smbios_bios_t bios;
		smbios_system_t sys;
		smbios_lang_t lang;
		smbios_evlog_t evlog;
		smbios_hwsec_t hwsec;
		smbios_boot_t boot;
		smbios_ipmi_t ipmi;
		smbios_version_t vers;
		smbios_entry_t out;

		if (smbios_info_bios(shp, &bios) != SMB_ERR) {
			touch(bios.smbb_vendor);
			touch(bios.smbb_version);
			touch(bios.smbb_reldate);
		}
		if (smbios_info_system(shp, &sys) != SMB_ERR) {
			touch(sys.smbs_sku);
			touch(sys.smbs_family);
		}
		if (smbios_info_lang(shp, &lang) != SMB_ERR)
			touch(lang.smbla_cur);
		(void) smbios_info_eventlog(shp, &evlog);
		(void) smbios_info_hwsec(shp, &hwsec);
		(void) smbios_info_boot(shp, &boot);
		(void) smbios_info_ipmi(shp, &ipmi);
		(void) smbios_info_smbios(shp, &out);
		smbios_info_smbios_version(shp, &vers);
		touch(smbios_psn(shp));
		touch(smbios_csn(shp));
		(void) smbios_truncated(shp);
	}
	smbios_close(shp);
	free(table);
	return (0);
}
