/*
 * Fuzz harness for illumos' nvlist parser (common/nvpair + libnvpair), the name-value list format that
 * the kernel, libzfs and fmd exchange over ioctls, doors and on disk.
 *
 * Input: a packed nvlist exactly as nvlist_pack() writes it -- byte 0 selects the encoding
 * (NV_ENCODE_NATIVE or NV_ENCODE_XDR), byte 1 the endianness, the rest is the encoded list. It is handed
 * to nvlist_unpack() in an exactly-sized heap copy, as a caller that received it over an ioctl would.
 * Anything the library refuses is rejected (-1); an accepted list is then walked, printed, duplicated and
 * re-packed in both encodings, which exercises every accessor on whatever the parser let through.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/nvpair.h>
#include <libnvpair.h>

static volatile uint64_t sink;

#define	SCALAR(fn, ty)	do { ty v; if (fn(nvp, &v) == 0) sink += (uint64_t)v; } while (0)
#define	ARRAY(fn, ty)	do { \
	ty *a; uint_t n; \
	if (fn(nvp, &a, &n) == 0) { \
		uint_t i; \
		for (i = 0; i < n; i++) \
			sink += (uint64_t)a[i]; \
	} \
} while (0)

static void
walk(nvlist_t *nvl)
{
	nvpair_t *nvp = NULL;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		nvpair_t *found = NULL;
		const char *name = nvpair_name(nvp);

		sink += strlen(name);
		(void) nvlist_lookup_nvpair(nvl, name, &found);
		(void) nvlist_exists(nvl, name);
		(void) nvpair_type_is_array(nvp);

		switch (nvpair_type(nvp)) {
		case DATA_TYPE_BOOLEAN_VALUE: SCALAR(nvpair_value_boolean_value, boolean_t); break;
		case DATA_TYPE_BYTE: SCALAR(nvpair_value_byte, uchar_t); break;
		case DATA_TYPE_INT8: SCALAR(nvpair_value_int8, int8_t); break;
		case DATA_TYPE_UINT8: SCALAR(nvpair_value_uint8, uint8_t); break;
		case DATA_TYPE_INT16: SCALAR(nvpair_value_int16, int16_t); break;
		case DATA_TYPE_UINT16: SCALAR(nvpair_value_uint16, uint16_t); break;
		case DATA_TYPE_INT32: SCALAR(nvpair_value_int32, int32_t); break;
		case DATA_TYPE_UINT32: SCALAR(nvpair_value_uint32, uint32_t); break;
		case DATA_TYPE_INT64: SCALAR(nvpair_value_int64, int64_t); break;
		case DATA_TYPE_UINT64: SCALAR(nvpair_value_uint64, uint64_t); break;
		case DATA_TYPE_HRTIME: SCALAR(nvpair_value_hrtime, hrtime_t); break;
		case DATA_TYPE_DOUBLE: {
			double d;

			if (nvpair_value_double(nvp, &d) == 0)
				sink += (uint64_t)(d > 0);
			break;
		}
		case DATA_TYPE_STRING: {
			char *s;

			if (nvpair_value_string(nvp, &s) == 0)
				sink += strlen(s);
			break;
		}
		case DATA_TYPE_NVLIST: {
			nvlist_t *sub;

			if (nvpair_value_nvlist(nvp, &sub) == 0)
				walk(sub);
			break;
		}
		case DATA_TYPE_BOOLEAN_ARRAY: ARRAY(nvpair_value_boolean_array, boolean_t); break;
		case DATA_TYPE_BYTE_ARRAY: ARRAY(nvpair_value_byte_array, uchar_t); break;
		case DATA_TYPE_INT8_ARRAY: ARRAY(nvpair_value_int8_array, int8_t); break;
		case DATA_TYPE_UINT8_ARRAY: ARRAY(nvpair_value_uint8_array, uint8_t); break;
		case DATA_TYPE_INT16_ARRAY: ARRAY(nvpair_value_int16_array, int16_t); break;
		case DATA_TYPE_UINT16_ARRAY: ARRAY(nvpair_value_uint16_array, uint16_t); break;
		case DATA_TYPE_INT32_ARRAY: ARRAY(nvpair_value_int32_array, int32_t); break;
		case DATA_TYPE_UINT32_ARRAY: ARRAY(nvpair_value_uint32_array, uint32_t); break;
		case DATA_TYPE_INT64_ARRAY: ARRAY(nvpair_value_int64_array, int64_t); break;
		case DATA_TYPE_UINT64_ARRAY: ARRAY(nvpair_value_uint64_array, uint64_t); break;
		case DATA_TYPE_STRING_ARRAY: {
			char **a;
			uint_t n, i;

			if (nvpair_value_string_array(nvp, &a, &n) == 0)
				for (i = 0; i < n; i++)
					sink += strlen(a[i]);
			break;
		}
		case DATA_TYPE_NVLIST_ARRAY: {
			nvlist_t **a;
			uint_t n, i;

			if (nvpair_value_nvlist_array(nvp, &a, &n) == 0)
				for (i = 0; i < n; i++)
					walk(a[i]);
			break;
		}
		default:
			break;
		}
	}
}

static void
render(nvlist_t *nvl)
{
	char *out = NULL;
	size_t outlen = 0;
	FILE *fp = open_memstream(&out, &outlen);

	if (fp == NULL)
		return;
	nvlist_print(fp, nvl);
	(void) nvlist_print_json(fp, nvl);
	(void) fclose(fp);
	sink += outlen;
	free(out);
}

static void
repack(nvlist_t *nvl, int encoding)
{
	size_t sz = 0;
	char *buf = NULL;
	size_t len = 0;
	nvlist_t *again = NULL;

	if (nvlist_size(nvl, &sz, encoding) != 0)
		return;
	if (nvlist_pack(nvl, &buf, &len, encoding, 0) != 0)
		return;
	if (nvlist_unpack(buf, len, &again, 0) == 0)
		nvlist_free(again);
	free(buf);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	nvlist_t *nvl = NULL, *dup = NULL;
	char *buf;

	if (size == 0)
		return (-1);
	if ((buf = malloc(size)) == NULL)
		return (-1);
	memcpy(buf, data, size);

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		free(buf);
		return (-1);
	}
	free(buf);

	walk(nvl);
	render(nvl);
	if (nvlist_dup(nvl, &dup, 0) == 0) {
		(void) nvlist_merge(dup, nvl, 0);
		nvlist_free(dup);
	}
	repack(nvl, NV_ENCODE_NATIVE);
	repack(nvl, NV_ENCODE_XDR);
	nvlist_free(nvl);
	return (0);
}
