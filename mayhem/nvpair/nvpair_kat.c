/*
 * Known-answer probe for illumos' nvlist code (common/nvpair, libnvpair), built with normal flags.
 *
 *   nvpair_kat <packed-nvlist>   unpack the file and print one line per pair, recursing into nested lists
 *   nvpair_kat --gen <dir>       write the fixtures (kat/*.bin and the fuzzer seeds) by building lists with
 *                                the nvlist_add_* API and packing them; run by hand, not by the build
 *
 * mayhem/test.sh compares the first form's output on the committed fixtures with kat/*.expected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/nvpair.h>
#include <libnvpair.h>

static void dump(nvlist_t *nvl, int depth);

static void
dump_pair(nvpair_t *nvp, int depth)
{
	const char *name = nvpair_name(nvp);
	uint_t n, i;

	printf("%*s%s ", depth * 2, "", name);
	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BOOLEAN:
		printf("boolean\n");
		break;
	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t v;
		(void) nvpair_value_boolean_value(nvp, &v);
		printf("boolean_value=%d\n", (int)v);
		break;
	}
	case DATA_TYPE_BYTE: {
		uchar_t v;
		(void) nvpair_value_byte(nvp, &v);
		printf("byte=0x%02x\n", v);
		break;
	}
	case DATA_TYPE_INT8: {
		int8_t v;
		(void) nvpair_value_int8(nvp, &v);
		printf("int8=%d\n", v);
		break;
	}
	case DATA_TYPE_UINT8: {
		uint8_t v;
		(void) nvpair_value_uint8(nvp, &v);
		printf("uint8=%u\n", v);
		break;
	}
	case DATA_TYPE_INT16: {
		int16_t v;
		(void) nvpair_value_int16(nvp, &v);
		printf("int16=%d\n", v);
		break;
	}
	case DATA_TYPE_UINT16: {
		uint16_t v;
		(void) nvpair_value_uint16(nvp, &v);
		printf("uint16=%u\n", v);
		break;
	}
	case DATA_TYPE_INT32: {
		int32_t v;
		(void) nvpair_value_int32(nvp, &v);
		printf("int32=%d\n", v);
		break;
	}
	case DATA_TYPE_UINT32: {
		uint32_t v;
		(void) nvpair_value_uint32(nvp, &v);
		printf("uint32=%u\n", v);
		break;
	}
	case DATA_TYPE_INT64: {
		int64_t v;
		(void) nvpair_value_int64(nvp, &v);
		printf("int64=%lld\n", (long long)v);
		break;
	}
	case DATA_TYPE_UINT64: {
		uint64_t v;
		(void) nvpair_value_uint64(nvp, &v);
		printf("uint64=%llu\n", (unsigned long long)v);
		break;
	}
	case DATA_TYPE_HRTIME: {
		hrtime_t v;
		(void) nvpair_value_hrtime(nvp, &v);
		printf("hrtime=%lld\n", (long long)v);
		break;
	}
	case DATA_TYPE_STRING: {
		char *v;
		(void) nvpair_value_string(nvp, &v);
		printf("string=%s\n", v);
		break;
	}
	case DATA_TYPE_BYTE_ARRAY: {
		uchar_t *v;
		(void) nvpair_value_byte_array(nvp, &v, &n);
		printf("byte_array[%u]=", n);
		for (i = 0; i < n; i++)
			printf("%s%u", i ? "," : "", v[i]);
		printf("\n");
		break;
	}
	case DATA_TYPE_UINT32_ARRAY: {
		uint32_t *v;
		(void) nvpair_value_uint32_array(nvp, &v, &n);
		printf("uint32_array[%u]=", n);
		for (i = 0; i < n; i++)
			printf("%s%u", i ? "," : "", v[i]);
		printf("\n");
		break;
	}
	case DATA_TYPE_BOOLEAN_ARRAY: {
		boolean_t *v;
		(void) nvpair_value_boolean_array(nvp, &v, &n);
		printf("boolean_array[%u]=", n);
		for (i = 0; i < n; i++)
			printf("%s%d", i ? "," : "", (int)v[i]);
		printf("\n");
		break;
	}
	case DATA_TYPE_STRING_ARRAY: {
		char **v;
		(void) nvpair_value_string_array(nvp, &v, &n);
		printf("string_array[%u]=", n);
		for (i = 0; i < n; i++)
			printf("%s%s", i ? "," : "", v[i]);
		printf("\n");
		break;
	}
	case DATA_TYPE_NVLIST: {
		nvlist_t *v;
		(void) nvpair_value_nvlist(nvp, &v);
		printf("nvlist\n");
		dump(v, depth + 1);
		break;
	}
	case DATA_TYPE_NVLIST_ARRAY: {
		nvlist_t **v;
		(void) nvpair_value_nvlist_array(nvp, &v, &n);
		printf("nvlist_array[%u]\n", n);
		for (i = 0; i < n; i++)
			dump(v[i], depth + 1);
		break;
	}
	default:
		printf("type=%d\n", (int)nvpair_type(nvp));
		break;
	}
}

static void
dump(nvlist_t *nvl, int depth)
{
	nvpair_t *nvp = NULL;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL)
		dump_pair(nvp, depth);
}

static nvlist_t *
build(int variant)
{
	nvlist_t *nvl, *sub, *subs[2];
	uchar_t bytes[] = { 1, 2, 3, 4, 5 };
	uint32_t u32s[] = { 10, 20, 30 };
	boolean_t bools[] = { B_TRUE, B_FALSE, B_TRUE };
	char *strs[] = { "alpha", "beta" };
	int i;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		exit(2);
	if (variant == 1) {
		(void) nvlist_add_string(nvl, "str", "illumos");
		(void) nvlist_add_uint32(nvl, "u32", 4000000000U);
		return (nvl);
	}
	if (variant == 2) {
		(void) nvlist_alloc(&sub, NV_UNIQUE_NAME, 0);
		(void) nvlist_add_string(sub, "inner", "gate");
		(void) nvlist_add_uint64(sub, "n", 42);
		(void) nvlist_add_nvlist(nvl, "sub", sub);
		nvlist_free(sub);
		return (nvl);
	}
	(void) nvlist_add_boolean(nvl, "boolean");
	(void) nvlist_add_boolean_value(nvl, "flag", B_TRUE);
	(void) nvlist_add_byte(nvl, "b", 0x7f);
	(void) nvlist_add_int8(nvl, "i8", -5);
	(void) nvlist_add_uint8(nvl, "u8", 250);
	(void) nvlist_add_int16(nvl, "i16", -1234);
	(void) nvlist_add_uint16(nvl, "u16", 54321);
	(void) nvlist_add_int32(nvl, "i32", -100000);
	(void) nvlist_add_uint32(nvl, "u32", 4000000000U);
	(void) nvlist_add_int64(nvl, "i64", -5000000000LL);
	(void) nvlist_add_uint64(nvl, "u64", 18446744073709551615ULL);
	(void) nvlist_add_hrtime(nvl, "hr", 123456789012LL);
	(void) nvlist_add_string(nvl, "str", "illumos");
	(void) nvlist_add_byte_array(nvl, "bytes", bytes, 5);
	(void) nvlist_add_uint32_array(nvl, "u32s", u32s, 3);
	(void) nvlist_add_boolean_array(nvl, "bools", bools, 3);
	(void) nvlist_add_string_array(nvl, "strs", strs, 2);
	(void) nvlist_alloc(&sub, NV_UNIQUE_NAME, 0);
	(void) nvlist_add_string(sub, "inner", "gate");
	(void) nvlist_add_uint64(sub, "n", 42);
	(void) nvlist_add_nvlist(nvl, "sub", sub);
	nvlist_free(sub);
	for (i = 0; i < 2; i++) {
		(void) nvlist_alloc(&subs[i], NV_UNIQUE_NAME, 0);
		(void) nvlist_add_uint32(subs[i], "idx", i + 7);
	}
	(void) nvlist_add_nvlist_array(nvl, "subs", subs, 2);
	nvlist_free(subs[0]);
	nvlist_free(subs[1]);
	return (nvl);
}

static int
emit(const char *dir, const char *name, int variant, int encoding)
{
	nvlist_t *nvl = build(variant);
	char *buf = NULL;
	size_t len = 0;
	char path[4096];
	FILE *fp;

	if (nvlist_pack(nvl, &buf, &len, encoding, 0) != 0)
		return (1);
	(void) snprintf(path, sizeof (path), "%s/%s", dir, name);
	if ((fp = fopen(path, "wb")) == NULL)
		return (1);
	(void) fwrite(buf, 1, len, fp);
	(void) fclose(fp);
	free(buf);
	nvlist_free(nvl);
	return (0);
}

int
main(int argc, char **argv)
{
	FILE *fp;
	char *buf;
	long len;
	nvlist_t *nvl = NULL;

	if (argc == 3 && strcmp(argv[1], "--gen") == 0)
		return (emit(argv[2], "full-xdr", 0, NV_ENCODE_XDR) ||
		    emit(argv[2], "full-native", 0, NV_ENCODE_NATIVE) ||
		    emit(argv[2], "small-xdr", 1, NV_ENCODE_XDR) ||
		    emit(argv[2], "small-native", 1, NV_ENCODE_NATIVE) ||
		    emit(argv[2], "nested-xdr", 2, NV_ENCODE_XDR) ||
		    emit(argv[2], "nested-native", 2, NV_ENCODE_NATIVE));
	if (argc != 2 || (fp = fopen(argv[1], "rb")) == NULL)
		return (2);
	(void) fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	(void) fseek(fp, 0, SEEK_SET);
	buf = malloc(len);
	if (fread(buf, 1, len, fp) != (size_t)len)
		return (2);
	(void) fclose(fp);
	if (nvlist_unpack(buf, len, &nvl, 0) != 0) {
		printf("unpack failed\n");
		return (1);
	}
	dump(nvl, 0);
	return (0);
}
