/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */
#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>

#include <getopt.h>

#include <efi.h>

#include <ccan/list/list.h>
#include <ccan/array_size/array_size.h>
#include <ccan/talloc/talloc.h>

#include <openssl/x509.h>
#include <openssl/err.h>

#include "fileio.h"
#include "efivars.h"

#define EFIVARS_MOUNTPOINT	"/sys/firmware/efi/vars"
#define EFIVARS_FSTYPE		0x6165676C

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
	{ 0xd719b2cb, 0x3d3a, 0x4596, \
	{ 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } }

static const char *efivars_mountpoint = EFIVARS_MOUNTPOINT;
static const char *toolname = "sbkeysync";

enum sigdb_type {
	SIGDB_KEK,
	SIGDB_DB,
	SIGDB_DBX,
};

struct efi_sigdb_desc {
	enum sigdb_type	type;
	const char	*name;
	EFI_GUID	guid;
};

struct efi_sigdb_desc efi_sigdb_descs[] = {
	{ SIGDB_KEK, "KEK", EFI_GLOBAL_VARIABLE },
	{ SIGDB_DB,  "db",  EFI_IMAGE_SECURITY_DATABASE_GUID },
	{ SIGDB_DBX, "dbx", EFI_IMAGE_SECURITY_DATABASE_GUID },
};

#if 0
static const char *keystores[] = {
	"/usr/share/secureboot/keys",
	"/etc/secureboot/keys",
};
#endif

typedef int (*key_id_func)(void *, EFI_SIGNATURE_DATA *, size_t,
				uint8_t **, int *);

struct cert_type {
	EFI_GUID	guid;
	key_id_func	get_id;
};

struct key {
	EFI_GUID		type;
	int			id_len;
	uint8_t			*id;

	size_t			len;
	uint8_t			*data;

	struct list_node	list;
};

struct key_database {
	const char		*name;
	struct list_head	keys;
};

struct sync_context {
	struct key_database	*kek;
	struct key_database	*db;
	struct key_database	*dbx;
};

#define GUID_STRLEN (8 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 12 + 1)
static void guid_to_str(const EFI_GUID *guid, char *str)
{
	snprintf(str, GUID_STRLEN,
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			guid->Data1, guid->Data2, guid->Data3,
			guid->Data4[0], guid->Data4[1],
			guid->Data4[2], guid->Data4[3],
			guid->Data4[4], guid->Data4[5],
			guid->Data4[6], guid->Data4[7]);
}

static int sha256_key_id(void *ctx, EFI_SIGNATURE_DATA *sigdata,
		size_t sigdata_datalen, uint8_t **buf, int *len)
{
	const unsigned int sha256_id_size = 256 / 8;
	uint8_t *id;

	if (sigdata_datalen != sha256_id_size)
		return -1;

	id = talloc_array(ctx, uint8_t, sha256_id_size);
	memcpy(sigdata->SignatureData, buf, sha256_id_size);

	*buf = id;
	*len = sha256_id_size;

	return 0;
}

static int x509_key_id(void *ctx, EFI_SIGNATURE_DATA *sigdata,
		size_t sigdata_datalen, uint8_t **buf, int *len)
{
	ASN1_INTEGER *serial;
	const uint8_t *tmp;
	uint8_t *tmp_buf;
	int tmp_len, rc;
	X509 *x509;

	rc = -1;

	tmp = sigdata->SignatureData;

	x509 = d2i_X509(NULL, &tmp, sigdata_datalen);
	if (!x509)
		return -1;

	/* we use the X509 serial number as the key ID */
	if (!x509->cert_info || !x509->cert_info->serialNumber)
		goto out;

	serial = x509->cert_info->serialNumber;

	tmp_len = ASN1_STRING_length(serial);
	tmp_buf = talloc_array(ctx, uint8_t, tmp_len);

	memcpy(tmp_buf, ASN1_STRING_data(serial), tmp_len);

	*buf = tmp_buf;
	*len = tmp_len;

	rc = 0;

out:
	X509_free(x509);
	return rc;
}

struct cert_type cert_types[] = {
	{ EFI_CERT_SHA256_GUID, sha256_key_id },
	{ EFI_CERT_X509_GUID, x509_key_id },
};

static int guidcmp(const EFI_GUID *a, const EFI_GUID *b)
{
	return memcmp(a, b, sizeof(EFI_GUID));
}

static int key_id(void *ctx, const EFI_GUID *type, EFI_SIGNATURE_DATA *sigdata,
		size_t sigdata_datalen, uint8_t **buf, int *len)
{
	char guid_str[GUID_STRLEN];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cert_types); i++) {
		if (guidcmp(&cert_types[i].guid, type))
			continue;

		return cert_types[i].get_id(ctx, sigdata, sigdata_datalen,
				buf, len);
	}

	guid_to_str(type, guid_str);
	printf("warning: unknown signature type found:\n  %s\n",
			guid_str);
	return -1;

}

struct efi_sigdb_desc *efi_sigdb_desc_lookup(enum sigdb_type type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(efi_sigdb_descs); i++)
		if (efi_sigdb_descs[i].type == type)
			return &efi_sigdb_descs[i];

	abort();
}

typedef int (*sigdata_fn)(EFI_SIGNATURE_DATA *, int, const EFI_GUID *, void *);

static int sigdb_iterate(void *db_data, size_t len,
		sigdata_fn fn, void *arg)
{
	EFI_SIGNATURE_LIST *siglist;
	EFI_SIGNATURE_DATA *sigdata;
	unsigned int i, j;
	int rc = 0;

	if (len == 0)
		return 0;

	if (len < sizeof(*siglist))
		return -1;

	for (i = 0, siglist = db_data + i;
			i + sizeof(*siglist) <= len &&
			i + siglist->SignatureListSize > i &&
			i + siglist->SignatureListSize <= len && !rc;
			siglist = db_data + i,
			i += siglist->SignatureListSize) {

		/* ensure that the header & sig sizes are sensible */
		if (siglist->SignatureHeaderSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize < sizeof(*sigdata))
			continue;

		/* iterate through the (constant-sized) signature data blocks */
		for (j = sizeof(*siglist) + siglist->SignatureHeaderSize;
				j < siglist->SignatureListSize && !rc;
				j += siglist->SignatureSize)
		{
			sigdata = (void *)(siglist) + j;

			rc = fn(sigdata, siglist->SignatureSize,
					&siglist->SignatureType, arg);

		}

	}

	return rc;
}

static int sigdb_add_key(EFI_SIGNATURE_DATA *sigdata, int len,
		const EFI_GUID *type, void *arg)
{
	struct key_database *kdb = arg;
	struct key *key;
	int rc;

	key = talloc(kdb, struct key);

	rc = key_id(kdb, type, sigdata, len - sizeof(sigdata), &key->id,
			&key->id_len);

	if (rc)
		talloc_free(key);
	else
		list_add(&kdb->keys, &key->list);

	return 0;
}


static int read_efivars_key_database(struct sync_context *ctx,
		enum sigdb_type type, struct key_database *kdb)
{
	struct efi_sigdb_desc *desc;
	char guid_str[GUID_STRLEN];
	char *filename;
	uint8_t *buf;
	size_t len;

	desc = efi_sigdb_desc_lookup(type);

	guid_to_str(&desc->guid, guid_str);

	filename = talloc_asprintf(ctx, "%s/%s-%s", efivars_mountpoint,
					desc->name, guid_str);

	if (fileio_read_file_noerror(ctx, filename, &buf, &len))
		return -1;

	/* efivars files start with a 32-bit attribute block */
	buf += sizeof(uint32_t);
	len -= sizeof(uint32_t);

	sigdb_iterate(buf, len, sigdb_add_key, kdb);

	return 0;
}

static void print_key_database(struct key_database *kdb)
{
	struct key *key;
	int i;

	printf("kdb %s\n", kdb->name);

	list_for_each(&kdb->keys, key, list) {
		printf("  %d bytes: [ ", key->id_len);
		for (i = 0; i < key->id_len; i++)
			printf("0x%02x ", key->id[i]);
		printf("]\n");
	}
}

static int read_key_databases(struct sync_context *ctx)
{
	struct efi_sigdb_desc *desc;
	unsigned int i;
	int rc;
	struct {
		enum sigdb_type type;
		struct key_database **kdb;
	} databases[] = {
		{ SIGDB_KEK, &ctx->kek },
		{ SIGDB_DB,  &ctx->db },
		{ SIGDB_DBX, &ctx->dbx },
	};

	for (i = 0; i < ARRAY_SIZE(databases); i++) {
		struct key_database *kdb;

		desc = efi_sigdb_desc_lookup(databases[i].type);

		kdb = talloc(ctx, struct key_database);
		kdb->name = desc->name;
		list_head_init(&kdb->keys);

		rc = read_efivars_key_database(ctx, databases[i].type, kdb);

		if (!rc)
			print_key_database(kdb);

		*databases[i].kdb = kdb;
	}

	return 0;
}

static int check_efivars_mount(void)
{
	struct statfs statbuf;
	int rc;

	rc = statfs(efivars_mountpoint, &statbuf);
	if (rc)
		return -1;

	if (statbuf.f_type != EFIVARS_FSTYPE)
		return -1;

	return 0;
}

static struct option options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options]\n"
		"Update EFI key databases from the filesystem\n",
		toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

int main(int argc, char **argv)
{
	struct sync_context *ctx;

	for (;;) {
		int idx, c;
		c = getopt_long(argc, argv, "a:d:rhV", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		}
	}

	if (argc != optind) {
		usage();
		return EXIT_FAILURE;
	}

	if (check_efivars_mount()) {
		fprintf(stderr, "Can't access efivars filesystem, aborting\n");
		return EXIT_FAILURE;
	}

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	ctx = talloc(NULL, struct sync_context);

	read_key_databases(ctx);

	return EXIT_SUCCESS;
}
