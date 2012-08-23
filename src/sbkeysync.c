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
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/types.h>

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

static const char *toolname = "sbkeysync";

struct key_database_type {
	const char	*name;
	EFI_GUID	guid;
};

struct key_database_type keydb_types[] = {
	{ "KEK", EFI_GLOBAL_VARIABLE },
	{ "db",  EFI_IMAGE_SECURITY_DATABASE_GUID },
	{ "dbx", EFI_IMAGE_SECURITY_DATABASE_GUID },
};

static const char *default_keystore_dirs[] = {
	"/etc/secureboot/keys",
	"/usr/share/secureboot/keys",
};


struct key {
	EFI_GUID			type;
	int				id_len;
	uint8_t				*id;

	char				*description;

	struct list_node		list;

	/* set for keys loaded from a filesystem keystore */
	struct fs_keystore_entry	*keystore_entry;
};

typedef int (*key_parse_func)(struct key *, uint8_t *, size_t);

struct cert_type {
	EFI_GUID	guid;
	key_parse_func	parse;
};

struct key_database {
	const struct key_database_type	*type;
	struct list_head		firmware_keys;
	struct list_head		filesystem_keys;
};

struct fs_keystore_entry {
	const struct key_database_type	*type;
	const char			*root;
	const char			*name;
	uint8_t				*data;
	size_t				len;
	struct list_node		keystore_list;
	struct list_node		new_list;
};

struct fs_keystore {
	struct list_head	keys;
};

struct sync_context {
	const char		*efivars_dir;
	struct key_database	*kek;
	struct key_database	*db;
	struct key_database	*dbx;
	struct fs_keystore	*fs_keystore;
	const char		**keystore_dirs;
	unsigned int		n_keystore_dirs;
	struct list_head	new_keys;
	bool			verbose;
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

static int sha256_key_parse(struct key *key, uint8_t *data, size_t len)
{
	const unsigned int sha256_id_size = 256 / 8;
	unsigned int i;

	if (len != sha256_id_size)
		return -1;

	key->id = talloc_memdup(key, data, sha256_id_size);
	key->id_len = sha256_id_size;

	key->description = talloc_array(key, char, len * 2 + 1);
	for (i = 0; i < len; i++)
		snprintf(&key->description[i*2], 3, "%02x", data[i]);
	key->description[len*2] = '\0';

	return 0;
}

static int x509_key_parse(struct key *key, uint8_t *data, size_t len)
{
	const int description_len = 160;
	ASN1_INTEGER *serial;
	const uint8_t *tmp;
	X509 *x509;
	int rc;

	rc = -1;

	tmp = data;

	x509 = d2i_X509(NULL, &tmp, len);
	if (!x509)
		return -1;

	/* we use the X509 serial number as the key ID */
	if (!x509->cert_info || !x509->cert_info->serialNumber)
		goto out;

	serial = x509->cert_info->serialNumber;

	key->id_len = ASN1_STRING_length(serial);
	key->id = talloc_memdup(key, ASN1_STRING_data(serial), key->id_len);

	key->description = talloc_array(key, char, description_len);
	X509_NAME_oneline(x509->cert_info->subject,
			key->description, description_len);

	rc = 0;

out:
	X509_free(x509);
	return rc;
}

struct cert_type cert_types[] = {
	{ EFI_CERT_SHA256_GUID, sha256_key_parse },
	{ EFI_CERT_X509_GUID, x509_key_parse },
};

static int guidcmp(const EFI_GUID *a, const EFI_GUID *b)
{
	return memcmp(a, b, sizeof(EFI_GUID));
}

static int key_parse(struct key *key, const EFI_GUID *type,
		uint8_t *data, size_t len)
{
	char guid_str[GUID_STRLEN];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cert_types); i++) {
		if (guidcmp(&cert_types[i].guid, type))
			continue;

		return cert_types[i].parse(key, data, len);
	}

	guid_to_str(type, guid_str);
	printf("warning: unknown signature type found:\n  %s\n",
			guid_str);
	return -1;

}

typedef int (*sigdata_fn)(EFI_SIGNATURE_DATA *, int, const EFI_GUID *, void *);

/**
 * Iterates an buffer of EFI_SIGNATURE_LISTs (at db_data, of length len),
 * and calls fn on each EFI_SIGNATURE_DATA item found.
 *
 * fn is passed the EFI_SIGNATURE_DATA pointer, and the length of the
 * signature data (including GUID header), the type of the signature list,
 * and a context pointer.
 */
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

	rc = key_parse(key, type, sigdata->SignatureData,
			len - sizeof(*sigdata));

	if (rc)
		talloc_free(key);
	else
		list_add(&kdb->firmware_keys, &key->list);

	return 0;
}

static int read_firmware_key_database(struct key_database *kdb,
		const char *dir)
{
	char guid_str[GUID_STRLEN];
	char *filename;
	uint8_t *buf;
	size_t len;

	guid_to_str(&kdb->type->guid, guid_str);

	filename = talloc_asprintf(kdb, "%s/%s-%s", dir,
					kdb->type->name, guid_str);

	if (fileio_read_file_noerror(ctx, filename, &buf, &len))
		return -1;

	/* efivars files start with a 32-bit attribute block */
	buf += sizeof(uint32_t);
	len -= sizeof(uint32_t);

	sigdb_iterate(buf, len, sigdb_add_key, kdb);

	return 0;
}

struct keystore_add_ctx {
	struct fs_keystore *keystore;
	struct fs_keystore_entry *ke;
	struct key_database *kdb;
};

static int keystore_add_key(EFI_SIGNATURE_DATA *sigdata, int len,
		const EFI_GUID *type, void *arg)
{
	struct keystore_add_ctx *add_ctx = arg;
	struct key *key;
	int rc;

	key = talloc(add_ctx->kdb, struct key);
	key->keystore_entry = add_ctx->ke;
	key->type = *type;

	rc = key_parse(key, type, sigdata->SignatureData,
			len - sizeof(*sigdata));

	if (rc) {
		talloc_free(key);
		return 0;
	}

	/* add a reference to the data: we don't want it to be
	 * deallocated if the keystore is deallocated before the
	 * struct key. */
	talloc_reference(key, add_ctx->ke->data);
	list_add(&add_ctx->kdb->filesystem_keys, &key->list);

	return 0;
}

static void __attribute__((format(printf, 2, 3))) print_keystore_key_error(
		struct fs_keystore_entry *ke, const char *fmt, ...)
{
	char *errstr;
	va_list ap;

	va_start(ap, fmt);
	errstr = talloc_vasprintf(ke, fmt, ap);

	fprintf(stderr, "Invalid key %s/%s\n - %s\n", ke->root, ke->name,
			errstr);

	talloc_free(errstr);
	va_end(ap);
}

static int read_keystore_key_database(struct key_database *kdb,
		struct fs_keystore *keystore)
{
	EFI_GUID cert_type_pkcs7 = EFI_CERT_TYPE_PKCS7_GUID;
	EFI_VARIABLE_AUTHENTICATION_2 *auth;
	struct keystore_add_ctx add_ctx;
	struct fs_keystore_entry *ke;
	int rc;

	add_ctx.keystore = keystore;
	add_ctx.kdb = kdb;

	list_for_each(&keystore->keys, ke, keystore_list) {
		unsigned int len;
		void *buf;

		if (ke->len == 0)
			continue;

		if (ke->type != kdb->type)
			continue;

		/* parse the three data structures:
		 *  EFI_VARIABLE_AUTHENTICATION_2 token
		 *  EFI_SIGNATURE_LIST
		 *  EFI_SIGNATURE_DATA
		 * ensuring that we have enough data for each
		 */

		buf = ke->data;
		len = ke->len;

		if (len < sizeof(*auth)) {
			print_keystore_key_error(ke, "does not contain an "
				"EFI_VARIABLE_AUTHENTICATION_2 descriptor");
			continue;
		}

		auth = buf;

		if (guidcmp(&auth->AuthInfo.CertType, &cert_type_pkcs7)) {
			print_keystore_key_error(ke, "unknown cert type");
			continue;
		}

		if (auth->AuthInfo.Hdr.dwLength > len) {
			print_keystore_key_error(ke,
					"invalid WIN_CERTIFICATE length");
			continue;
		}

		/* the dwLength field includes the size of the WIN_CERTIFICATE,
		 * but not the other data in the EFI_VARIABLE_AUTHENTICATION_2
		 * descriptor */
		buf += sizeof(*auth) - sizeof(auth->AuthInfo) +
			auth->AuthInfo.Hdr.dwLength;
		len -= sizeof(*auth) - sizeof(auth->AuthInfo) +
			auth->AuthInfo.Hdr.dwLength;

		add_ctx.ke = ke;
		rc = sigdb_iterate(buf, len, keystore_add_key, &add_ctx);
		if (rc) {
			print_keystore_key_error(ke, "error parsing "
					"EFI_SIGNATURE_LIST");
			continue;
		}

	}

	return 0;
}

static int read_key_databases(struct sync_context *ctx)
{
	struct key_database *kdbs[] = {
		ctx->kek,
		ctx->db,
		ctx->dbx,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(kdbs); i++) {
		struct key_database *kdb = kdbs[i];
		read_firmware_key_database(kdb, ctx->efivars_dir);
		read_keystore_key_database(kdb, ctx->fs_keystore);
	}

	return 0;
}

static void print_key_database(struct key_database *kdb)
{
	struct key *key;

	printf("  %s (firmware)\n", kdb->type->name);

	list_for_each(&kdb->firmware_keys, key, list)
		printf("    %s\n", key->description);

	printf("  %s (filesystem)\n", kdb->type->name);

	list_for_each(&kdb->filesystem_keys, key, list) {
		printf("    %s\n", key->description);
		printf("     from %s/%s\n",
				key->keystore_entry->root,
				key->keystore_entry->name);
	}
}

static void print_key_databases(struct sync_context *ctx)
{
	printf("EFI key databases:\n");
	print_key_database(ctx->kek);
	print_key_database(ctx->db);
	print_key_database(ctx->dbx);
}

static int check_efivars_mount(const char *mountpoint)
{
	struct statfs statbuf;
	int rc;

	rc = statfs(mountpoint, &statbuf);
	if (rc)
		return -1;

	if (statbuf.f_type != EFIVARS_FSTYPE)
		return -1;

	return 0;
}

/* for each root directory, top-level first:
 *  for each db/dbx/KEK:
 *   for each file:
 *     if file exists in keystore, skip
 *     add file to keystore
 */

static int keystore_entry_read(struct fs_keystore_entry *ke)
{
	const char *path;

	path = talloc_asprintf(ke, "%s/%s", ke->root, ke->name);

	if (fileio_read_file(ke, path, &ke->data, &ke->len)) {
		talloc_free(ke);
		return -1;
	}

	talloc_free(path);

	return 0;
}

static bool keystore_contains_file(struct fs_keystore *keystore,
		const char *filename)
{
	struct fs_keystore_entry *ke;

	list_for_each(&keystore->keys, ke, keystore_list) {
		if (!strcmp(ke->name, filename))
			return true;
	}

	return false;
}

static int update_keystore(struct fs_keystore *keystore, const char *root)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(keydb_types); i++) {
		const char *dirname, *filename;
		struct dirent *dirent;
		DIR *dir;

		dirname = talloc_asprintf(keystore, "%s/%s", root,
					keydb_types[i].name);

		dir = opendir(dirname);
		if (!dir)
			continue;

		for (dirent = readdir(dir); dirent; dirent = readdir(dir)) {
			struct fs_keystore_entry *ke;

			if (dirent->d_name[0] == '.')
				continue;

			filename = talloc_asprintf(dirname, "%s/%s",
					keydb_types[i].name,
					dirent->d_name);

			if (keystore_contains_file(keystore, filename))
				continue;

			ke = talloc(keystore, struct fs_keystore_entry);
			ke->name = filename;
			ke->root = root;
			ke->type = &keydb_types[i];
			talloc_steal(ke, ke->name);

			if (keystore_entry_read(ke))
				talloc_free(ke);
			else
				list_add(&keystore->keys, &ke->keystore_list);
		}

		closedir(dir);
		talloc_free(dirname);
	}
	return 0;
}

static int read_keystore(struct sync_context *ctx)
{
	struct fs_keystore *keystore;
	unsigned int i;

	keystore = talloc(ctx, struct fs_keystore);
	list_head_init(&keystore->keys);

	for (i = 0; i < ctx->n_keystore_dirs; i++) {
		update_keystore(keystore, ctx->keystore_dirs[i]);
	}

	ctx->fs_keystore = keystore;

	return 0;
}

static void print_keystore(struct fs_keystore *keystore)
{
	struct fs_keystore_entry *ke;

	printf("Filesystem keystore:\n");

	list_for_each(&keystore->keys, ke, keystore_list)
		printf("  %s/%s [%zd bytes]\n", ke->root, ke->name, ke->len);
}

static int key_cmp(struct key *a, struct key *b)
{
	if (a->id_len != b->id_len)
		return a->id_len - b->id_len;

	return memcmp(a->id, b->id, a->id_len);
}

static int find_new_keys_in_kdb(struct sync_context *ctx,
		struct key_database *kdb)
{
	struct fs_keystore_entry *ke;
	struct key *fs_key, *fw_key;
	bool found;
	int n = 0;

	list_for_each(&kdb->filesystem_keys, fs_key, list) {
		found = false;
		list_for_each(&kdb->firmware_keys, fw_key, list) {
			if (!key_cmp(fs_key, fw_key)) {
				found = true;
				break;
			}
		}
		if (found)
			continue;

		/* add the keystore entry if it's not already present */
		found = false;
		list_for_each(&ctx->new_keys, ke, new_list) {
			if (fs_key->keystore_entry == ke) {
				found = true;
				break;
			}
		}

		if (found)
			continue;

		list_add(&ctx->new_keys, &fs_key->keystore_entry->new_list);
		n++;
	}

	return n;
}

/* Find the keys that are present in the filesystem, but not the firmware.
 * Returns:
 *  0   if there are no new keys to add
 *  >0  if there are keys to add
 *  -1  on error
 */
static int find_new_keys(struct sync_context *ctx)
{
	struct key_database *kdbs[] = {
		ctx->kek,
		ctx->db,
		ctx->dbx,
	};
	unsigned int n, i;
	int rc;

	n = 0;

	for (i = 0; i < ARRAY_SIZE(kdbs); i++) {
		rc = find_new_keys_in_kdb(ctx, kdbs[i]);
		if (rc < 0)
			return rc;
		n += rc;
	}

	return n;
}

static void print_new_keys(struct sync_context *ctx)
{
	struct fs_keystore_entry *ke;

	printf("New keys to be added:\n");

	list_for_each(&ctx->new_keys, ke, new_list)
		printf(" %s/%s\n", ke->root, ke->name);
}

static void init_key_database(struct sync_context *ctx,
		struct key_database **kdb_p,
		const struct key_database_type *type)
{
	struct key_database *kdb;

	kdb = talloc(ctx, struct key_database);

	list_head_init(&kdb->firmware_keys);
	list_head_init(&kdb->filesystem_keys);
	kdb->type = type;

	*kdb_p = kdb;
}

static struct option options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "efivars-path", required_argument, NULL, 'e' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "no-default-keystores", no_argument, NULL, 'd' },
	{ "keystore", required_argument, NULL, 'k' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options]\n"
		"Update EFI key databases from the filesystem\n"
		"\n"
		"Options:\n"
		"\t--efivars-path <dir>  Path to efivars mountpoint\n"
		"\t                       (or regular directory for testing)\n"
		"\t--verbose             Print verbose progress information\n"
		"\t--keystore <dir>      Read keys from <dir>/{db,dbx,KEK}/*\n"
		"\t                       (can be specified multiple times,\n"
		"\t                       first dir takes precedence)\n"
		"\t--no-default-keystores\n"
		"\t                      Don't read keys from the default\n"
		"\t                       keystore dirs\n",
		toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

static void add_keystore_dir(struct sync_context *ctx, const char *dir)
{
	ctx->keystore_dirs = talloc_realloc(ctx, ctx->keystore_dirs,
			const char *, ++ctx->n_keystore_dirs);

	ctx->keystore_dirs[ctx->n_keystore_dirs - 1] =
				talloc_strdup(ctx->keystore_dirs, dir);
}

int main(int argc, char **argv)
{
	bool use_default_keystore_dirs;
	struct sync_context *ctx;

	use_default_keystore_dirs = true;
	ctx = talloc_zero(NULL, struct sync_context);
	list_head_init(&ctx->new_keys);

	for (;;) {
		int idx, c;
		c = getopt_long(argc, argv, "e:dkvhV", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'e':
			ctx->efivars_dir = optarg;
			break;
		case 'd':
			use_default_keystore_dirs = false;
			break;
		case 'k':
			add_keystore_dir(ctx, optarg);
			break;
		case 'v':
			ctx->verbose = true;
			break;
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

	init_key_database(ctx, &ctx->kek, &keydb_types[0]);
	init_key_database(ctx, &ctx->db, &keydb_types[1]);
	init_key_database(ctx, &ctx->dbx, &keydb_types[2]);

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	if (!ctx->efivars_dir) {
		ctx->efivars_dir = EFIVARS_MOUNTPOINT;
		if (check_efivars_mount(ctx->efivars_dir)) {
			fprintf(stderr, "Can't access efivars filesystem "
					"at %s, aborting\n", ctx->efivars_dir);
			return EXIT_FAILURE;
		}
	}

	if (use_default_keystore_dirs) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(default_keystore_dirs); i++)
			add_keystore_dir(ctx, default_keystore_dirs[i]);
	}


	read_keystore(ctx);
	read_key_databases(ctx);

	if (ctx->verbose) {
		print_key_databases(ctx);
		print_keystore(ctx->fs_keystore);
	}

	find_new_keys(ctx);

	if (ctx->verbose)
		print_new_keys(ctx);

	return EXIT_SUCCESS;
}
