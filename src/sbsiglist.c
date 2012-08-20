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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <getopt.h>

#include <uuid/uuid.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#include <ccan/array_size/array_size.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/talloc/talloc.h>

#include "efivars.h"
#include "fileio.h"

static const char *toolname = "sbsiglist";

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "type", required_argument, NULL, 't' },
	{ "owner", required_argument, NULL, 'w' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

struct cert_type {
	const char	*name;
	const EFI_GUID	guid;
	unsigned int	sigsize;
};

struct cert_type cert_types[] = {
	{ "x509",   EFI_CERT_X509_GUID,   0 },
	{ "sha256", EFI_CERT_SHA256_GUID, 32 },
};

struct siglist_context {
	int			verbose;

	const char		*infilename;
	const char		*outfilename;
	const struct cert_type	*type;
	EFI_GUID		owner;

	uint8_t			*data;
	size_t			data_len;

	EFI_SIGNATURE_LIST	*siglist;
};


void usage(void)
{
	unsigned int i;

	printf("Usage: %s [options] --owner <guid> --type <type> <sig-file>\n"
		"Create an EFI_SIGNATURE_LIST from a signature file\n"
		"Options:\n"
		"\t--owner <guid>   Signature owner GUID\n"
		"\t--type <type>    Signature type. One of:\n",
		toolname);

	for (i = 0; i < ARRAY_SIZE(cert_types); i++)
		printf("\t                     %s\n", cert_types[i].name);

	printf("\t--output <file>  write signed data to <file>\n"
		"\t                  (default <sig-file>.siglist)\n");
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

static int siglist_create(struct siglist_context *ctx)
{
	EFI_SIGNATURE_LIST *siglist;
	EFI_SIGNATURE_DATA *sigdata;
	uint32_t size;

	if (ctx->type->sigsize && ctx->data_len != ctx->type->sigsize) {
		fprintf(stderr, "Error: signature lists of type '%s' expect "
					"%d bytes of data, "
					"%zd bytes provided.\n",
				ctx->type->name,
				ctx->type->sigsize,
				ctx->data_len);
		return -1;
	}

	size = sizeof(*siglist) + sizeof(*sigdata) + ctx->data_len;

	siglist = talloc_size(ctx, size);
	sigdata = (void *)(siglist + 1);

	siglist->SignatureType = ctx->type->guid;
	siglist->SignatureListSize = size;
	siglist->SignatureHeaderSize = 0;
	siglist->SignatureSize = ctx->data_len + sizeof(*sigdata);

	sigdata->SignatureOwner = ctx->owner;

	memcpy(sigdata->SignatureData, ctx->data, ctx->data_len);

	ctx->siglist = siglist;

	return 0;
}

static int parse_guid(const char *str, EFI_GUID *guid)
{
	uuid_t uuid;

	if (uuid_parse(str, uuid))
		return -1;

	/* convert to an EFI_GUID */
	guid->Data1 = uuid[0] << 24 | uuid[1] << 16 | uuid[2] << 8 | uuid[3];
	guid->Data2 = uuid[4] << 8 | uuid[5];
	guid->Data3 = uuid[6] << 8 | uuid[7];
	memcpy(guid->Data4, &uuid[8], sizeof(guid->Data4));

	return 0;
}

static struct cert_type *parse_type(const char *str)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cert_types); i++)
		if (!strcasecmp(cert_types[i].name, str))
			return &cert_types[i];

	return NULL;
}

static void set_default_outfilename(struct siglist_context *ctx)
{
	const char *extension = "siglist";

	ctx->outfilename = talloc_asprintf(ctx, "%s.%s",
			ctx->infilename, extension);
}
int main(int argc, char **argv)
{
	const char *type_str, *owner_guid_str;
	struct siglist_context *ctx;
	int c;

	ctx = talloc_zero(NULL, struct siglist_context);

	owner_guid_str = NULL;
	type_str = NULL;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:t:w:ivVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			ctx->outfilename = optarg;
			break;
		case 't':
			type_str = optarg;
			break;
		case 'w':
			owner_guid_str = optarg;
			break;
		case 'v':
			ctx->verbose = 1;
			break;
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		}
	}

	if (argc != optind + 1) {
		usage();
		return EXIT_FAILURE;
	}

	ctx->infilename = argv[optind];

	if (!type_str) {
		fprintf(stderr, "No type specified\n");
		usage();
		return EXIT_FAILURE;
	}

	if (!type_str) {
		fprintf(stderr, "No owner specified\n");
		usage();
		return EXIT_FAILURE;
	}

	ctx->type = parse_type(type_str);
	if (!ctx->type) {
		fprintf(stderr, "Invalid type '%s'\n", type_str);
		return EXIT_FAILURE;
	}

	if (parse_guid(owner_guid_str, &ctx->owner)) {
		fprintf(stderr, "Invalid owner GUID '%s'\n", owner_guid_str);
		return EXIT_FAILURE;
	}

	if (!ctx->outfilename)
		set_default_outfilename(ctx);

	if (fileio_read_file(ctx, ctx->infilename,
				&ctx->data, &ctx->data_len)) {
		fprintf(stderr, "Can't read input file %s\n", ctx->infilename);
		return EXIT_FAILURE;
	}

	if (siglist_create(ctx))
		return EXIT_FAILURE;

	if (fileio_write_file(ctx->outfilename,
				(void *)ctx->siglist,
				ctx->siglist->SignatureListSize)) {
		fprintf(stderr, "Can't write output file %s\n",
				ctx->outfilename);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
