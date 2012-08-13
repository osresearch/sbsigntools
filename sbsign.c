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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include <getopt.h>

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <ccan/talloc/talloc.h>

#include "idc.h"
#include "image.h"
#include "fileio.h"

static const char *toolname = "sbsign";

struct sign_context {
	struct image *image;
	const char *infilename;
	const char *outfilename;
	int verbose;
	int detached;
};

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "cert", required_argument, NULL, 'c' },
	{ "key", required_argument, NULL, 'k' },
	{ "detached", no_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options] --key <keyfile> --cert <certfile> "
			"<efi-boot-image>\n"
		"Sign an EFI boot image for use with secure boot.\n\n"
		"Options:\n"
		"\t--key <keyfile>    signing key (PEM-encoded RSA "
						"private key)\n"
		"\t--cert <certfile>  certificate (x509 certificate)\n"
		"\t--detached         write a detached signature, instead of\n"
		"\t                    a signed binary\n"
		"\t--output <file>    write signed data to <file>\n"
		"\t                    (default <efi-boot-image>.signed,\n"
		"\t                    or <efi-boot-image>.pk7 for detached\n"
		"\t                    signatures)\n",
		toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

static void set_default_outfilename(struct sign_context *ctx)
{
	const char *extension;

	extension = ctx->detached ? "pk7" : "signed";

	ctx->outfilename = talloc_asprintf(ctx, "%s.%s",
			ctx->infilename, extension);
}

int main(int argc, char **argv)
{
	const char *keyfilename, *certfilename;
	struct sign_context *ctx;
	uint8_t *buf, *tmp;
	int rc, c, sigsize;

	ctx = talloc_zero(NULL, struct sign_context);

	keyfilename = NULL;
	certfilename = NULL;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:c:k:dvVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			ctx->outfilename = talloc_strdup(ctx, optarg);
			break;
		case 'c':
			certfilename = optarg;
			break;
		case 'k':
			keyfilename = optarg;
			break;
		case 'd':
			ctx->detached = 1;
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
	if (!ctx->outfilename)
		set_default_outfilename(ctx);

	if (!certfilename) {
		fprintf(stderr,
			"error: No certificate specified (with --cert)\n");
		usage();
		return EXIT_FAILURE;
	}
	if (!keyfilename) {
		fprintf(stderr,
			"error: No key specified (with --key)\n");
		usage();
		return EXIT_FAILURE;
	}

	ctx->image = image_load(ctx->infilename);
	if (!ctx->image)
		return EXIT_FAILURE;

	talloc_steal(ctx, ctx->image);

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	EVP_PKEY *pkey = fileio_read_pkey(keyfilename);
	if (!pkey)
		return EXIT_FAILURE;

	X509 *cert = fileio_read_cert(certfilename);
	if (!cert)
		return EXIT_FAILURE;

	const EVP_MD *md = EVP_get_digestbyname("SHA256");

	/* set up the PKCS7 object */
	PKCS7 *p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);

	PKCS7_SIGNER_INFO *si = PKCS7_sign_add_signer(p7, cert,
			pkey, md, PKCS7_BINARY);
	if (!si) {
		fprintf(stderr, "error in key/certificate chain\n");
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	PKCS7_content_new(p7, NID_pkcs7_data);

	rc = IDC_set(p7, si, ctx->image);
	if (rc)
		return EXIT_FAILURE;

	sigsize = i2d_PKCS7(p7, NULL);
	tmp = buf = talloc_array(ctx->image, uint8_t, sigsize);
	i2d_PKCS7(p7, &tmp);
	ERR_print_errors_fp(stdout);

	image_add_signature(ctx->image, buf, sigsize);

	if (ctx->detached)
		image_write_detached(ctx->image, ctx->outfilename);
	else
		image_write(ctx->image, ctx->outfilename);

	talloc_free(ctx);

	return EXIT_SUCCESS;
}

