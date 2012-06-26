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
	uint8_t *buf;
	int rc, c;

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

	image_find_regions(ctx->image);

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	BIO *privkey_bio = BIO_new_file(keyfilename, "r");
	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(privkey_bio, NULL, NULL, NULL);
	if (!pkey) {
		fprintf(stderr, "error reading private key %s\n", keyfilename);
		return EXIT_FAILURE;
	}

	BIO *cert_bio = BIO_new_file(certfilename, "r");
	X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);

	if (!cert) {
		fprintf(stderr, "error reading certificate %s\n", certfilename);
		return EXIT_FAILURE;
	}

	const EVP_MD *md = EVP_get_digestbyname("SHA256");

	/* set up the PKCS7 object */
	PKCS7 *p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);

	PKCS7_SIGNER_INFO *si = PKCS7_sign_add_signer(p7, cert,
			pkey, md, PKCS7_BINARY);

	PKCS7_content_new(p7, NID_pkcs7_data);

	rc = IDC_set(p7, si, ctx->image);
	if (rc)
		return EXIT_FAILURE;

	ctx->image->sigsize = i2d_PKCS7(p7, NULL);
	ctx->image->sigbuf = buf = talloc_array(ctx->image,
			uint8_t, ctx->image->sigsize);
	i2d_PKCS7(p7, &buf);
	ERR_print_errors_fp(stdout);

	if (ctx->detached)
		image_write_detached(ctx->image, ctx->outfilename);
	else
		image_write(ctx->image, ctx->outfilename);

	talloc_free(ctx);

	return EXIT_SUCCESS;
}

