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

#include <getopt.h>

#include <ccan/talloc/talloc.h>

#include "image.h"
#include "idc.h"

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

enum verify_status {
	VERIFY_FAIL = 0,
	VERIFY_OK = 1,
};

static struct option options[] = {
	{ "cert", required_argument, NULL, 'c' },
	{ "no-verify", no_argument, NULL, 'n' },
	{ NULL, 0, NULL, 0 },
};

static void usage(const char *progname)
{
	fprintf(stderr,
		"usage: %s --cert <certfile> <efi-boot-image>\n"
		"options:\n"
		"\t--cert <certfile>  certificate (x509 certificate)\n"
		"\t--no-verify        don't perform certificate verification\n",
			progname);
}

int load_cert(X509_STORE *certs, const char *filename)
{
	X509 *cert;
	BIO *bio;

	bio = NULL;
	cert = NULL;

	bio = BIO_new_file(filename, "r");
	if (!bio) {
		fprintf(stderr, "Couldn't open file %s\n", filename);
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!cert) {
		fprintf(stderr, "Couldn't read certificate file %s\n",
				filename);
		goto err;
	}

	X509_STORE_add_cert(certs, cert);
	return 0;

err:
	ERR_print_errors_fp(stderr);
	if (cert)
		X509_free(cert);
	if (bio)
		BIO_free(bio);
	return -1;
}

static int x509_verify_cb(int status, X509_STORE_CTX *ctx)
{
	int err = X509_STORE_CTX_get_error(ctx);

	/* also accept code-signing keys */
	if (err == X509_V_ERR_INVALID_PURPOSE
			&& ctx->cert->ex_xkusage == XKU_CODE_SIGN)
		status = 1;

	return status;
}

int main(int argc, char **argv)
{
	struct cert_table_header *header;
	enum verify_status status;
	int rc, c, flags, verify;
	struct image *image;
	const uint8_t *buf;
	X509_STORE *certs;
	struct idc *idc;
	BIO *idcbio;
	PKCS7 *p7;

	status = VERIFY_FAIL;
	certs = X509_STORE_new();
	verify = 1;

	ERR_load_crypto_strings();

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "c:n", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			rc = load_cert(certs, optarg);
			if (rc)
				return EXIT_FAILURE;
			break;
		case 'n':
			verify = 0;
			break;
		}

	}

	if (argc != optind + 1) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	image = image_load(argv[optind]);
	image_pecoff_parse(image);
	image_find_regions(image);

	if (!image->data_dir_sigtable->addr
			|| !image->data_dir_sigtable->size) {
		fprintf(stderr, "No signature table present\n");
		goto out;
	}

	header = image->buf + image->data_dir_sigtable->addr;

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	buf = (void *)(header + 1);
	p7 = d2i_PKCS7(NULL, &buf, header->size);

	idcbio = BIO_new(BIO_s_mem());
	idc = IDC_get(p7, idcbio);
	if (!idc)
		goto out;

	rc = IDC_check_hash(idc, image);
	if (rc)
		goto out;

	flags = PKCS7_BINARY;
	if (!verify)
		flags |= PKCS7_NOVERIFY;

	X509_STORE_set_verify_cb_func(certs, x509_verify_cb);
	rc = PKCS7_verify(p7, NULL, certs, idcbio, NULL, flags);
	if (!rc) {
		printf("PKCS7 verification failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	status = VERIFY_OK;

out:
	talloc_free(image);
	if (status == VERIFY_OK)
		printf("Signature verification OK\n");
	else
		printf("Signature verification failed\n");

	return status == VERIFY_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
