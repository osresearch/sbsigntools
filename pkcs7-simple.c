
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

static const char *keyfile = "keys/archive-subkey-private.key";
static const char *certfile = "keys/archive-subkey-public.crt";

int main(void)
{
	uint8_t data[] = {'m', 'e', 'e', 'p'};
	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	BIO *stdout_bio = BIO_new_fd(STDOUT_FILENO, 0);

	BIO *privkey_bio = BIO_new_file(keyfile, "r");
	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(privkey_bio, NULL, NULL, NULL);
	if (!pkey) {
		fprintf(stderr, "error reading private key %s\n", keyfile);
		return EXIT_FAILURE;
	}

	if (0)
		EVP_PKEY_print_public(stdout_bio, pkey, 4, NULL);

	BIO *cert_bio = BIO_new_file(certfile, "r");
	X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);

	if (!pkey) {
		fprintf(stderr, "error reading certificate %s\n", certfile);
		return EXIT_FAILURE;
	}

	BIO *bio = BIO_new_mem_buf(data, sizeof(data));

	PKCS7 *p7 = PKCS7_sign(cert, pkey, NULL, bio, PKCS7_BINARY);

	ERR_print_errors_fp(stdout);

	int ofd = open("out.pkcs7", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	BIO *out_bio = BIO_new_fd(ofd, 1);
	i2d_PKCS7_bio_stream(out_bio, p7, NULL, 0);
	ERR_print_errors_fp(stdout);

	return EXIT_SUCCESS;
}
