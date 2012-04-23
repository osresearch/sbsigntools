#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <uuid/uuid.h>


#include "ccan/talloc/talloc.h"

struct efi_guid {
    uint32_t	data1;
    uint16_t	data2;
    uint16_t	data3;
    uint8_t	data4[8];
};

#if __BYTE_ORDER != __LITTLE_ENDIAN
#error Only little-endian machines are supported currently
#endif

const struct efi_guid x509_guid = { 0xa5c059a1, 0x94e4, 0x4aa7, \
	{ 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };

struct efi_signature_data {
	struct efi_guid	SignatureOwner;
	uint8_t		SignatureData[];
};

struct efi_signature_list {
	struct efi_guid	SignatureType;
	uint32_t	SignatureListSize;
	uint32_t	SignatureHeaderSize;
	uint32_t	SignatureSize;
	/* this can follow directly, as we don't have a header */
	struct efi_signature_data	Signatures[];
};

struct keydata {
	void		*buf;
	unsigned int	size;
};

static void uuid_to_efi_guid(uuid_t u, struct efi_guid *e)
{
	/* The UUID is in raw format, so no byte-swapping is required */
	memcpy(e, u, sizeof(*e));
}

static struct keydata *slurp_file(const char *filename)
{
	unsigned int bytes_read;
	struct stat statbuf;
	struct keydata *keydata;
	int rc, fd;

	keydata = talloc(NULL, struct keydata);
	if (!keydata) {
		perror("talloc(keydata)");
		return NULL;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		goto err_free;
	}

	rc = fstat(fd, &statbuf);
	if (rc) {
		perror("fstat");
		goto err_close;
	}

	keydata->size = statbuf.st_size;

	keydata->buf = talloc_size(keydata, keydata->size);
	if (!keydata->buf) {
		perror("talloc(buf)");
		goto err_close;
	}

	for (bytes_read = 0; bytes_read < keydata->size; bytes_read += rc) {
		rc = read(fd, keydata->buf + bytes_read,
					keydata->size - bytes_read);
		if (rc < 0) {
			perror("read");
			break;
		}
		if (rc == 0)
			break;
	}

	if (bytes_read < keydata->size) {
		fprintf(stderr, "error reading input file\n");
		goto err_close;
	}

	close(fd);
	return keydata;

err_close:
	close(fd);
err_free:
	talloc_free(keydata);
	return NULL;
}

static int write_file(const char *filename, void *buf, unsigned int size)
{
	int fd, rc;

	fd = open(filename, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	rc = write(fd, buf, size);
	if (rc != (int)size) {
		perror("write");
		rc = -1;
	} else
		rc = 0;

	close(fd);
	return rc;
}

static int write_output(const char *basename,
		struct efi_signature_list *siglist)
{
	char *filename;

	/* write list */
	filename = talloc_asprintf(NULL, "%s.siglist", basename);
	write_file(filename, siglist, siglist->SignatureListSize);
	talloc_free(filename);

	/* write single entry data */
	filename = talloc_asprintf(NULL, "%s.sigdata", basename);
	write_file(filename, siglist->Signatures, siglist->SignatureSize);
	talloc_free(filename);

	return 0;
}

int main(int argc, char **argv)
{
	struct efi_signature_list *siglist;
	struct efi_signature_data *sigdata;
	struct keydata *keydata;
	const char *filename;
	int rc, siglist_size;
	uuid_t owner_uuid;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <owner-uuid> <keyfile>\n", argv[0]);
		return EXIT_FAILURE;
	}


	rc = uuid_parse(argv[1], owner_uuid);
	if (rc) {
		fprintf(stderr, "failed to parse uuid '%s'\n", argv[1]);
		return EXIT_FAILURE;
	}
	filename = argv[2];

	keydata = slurp_file(filename);
	if (!keydata)
		return EXIT_FAILURE;

	siglist_size =
		sizeof(struct efi_signature_list) +
		sizeof(struct efi_signature_data) +
		keydata->size;

	siglist = talloc_size(keydata, siglist_size);

	siglist->SignatureType = x509_guid;
	siglist->SignatureListSize = siglist_size;
	siglist->SignatureHeaderSize = 0;
	siglist->SignatureSize = sizeof(struct efi_signature_data) +
					keydata->size;
	sigdata = siglist->Signatures;
	uuid_to_efi_guid(owner_uuid, &sigdata->SignatureOwner);
	memcpy(sigdata->SignatureData, keydata->buf, keydata->size);

	write_output(filename, siglist);

	return 0;
}
