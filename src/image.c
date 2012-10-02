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

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <ccan/talloc/talloc.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/build_assert/build_assert.h>
#include <openssl/sha.h>

#include "fileio.h"
#include "image.h"

#define DATA_DIR_CERT_TABLE	4

#define CERT_TABLE_TYPE_PKCS	0x0002	/* PKCS signedData */
#define CERT_TABLE_REVISION	0x0200	/* revision 2 */

/**
 * The PE/COFF headers export struct fields as arrays of chars. So, define
 * a couple of accessor functions that allow fields to be deferenced as their
 * native types, to allow strict aliasing. This also allows for endian-
 * neutral behaviour.
 */
static uint32_t __pehdr_u32(char field[])
{
	uint8_t *ufield = (uint8_t *)field;
	return (ufield[3] << 24) +
		(ufield[2] << 16) +
		(ufield[1] << 8) +
		ufield[0];
}

static uint16_t __pehdr_u16(char field[])
{
	uint8_t *ufield = (uint8_t *)field;
	return (ufield[1] << 8) +
		ufield[0];
}

/* wrappers to ensure type correctness */
#define pehdr_u32(f) __pehdr_u32(f + BUILD_ASSERT_OR_ZERO(sizeof(f) == 4))
#define pehdr_u16(f) __pehdr_u16(f + BUILD_ASSERT_OR_ZERO(sizeof(f) == 2))

/* Machine-specific PE/COFF parse functions. These parse the relevant a.out
 * header for the machine type, and set the following members of struct image:
 *   - aouthdr_size
 *   - file_alignment
 *   - header_size
 *   - data_dir
 *   - checksum
 *
 *  These functions require image->opthdr to be set by the caller.
 */
static int image_pecoff_parse_32(struct image *image)
{
	if (image->opthdr.opt_32->standard.magic[0] != 0x0b ||
			image->opthdr.opt_32->standard.magic[1] != 0x01) {
		fprintf(stderr, "Invalid a.out machine type\n");
		return -1;
	}

	image->opthdr_min_size = sizeof(*image->opthdr.opt_32) -
				sizeof(image->opthdr.opt_32->DataDirectory);

	image->file_alignment =
		pehdr_u32(image->opthdr.opt_32->FileAlignment);
	image->header_size =
		pehdr_u32(image->opthdr.opt_32->SizeOfHeaders);

	image->data_dir = (void *)image->opthdr.opt_32->DataDirectory;
	image->checksum = (uint32_t *)image->opthdr.opt_32->CheckSum;
	return 0;
}

static int image_pecoff_parse_64(struct image *image)
{
	if (image->opthdr.opt_64->standard.magic[0] != 0x0b ||
			image->opthdr.opt_64->standard.magic[1] != 0x02) {
		fprintf(stderr, "Invalid a.out machine type\n");
		return -1;
	}

	image->opthdr_min_size = sizeof(*image->opthdr.opt_64) -
				sizeof(image->opthdr.opt_64->DataDirectory);

	image->file_alignment =
		pehdr_u32(image->opthdr.opt_64->FileAlignment);
	image->header_size =
		pehdr_u32(image->opthdr.opt_64->SizeOfHeaders);

	image->data_dir = (void *)image->opthdr.opt_64->DataDirectory;
	image->checksum = (uint32_t *)image->opthdr.opt_64->CheckSum;
	return 0;
}

static int image_pecoff_parse(struct image *image)
{
	struct cert_table_header *cert_table;
	char nt_sig[] = {'P', 'E', 0, 0};
	size_t size = image->size;
	int rc, cert_table_offset;
	void *buf = image->buf;
	uint16_t magic;
	uint32_t addr;

	/* sanity checks */
	if (size < sizeof(*image->doshdr)) {
		fprintf(stderr, "file is too small for DOS header\n");
		return -1;
	}

	image->doshdr = buf;

	if (image->doshdr->e_magic[0] != 0x4d
			|| image->doshdr->e_magic[1] != 0x5a) {
		fprintf(stderr, "Invalid DOS header magic\n");
		return -1;
	}

	addr = pehdr_u32(image->doshdr->e_lfanew);
	if (addr >= image->size) {
		fprintf(stderr, "pehdr is beyond end of file [0x%08x]\n",
				addr);
		return -1;
	}

	if (addr + sizeof(*image->pehdr) > image->size) {
		fprintf(stderr, "File not large enough to contain pehdr\n");
		return -1;
	}

	image->pehdr = buf + addr;
	if (memcmp(image->pehdr->nt_signature, nt_sig, sizeof(nt_sig))) {
		fprintf(stderr, "Invalid PE header signature\n");
		return -1;
	}

	/* a.out header directly follows PE header */
	image->opthdr.addr = image->pehdr + 1;
	magic = pehdr_u16(image->pehdr->f_magic);

	if (magic == IMAGE_FILE_MACHINE_AMD64) {
		rc = image_pecoff_parse_64(image);

	} else if (magic == IMAGE_FILE_MACHINE_I386) {
		rc = image_pecoff_parse_32(image);

	} else {
		fprintf(stderr, "Invalid PE header magic\n");
		return -1;
	}

	if (rc) {
		fprintf(stderr, "Error parsing a.out header\n");
		return -1;
	}

	/* the optional header has a variable size, as the data directory
	 * has a variable number of entries. Ensure that the we have enough
	 * space to include the security directory entry */
	image->opthdr_size = pehdr_u16(image->pehdr->f_opthdr);
	cert_table_offset = sizeof(*image->data_dir) *
				(DATA_DIR_CERT_TABLE + 1);

	if (image->opthdr_size < image->opthdr_min_size + cert_table_offset) {
		fprintf(stderr, "PE opt header too small (%d bytes) to contain "
				"a suitable data directory (need %d bytes)\n",
				image->opthdr_size,
				image->opthdr_min_size + cert_table_offset);
		return -1;
	}


	image->data_dir_sigtable = &image->data_dir[DATA_DIR_CERT_TABLE];

	if (image->size < sizeof(*image->doshdr) + sizeof(*image->pehdr)
			+ image->opthdr_size) {
		fprintf(stderr, "file is too small for a.out header\n");
		return -1;
	}

	image->cert_table_size = image->data_dir_sigtable->size;
	if (image->cert_table_size)
		cert_table = buf + image->data_dir_sigtable->addr;
	else
		cert_table = NULL;

	image->cert_table = cert_table;

	/* if we have a valid cert table header, populate sigbuf as a shadow
	 * copy of the cert table */
	if (cert_table && cert_table->revision == CERT_TABLE_REVISION &&
			cert_table->type == CERT_TABLE_TYPE_PKCS &&
			cert_table->size < size) {
		image->sigsize = cert_table->size;
		image->sigbuf = talloc_memdup(image, cert_table + 1,
				image->sigsize);
	}

	image->sections = pehdr_u16(image->pehdr->f_nscns);
	image->scnhdr = image->opthdr.addr + image->opthdr_size;

	return 0;
}

static int align_up(int size, int align)
{
	return (size + align - 1) & ~(align - 1);
}

static int cmp_regions(const void *p1, const void *p2)
{
	const struct region *r1 = p1, *r2 = p2;

	if (r1->data < r2->data)
		return -1;
	if (r1->data > r2->data)
		return 1;
	return 0;
}

static void set_region_from_range(struct region *region, void *start, void *end)
{
	region->data = start;
	region->size = end - start;
}

static int image_find_regions(struct image *image)
{
	struct region *regions, *r;
	void *buf = image->buf;
	int i, gap_warn;
	size_t bytes;

	gap_warn = 0;

	/* now we know where the checksum and cert table data is, we can
	 * construct regions that need to be signed */
	bytes = 0;
	image->n_checksum_regions = 0;
	image->checksum_regions = NULL;

	image->n_checksum_regions = 3;
	image->checksum_regions = talloc_zero_array(image,
					struct region,
					image->n_checksum_regions);

	/* first region: beginning to checksum field */
	regions = image->checksum_regions;
	set_region_from_range(&regions[0], buf, image->checksum);
	regions[0].name = "begin->cksum";
	bytes += regions[0].size;

	bytes += sizeof(*image->checksum);

	/* second region: end of checksum to certificate table entry */
	set_region_from_range(&regions[1],
			image->checksum + 1,
			image->data_dir_sigtable
			);
	regions[1].name = "cksum->datadir[CERT]";
	bytes += regions[1].size;

	bytes += sizeof(struct data_dir_entry);
	/* third region: end of checksum to end of headers */
	set_region_from_range(&regions[2],
				(void *)image->data_dir_sigtable
					+ sizeof(struct data_dir_entry),
				buf + image->header_size);
	regions[2].name = "datadir[CERT]->headers";
	bytes += regions[2].size;

	/* add COFF sections */
	for (i = 0; i < image->sections; i++) {
		uint32_t file_offset, file_size;

		file_offset = pehdr_u32(image->scnhdr[i].s_scnptr);
		file_size = pehdr_u32(image->scnhdr[i].s_size);

		if (!file_size)
			continue;

		image->n_checksum_regions++;
		image->checksum_regions = talloc_realloc(image,
				image->checksum_regions,
				struct region,
				image->n_checksum_regions);
		regions = image->checksum_regions;

		regions[i + 3].data = buf + file_offset;
		regions[i + 3].size = align_up(file_size,
					image->file_alignment);
		regions[i + 3].name = talloc_strndup(image->checksum_regions,
					image->scnhdr[i].s_name, 8);
		bytes += regions[i + 3].size;

		if (file_offset + regions[i+3].size > image->size) {
			fprintf(stderr, "warning: file-aligned section %s "
					"extends beyond end of file\n",
					regions[i+3].name);
		}

		if (regions[i+2].data + regions[i+2].size
				!= regions[i+3].data) {
			fprintf(stderr, "warning: gap in section table:\n");
			fprintf(stderr, "    %-8s: 0x%08tx - 0x%08tx,\n",
					regions[i+2].name,
					regions[i+2].data - buf,
					regions[i+2].data +
						regions[i+2].size - buf);
			fprintf(stderr, "    %-8s: 0x%08tx - 0x%08tx,\n",
					regions[i+3].name,
					regions[i+3].data - buf,
					regions[i+3].data +
						regions[i+3].size - buf);


			gap_warn = 1;
		}
	}

	if (gap_warn)
		fprintf(stderr, "gaps in the section table may result in "
				"different checksums\n");

	qsort(image->checksum_regions, image->n_checksum_regions,
			sizeof(struct region), cmp_regions);

	if (bytes + image->cert_table_size < image->size) {
		int n = image->n_checksum_regions++;
		struct region *r;

		image->checksum_regions = talloc_realloc(image,
				image->checksum_regions,
				struct region,
				image->n_checksum_regions);
		r = &image->checksum_regions[n];
		r->name = "endjunk";
		r->data = image->buf + bytes;
		r->size = image->size - bytes - image->cert_table_size;

		fprintf(stderr, "warning: data remaining[%zd vs %zd]: gaps "
				"between PE/COFF sections?\n",
				bytes + image->cert_table_size, image->size);
	} else if (bytes + image->cert_table_size > image->size) {
		fprintf(stderr, "warning: checksum areas are greater than "
				"image size. Invalid section table?\n");
	}

	/* record the size of non-signature data */
	r = &image->checksum_regions[image->n_checksum_regions - 1];
	image->data_size = (r->data - (void *)image->buf) + r->size;

	return 0;
}

struct image *image_load(const char *filename)
{
	struct image *image;
	int rc;

	image = talloc(NULL, struct image);
	if (!image) {
		perror("talloc(image)");
		return NULL;
	}

	rc = fileio_read_file(image, filename, &image->buf, &image->size);
	if (rc)
		goto err;

reparse:
	rc = image_pecoff_parse(image);
	if (rc)
		goto err;

	rc = image_find_regions(image);
	if (rc)
		goto err;

	/* Some images may have incorrectly aligned sections, which get rounded
	 * up to a size that is larger that the image itself (and the buffer
	 * that we've allocated). We would have generated a warning about this,
	 * but we can improve our chances that the verification hash will
	 * succeed by padding the image out to the aligned size, and including
	 * the pad in the signed data.
	 *
	 * In this case, do a realloc, but that may peturb the addresses that
	 * we've calculated during the pecoff parsing, so we need to redo that
	 * too.
	 */
	if (image->data_size > image->size) {
		image->buf = talloc_realloc(image, image->buf, uint8_t,
				image->data_size);
		memset(image->buf + image->size, 0,
				image->data_size - image->size);
		image->size = image->data_size;

		goto reparse;
	}

	return image;
err:
	talloc_free(image);
	return NULL;
}

int image_hash_sha256(struct image *image, uint8_t digest[])
{
	struct region *region;
	SHA256_CTX ctx;
	int rc, i, n;

	rc = SHA256_Init(&ctx);
	if (!rc)
		return -1;

	n = 0;

	for (i = 0; i < image->n_checksum_regions; i++) {
		region = &image->checksum_regions[i];
		n += region->size;
#if 0
		printf("sum region: 0x%04lx -> 0x%04lx [0x%04x bytes]\n",
				region->data - image->buf,
				region->data - image->buf - 1 + region->size,
				region->size);

#endif
		rc = SHA256_Update(&ctx, region->data, region->size);
		if (!rc)
			return -1;
	}

	rc = SHA256_Final(digest, &ctx);

	return !rc;
}

int image_add_signature(struct image *image, void *sig, int size)
{
	/* we only support one signature at present */
	if (image->sigbuf) {
		fprintf(stderr, "warning: overwriting existing signature\n");
		talloc_free(image->sigbuf);
	}
	image->sigbuf = sig;
	image->sigsize = size;
	return 0;
}

void image_remove_signature(struct image *image)
{
	if (image->sigbuf)
		talloc_free(image->sigbuf);
	image->sigbuf = NULL;
	image->sigsize = 0;
}

int image_write(struct image *image, const char *filename)
{
	struct cert_table_header cert_table_header;
	int fd, rc, len, padlen;
	bool is_signed;
	uint8_t pad[8];

	is_signed = image->sigbuf && image->sigsize;
	padlen = 0;

	/* optionally update the image to contain signature data */
	if (is_signed) {
		cert_table_header.size = image->sigsize +
						sizeof(cert_table_header);
		cert_table_header.revision = CERT_TABLE_REVISION;
		cert_table_header.type = CERT_TABLE_TYPE_PKCS;

		len = sizeof(cert_table_header) + image->sigsize;

		/* pad to sizeof(pad)-byte boundary */
		padlen = align_up(len, sizeof(pad)) - len;

		image->data_dir_sigtable->addr = image->data_size;
		image->data_dir_sigtable->size = len + padlen;
	} else {
		image->data_dir_sigtable->addr = 0;
		image->data_dir_sigtable->size = 0;
	}

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	rc = write_all(fd, image->buf, image->data_size);
	if (!rc)
		goto out;
	if (!is_signed)
		goto out;

	rc = write_all(fd, &cert_table_header, sizeof(cert_table_header));
	if (!rc)
		goto out;

	rc = write_all(fd, image->sigbuf, image->sigsize);
	if (!rc)
		goto out;

	if (padlen) {
		memset(pad, 0, sizeof(pad));
		rc = write_all(fd, pad, padlen);
	}

out:
	close(fd);
	return !rc;
}

int image_write_detached(struct image *image, const char *filename)
{
	return fileio_write_file(filename, image->sigbuf, image->sigsize);
}
