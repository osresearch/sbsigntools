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
#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

#include <bfd.h>
#define DO_NOT_DEFINE_LINENO

#include "coff/x86_64.h"
#include "coff/external.h"
#include "coff/pe.h"

struct region {
	void	*data;
	int	size;
	char	*name;
};

struct image {
	int		fd;
	void		*buf;
	size_t		size;

	/* Pointers to interesting parts of the image */
	uint32_t	*checksum;
	struct external_PEI_DOS_hdr *doshdr;
	struct external_PEI_IMAGE_hdr *pehdr;
	PEPAOUTHDR	*aouthdr;
	struct data_dir_entry *data_dir;
	struct data_dir_entry *data_dir_sigtable;
	struct external_scnhdr *scnhdr;
	int		sections;

	void		*cert_table;
	int		cert_table_size;

	/* Regions that are included in the image hash: populated
	 * during image parsing, then used during the hash process.
	 */
	struct region	*checksum_regions;
	int		n_checksum_regions;

	/* Generated signature */
	void		*sigbuf;
	size_t		sigsize;

};

struct data_dir_entry {
	uint32_t	addr;
	uint32_t	size;
} __attribute__((packed));

struct cert_table_header {
	uint32_t size;
	uint16_t revision;
	uint16_t type;
} __attribute__((packed));

struct image *image_load(const char *filename);

int image_pecoff_parse(struct image *image);
int image_find_regions(struct image *image);
int image_hash_sha256(struct image *image, uint8_t digest[]);
int image_write_signed(struct image *image, const char *filename);

#endif /* IMAGE_H */

