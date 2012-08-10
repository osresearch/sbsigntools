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
#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

#include <bfd.h>
#define DO_NOT_DEFINE_LINENO

#include "coff/external.h"
#include "coff/pe.h"

struct region {
	void	*data;
	int	size;
	char	*name;
};

struct image {
	uint8_t		*buf;
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

int image_find_regions(struct image *image);
int image_hash_sha256(struct image *image, uint8_t digest[]);
int image_add_signature(struct image *, void *sig, int size);
void image_remove_signature(struct image *image);
int image_write(struct image *image, const char *filename);
int image_write_detached(struct image *image, const char *filename);

#endif /* IMAGE_H */

