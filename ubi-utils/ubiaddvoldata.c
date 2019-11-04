/*
 * Copyright (C) 2008 Nokia Corporation
 * Copyright (c) International Business Machines Corp., 2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * Generate UBI images.
 *
 * Authors: Artem Bityutskiy
 *          Oliver Lohmann
 */

#define PROGRAM_NAME    "ubiaddvoldata"

#include <sys/stat.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>

#include <mtd/ubi-media.h>
#include <libubigen.h>
#include <libiniparser.h>
#include <libubi.h>
#include <mtd_swab.h>
#include <crc32.h>
#include "common.h"

static const char optionsstr[] =
"-i, --image=<file name>      image file name\n"
"-z, --meta=<file name>       input meta-data file name\n"
"-v, --verbose                be verbose\n"
"-h, --help                   print help message\n"
"-V, --version                print program version\n\n";

static const char usage[] =
"Usage: " PROGRAM_NAME " [options] [ID FILE]...\n\n"
"Generate UBI images. An UBI image may contain one or more UBI volumes which\n"
"have to be defined in the input configuration ini-file. The flash\n"
"characteristics are defined via the command-line options.\n\n";

static const struct option long_options[] = {
	{ .name = "image",          .has_arg = 1, .flag = NULL, .val = 'i' },
	{ .name = "meta",           .has_arg = 1, .flag = NULL, .val = 'z' },
	{ .name = "verbose",        .has_arg = 0, .flag = NULL, .val = 'v' },
	{ .name = "help",           .has_arg = 0, .flag = NULL, .val = 'h' },
	{ .name = "version",        .has_arg = 0, .flag = NULL, .val = 'V' },
	{ NULL, 0, NULL, 0}
};

struct args {
	const char *f_image;
	const char *f_meta;
	int image_fd;
	int meta_fd;
	int verbose;
};

static struct args args = {
	.f_image = NULL,
	.f_meta = NULL,
	.image_fd = -1,
	.meta_fd = -1,
	.verbose = 0
};

static int parse_opt(int argc, char * const argv[])
{
	while (1) {
		int key;

		key = getopt_long(argc, argv, "i:z:vhV", long_options, NULL);
		if (key == -1)
			break;

		switch (key) {
		case 'i':
			args.f_image = optarg;
			break;

		case 'z':
			args.meta_fd = open(optarg, O_RDONLY, 0);
			if (args.meta_fd == -1)
				return sys_errmsg("cannot open file \"%s\"", optarg);
			args.f_meta = optarg;
			break;

		case 'v':
			args.verbose = 1;
			break;

		case 'h':
			fputs(usage, stdout);
			fputs(optionsstr, stdout);
			printf("For more information see `man 8 %s`\n\n",
				PROGRAM_NAME);
			exit(EXIT_SUCCESS);

		case 'V':
			common_print_version();
			exit(EXIT_SUCCESS);

		default:
			fputs(usage, stderr);
			fputs("Use -h for help\n\n", stderr);
			return -1;
		}
	}

	if (!args.f_image)
		return errmsg("image file was not specified (use -h for help)");
	if (!args.f_meta)
		return errmsg("meta file was not specified (use -h for help)");

	if ((argc - optind) % 2)
		return errmsg("number of positional args is not a multiple of 2");

	return 0;
}

static int open_image_file(off_t *sz)
{
	int fd;
	struct stat st;

	if (stat(args.f_image, &st))
		return sys_errmsg("cannot open \"%s\"", args.f_image);

	*sz = st.st_size;
	fd  = open(args.f_image, O_RDWR);
	if (fd == -1)
		return sys_errmsg("cannot open \"%s\"", args.f_image);

	if (lseek(fd, 0, SEEK_END) < 0) {
		sys_errmsg("cannot lseek \"%s\" to end", args.f_image);
		return -1;
	}

	return fd;
}

static int read_all(int fd, void *buf, size_t len)
{
	while (len > 0) {
		ssize_t l = read(fd, buf, len);
		if (l == 0)
			return errmsg("eof reached; %zu bytes remaining", len);
		else if (l > 0) {
			buf += l;
			len -= l;
		} else if (errno == EINTR || errno == EAGAIN)
			continue;
		else
			return sys_errmsg("reading failed; %zu bytes remaining", len);
	}

	return 0;
}

static int load_ubigen_info(struct ubigen_info *ui, uint32_t *psects)
{
	struct ubigen_info_raw ui_raw;
	int err;

	memset(ui, 0, sizeof(*ui));

	err = read_all(args.meta_fd, &ui_raw, sizeof(ui_raw));
	if (err) {
		sys_errmsg("failed to read ubigen info from \"%s\"", args.f_meta);
		return -1;
	}

	ui->leb_size = be32_to_cpu(ui_raw.leb_size);
	ui->peb_size = be32_to_cpu(ui_raw.peb_size);
	ui->min_io_size = be32_to_cpu(ui_raw.min_io_size);
	ui->vid_hdr_offs = be32_to_cpu(ui_raw.vid_hdr_offs);
	ui->data_offs = be32_to_cpu(ui_raw.data_offs);
	ui->ubi_ver = be32_to_cpu(ui_raw.ubi_ver);
	ui->vtbl_size = be32_to_cpu(ui_raw.vtbl_size);
	ui->max_volumes = be32_to_cpu(ui_raw.max_volumes);
	ui->image_seq = be32_to_cpu(ui_raw.image_seq);

	*psects = be32_to_cpu(ui_raw.num_volumes);

	return 0;
}

static int load_ubigen_vol_info(struct ubigen_vol_info *vi, uint32_t sects)
{
	struct ubigen_vol_info_raw vi_raw;
	int err;
	uint32_t i;

	for (i=0; i<sects; i++) {
		memset(&vi[i], 0, sizeof(*vi));

		err = read_all(args.meta_fd, &vi_raw, sizeof(vi_raw));
		if (err) {
			sys_errmsg("failed to read ubigen vol info from \"%s\"", args.f_meta);
			return -1;
		}

		uint32_t name_len = be32_to_cpu(vi_raw.name_len);
		if (name_len > UBI_VOL_NAME_MAX || vi_raw.name[name_len] != 0x00) {
			errmsg("vol name is invalid");
			return -1;
		}

		vi[i].name = strdup((char*)vi_raw.name);
		if (!vi[i].name) {
			errmsg("cannot allocate memory");
			return -1;
		}

		vi[i].id = be32_to_cpu(vi_raw.id);
		vi[i].type = be32_to_cpu(vi_raw.type);
		vi[i].alignment = be32_to_cpu(vi_raw.alignment);
		vi[i].data_pad = be32_to_cpu(vi_raw.data_pad);
		vi[i].usable_leb_size = be32_to_cpu(vi_raw.usable_leb_size);
		vi[i].compat = be32_to_cpu(vi_raw.compat);
		vi[i].used_ebs = be32_to_cpu(vi_raw.used_ebs);
		vi[i].bytes = be64_to_cpu(vi_raw.bytes);
		vi[i].flags = vi_raw.flags;
		vi[i].flash_later = be32_to_cpu(vi_raw.flash_later);
	}

	return 0;
}

struct flash_later_info {
	const char *img;
	struct ubigen_vol_info *vi;
	bool needs_vtable_patch;
	bool vtable_patched;
};

static int check_ech(struct ubi_ec_hdr *hdr)
{
	uint32_t crc;

	/* Check the EC header */
	if (be32_to_cpu(hdr->magic) != UBI_EC_HDR_MAGIC)
		return errmsg("bad UBI magic %#08x, should be %#08x",
			      be32_to_cpu(hdr->magic), UBI_EC_HDR_MAGIC);

	crc = mtd_crc32(UBI_CRC32_INIT, hdr, UBI_EC_HDR_SIZE_CRC);
	if (be32_to_cpu(hdr->hdr_crc) != crc)
		return errmsg("bad CRC %#08x, should be %#08x\n",
			      crc, be32_to_cpu(hdr->hdr_crc));

	return 0;
}

static struct flash_later_info * fli_from_vi_id(struct flash_later_info *fli, size_t flisz, size_t id) {
	size_t i;

	for (i=0; i<flisz; i++) {
		if (fli[i].vi->id == id)
			return &fli[i];
	}

	return NULL;
}

static int patch_vtable(const struct ubigen_info *ui, size_t peb,
	struct flash_later_info *fli, size_t flisz)
{
	char buf[ui->peb_size];
	int err;
	uint32_t crc;
	size_t i;
	struct ubi_ec_hdr *ech = (struct ubi_ec_hdr *)buf;
	struct ubi_vid_hdr *vid_hdr;
	struct ubi_vtbl_record *vtbl;
	struct flash_later_info *flientry;

	if (lseek(args.image_fd, peb * ui->peb_size, SEEK_SET) != peb * ui->peb_size) {
		sys_errmsg("cannot lseek \"%s\" to peb%zu", args.f_image, peb);
		return -1;
	}

	err = read_all(args.image_fd, buf, sizeof(buf));
	if (err) {
		sys_errmsg("failed to read PEB from \"%s\"", args.f_image);
		return -1;
	}

	err = check_ech(ech);
	if (err) {
		errmsg("invalid PEB in \"%s\"", args.f_image);
		return -1;
	}

	vid_hdr = (struct ubi_vid_hdr *)(buf + be32_to_cpu(ech->vid_hdr_offset));
	vtbl = (struct ubi_vtbl_record *)(buf + be32_to_cpu(ech->data_offset));

	if (be32_to_cpu(vid_hdr->magic) != UBI_VID_HDR_MAGIC)
		return errmsg("bad VID magic %#08x, should be %#08x",
			      be32_to_cpu(vid_hdr->magic), UBI_VID_HDR_MAGIC);

	crc = mtd_crc32(UBI_CRC32_INIT, vid_hdr, UBI_VID_HDR_SIZE_CRC);
	if (be32_to_cpu(vid_hdr->hdr_crc) != crc)
		return errmsg("bad CRC %#08x, should be %#08x\n",
			      crc, be32_to_cpu(vid_hdr->hdr_crc));

	for (i = 0; i < ui->max_volumes; i++) {
		uint32_t tmp;

		crc = mtd_crc32(UBI_CRC32_INIT, &vtbl[i],
				     UBI_VTBL_RECORD_SIZE_CRC);
		if (be32_to_cpu(vtbl[i].crc) != crc)
			return errmsg("bad CRC %#08x, should be %#08x\n",
					  crc, be32_to_cpu(vtbl[i].crc));

		flientry = fli_from_vi_id(fli, flisz, i);
		if (!flientry || !flientry->needs_vtable_patch)
			continue;

		tmp = (flientry->vi->bytes + ui->leb_size - 1) / ui->leb_size;
		vtbl[i].reserved_pebs = cpu_to_be32(tmp);

		tmp = mtd_crc32(UBI_CRC32_INIT, &vtbl[i], UBI_VTBL_RECORD_SIZE_CRC);
		vtbl[i].crc = cpu_to_be32(tmp);

		flientry->vtable_patched = true;
	}

	if (lseek(args.image_fd, peb * ui->peb_size, SEEK_SET) != peb * ui->peb_size) {
		sys_errmsg("cannot lseek \"%s\" to peb%zu", args.f_image, peb);
		return -1;
	}

	if (write(args.image_fd, buf, ui->peb_size) != ui->peb_size) {
		sys_errmsg("cannot write %d bytes", ui->peb_size);
		return -1;
	}

	return 0;
}

int main(int argc, char * const argv[])
{
	int err = -1;
	struct ubigen_info ui;
	struct ubigen_vol_info *vi;
	struct flash_later_info *fli;
	off_t image_sz;
	uint32_t sects;
	size_t i;
	size_t num_laters = 0;
	bool needs_vtable_patch = false;

	// TODO: allow statics only because they don't store the size in the vtable
	// neither do dynamics.

	err = parse_opt(argc, argv);
	if (err)
		return -1;

	args.image_fd = open_image_file(&image_sz);
	if (args.image_fd < 0) {
		errmsg("cannot open ubi image");
		return -1;
	}

	err = load_ubigen_info(&ui, &sects);
	if (err) {
		errmsg("cannot load ubigen info");
		goto out;
	}

	vi = calloc(sizeof(struct ubigen_vol_info), sects);
	if (!vi) {
		err = -1;
		errmsg("cannot allocate memory");
		goto out;
	}

	err = load_ubigen_vol_info(vi, sects);
	if (err) {
		errmsg("cannot load ubigen info");
		goto out_free_vi;
	}

	if (image_sz % ui.peb_size) {
		errmsg("ubi image is not a multiple of the peb size");
		err = -1;
		goto out_free_vi;
	}

	/* make sure we got as many images as we need */
	for (i=0; i<sects; i++) {
		if (vi[i].flash_later)
			num_laters++;
	}
	if (argc - optind != num_laters * 2) {
		errmsg("wrong number of positional arguments");
		goto out_free_vi;
	}

	fli = calloc(num_laters, sizeof(*fli));
	if (!fli) {
		err = -1;
		errmsg("cannot allocate memory");
		goto out_free_fli;
	}

	for (i=0; i<(argc-optind) / 2; i++) {
		char *endptr;
		const char *s_volid = argv[optind++];
		const char *s_img = argv[optind++];
		size_t j;

		long _vol_id = strtoul(s_volid, &endptr, 10);
		if (_vol_id == LONG_MIN || _vol_id == LONG_MAX || !(*s_img != '\0' && *endptr == '\0')
			|| _vol_id < 0 || _vol_id > INT_MAX)
		{
			err = -1;
			errmsg("invalid volid: %s", s_volid);
			goto out_free_fli;
		}
		int vol_id = (int)_vol_id;

		fli[i].img = s_img;

		/* check for duplicates */
		if (i) {
			for(j=0; j <= i - 1; j++) {
				if (fli[j].vi->id == vol_id) {
					err = -1;
					errmsg("duplicate volid: %d", vol_id);
					goto out_free_fli;
				}
			}
		}

		/* check if a volume with that id exists and can be flashed */
		for(j=0; j<sects; j++) {
			if (vi[j].id != vol_id)
				continue;

			if (!vi[j].flash_later) {
				err = -1;
				errmsg("volume %d does not have the flash_later flag", vol_id);
				goto out_free_fli;
			}

			fli[i].vi = &vi[j];
		}

		if (fli[i].vi == NULL) {
			err = -1;
			errmsg("no volume with id %d found", vol_id);
			goto out_free_fli;
		}
	}

	/* add volume data to the image */
	for (i=0; i<num_laters; i++) {
		struct stat st;
		int fd;

		if (stat(fli[i].img, &st)) {
			err = -1;
			sys_errmsg("cannot stat \"%s\"", fli[i].img);
			goto out_free_fli;
		}

		if (st.st_size == 0) {
			err = -1;
			errmsg("file \"%s\" is empty", fli[i].img);
			goto out_free_fli;
		}

		if (fli[i].vi->bytes == 0) {
			/* neither image nor size were given to ubinize */
			fli[i].vi->bytes = st.st_size;

			needs_vtable_patch = true;
			fli[i].needs_vtable_patch = true;
		}
		else {
			/* Make sure the image size is not larger than volume size */
			if (st.st_size > fli[i].vi->bytes) {
				err = -1;
				errmsg("size of the image file "
						  "\"%s\" is %lld, which is larger than volume size %lld",
						  fli[i].img, (long long)st.st_size, fli[i].vi->bytes);
				goto out_free_fli;
			}
		}

		if (fli[i].vi->type == UBI_VID_STATIC) {
			fli[i].vi->used_ebs = (st.st_size + fli[i].vi->usable_leb_size - 1) / fli[i].vi->usable_leb_size;
		}

		fd = open(fli[i].img, O_RDONLY);
		if (fd == -1) {
			err = fd;
			sys_errmsg("cannot open \"%s\"", fli[i].img);
			goto out_free_fli;
		}

		verbose(args.verbose, "writing volume %d", fli[i].vi->id);
		verbose(args.verbose, "image file: %s", fli[i].img);

		err = ubigen_write_volume(&ui, fli[i].vi, 0, st.st_size, fd, args.image_fd);
		close(fd);
		if (err) {
			errmsg("cannot write volume %d", fli[i].vi->id);
			goto out_free_fli;
		}
	}

	if (needs_vtable_patch) {
		verbose(args.verbose, "patching vtable");

		err = patch_vtable(&ui, 0, fli, num_laters);
		if (err) {
			errmsg("cannot patch peb0");
			goto out_free_fli;
		}

		err = patch_vtable(&ui, 1, fli, num_laters);
		if (err) {
			errmsg("cannot patch peb1");
			goto out_free_fli;
		}
	}

	for (i=0; i<num_laters; i++) {
		if (fli[i].needs_vtable_patch && !fli[i].vtable_patched) {
			errmsg("volume %d requested a vtable patch but that never happened", fli[i].vi->id);
			goto out_free_fli;
		}
	}

	verbose(args.verbose, "done patching the ubi-image \"%s\"", args.f_image);

	free(vi);
	close(args.image_fd);
	close(args.meta_fd);
	return 0;

out_free_fli:
	free(fli);
out_free_vi:
	free(vi);
out:
	close(args.image_fd);
	close(args.meta_fd);
	return err;
}
