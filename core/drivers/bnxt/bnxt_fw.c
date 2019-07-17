// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm-include/bnxt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * These macros are the offsets where images reside on sec mem
 */

#define BNXT_BUFFER_SEC_MEM	BCM_DRAM1_SEC_BASE
#define BNXT_FW_SEC_MEM_SRC	BNXT_BUFFER_SEC_MEM
#define BNXT_FW_SEC_MEM_CFG	(BNXT_BUFFER_SEC_MEM + 0x100000)
#define TEMP_MEM		(BNXT_BUFFER_SEC_MEM + 0x200000)

#define BNXT_CRASH_SEC_MEM	BCM_DRAM0_SEC_BASE
#define BNXT_CRASH_LEN		BCM_DRAM0_SEC_SIZE

#define BNXT_CONFIG_NS3_DEST	0x03a00000
#define BNXT_CONFIG_NS3Z_DEST	0x031a0000
#define BNXT_BSPD_CFG_OFFSET	0x51b0
#define BNXT_CONFIG_NS3_BSPD_DEST	(BNXT_CONFIG_NS3_DEST + \
					 BNXT_BSPD_CFG_OFFSET)
#define BNXT_CONFIG_NS3Z_BSPD_DEST	(BNXT_CONFIG_NS3Z_DEST + \
					 BNXT_BSPD_CFG_OFFSET)
#define BNXT_BSPD_CFG_SIZE	0x200

#define BNXT_CRASH_DUMP_INFO_NS3_BASE	0x3a5ff00
#define BNXT_CRASH_DUMP_INFO_NS3Z_BASE	0x31fff00

#define IS_ALIGNED(addr, algn)      (!((addr) & ((algn) - 1)))

#define SZ_1K				0x400

#define BUFFER_PADDING			SZ_1K

#define SRC_ADDR_4BYTES_INC		1

#define EOF				-1

#define BCM_BNXT_FASTBOOT_MASK		0x3u
#define BCM_BNXT_FASTBOOT_TYPE_1	1

#define ADDR_IS_4BYTE_ALIGNED(addr)	IS_ALIGNED(addr, 4)

#define SECTION_IS_LOADABLE(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_FLAGS_IS_LOADABLE)
#define SECTION_IS_ZIPPED(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_FLAGS_IS_ZIPPED)
#define SECTION_IS_TOBE_COPIED(section_ptr) \
	((section_ptr)->flags_src_offset & \
	 (SECTION_FLAGS_IS_EXEC_INSTR | SECTION_FLAGS_IS_DATA))
#define SECTION_IS_TOBE_ZEROED(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_FLAGS_IS_BSS)
#define SECTION_IS_4BYTE_ALIGNED(section_ptr) \
	ADDR_IS_4BYTE_ALIGNED(section_ptr->dest_addr)

#define SECTION_SRC_OFFSET(section_ptr) \
	((section_ptr)->flags_src_offset & SECTION_SRC_OFFFSET_MASK)

#define CRC32_INIT_VAL	(~0)
#define CRC32		crc32i

static const uint32_t crc32tbl[] = {     /* CRC polynomial 0xedb88320 */
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

#define ucrc32(ch, crc) (crc32tbl[(crc ^ (ch)) & 0xff] ^ (crc >> 8))

static inline uint32_t crc32i(uint32_t crc, const char *buf, size_t len)
{
	size_t l;

	for (l = 0; l < len; l++)
		crc = ucrc32(buf[l], crc);
	return (~crc);
}

/* -------------------------------------------------------------------------- */

/* Section header for each image block */
struct ape_section_hdr_s {
	/* destination address that this section is to be copied to */
	uint32_t dest_addr;

	/*
	 * bit[0:23]  source offset address that this image copy from
	 * bit[24:31] flags
	 */
	uint32_t flags_src_offset;
#define SECTION_FLAGS_MASK		0xff000000
	/* session is compressed (zipped) */
#define SECTION_FLAGS_IS_ZIPPED		0x01000000
	/* session contains CRC */
#define SECTION_FLAGS_IS_CRC		0x02000000
	/* session contains executable code (e.g. .text) */
#define SECTION_FLAGS_IS_EXEC_INSTR	0x04000000
	/* session contains initialized data (e.g. .data) */
#define SECTION_FLAGS_IS_DATA		0x08000000
	/* session contains zero initialized data (e.g. .bss) */
#define SECTION_FLAGS_IS_BSS		0x10000000
	/* loadable section mask */
#define SECTION_FLAGS_IS_LOADABLE	(SECTION_FLAGS_IS_EXEC_INSTR | \
					 SECTION_FLAGS_IS_DATA | \
					 SECTION_FLAGS_IS_BSS)
#define SECTION_SRC_OFFFSET_MASK	0x00ffffff

	/* original image length, dword (4byte) length */
	uint32_t org_data_len;

	/* compressed image length (if FlAGS_IS_ZIPPED is set) */
	uint32_t zip_data_len;

	/*
	 * checksum value for this image block, if FLAGS_IS_CRC then
	 * this is CRC checksum; otherwise it is a simple summation
	 */
	uint32_t checksum;
};

struct version_s {
	uint8_t version[16];	/* Null-terminated file version string */
};

struct ver_ext_offset_s {
	uint8_t  version[12];	/* Null-terminated file version string */
	uint32_t ext_hdr_offset;
};

union version_and_offset_u {
	struct version_s	version1;
	struct ver_ext_offset_s	version2;
};

#pragma pack(1)
struct ape_bin_hdr_s {
	/* APE binary header signature; expects APE_BIN_HDR_SIGNATURE */
	uint32_t signature;
#define APE_BIN_HDR_SIGNATURE 0x1a4d4342 /* "BCM"+0x1a */
	/* reserved for ChiMP's use */
	uint8_t flags;
	uint8_t code_type;
	uint8_t device;
	uint8_t media;
	union version_and_offset_u ver;
	uint8_t build;
	uint8_t revision;
	uint8_t minor_ver;
	uint8_t major_ver;
	uint32_t entry_address;
	uint8_t reserved;
	uint8_t header_dword_size;
	uint8_t num_total_sections;
	uint8_t num_loadable_sections;
	uint32_t checksum;
};

#pragma pack()

#define APE_BIN_HDR_SIZE	sizeof(struct ape_bin_hdr_s)
#define APE_SECTION_HDR_SIZE	sizeof(struct ape_section_hdr_s)

/* MAX number of image sections that will be accepted */
#define APE_IMG_MAX_SECTIONS	16

#define APE_IMG_LOAD_DEBUG	0

/* -------------------------------------------------------------------------- */

struct ape_mem_region_s {
	uint32_t c_base;	/* ChiMP's view of address */
	uint32_t h_base;	/* Host's view of address */
	uint32_t size;		/* Size in bytes */
};

/* Memory map into various scratchpad memories */
static struct ape_mem_region_s ape_mem_regions[] = {
	/* CHIMP scratchpad */
	{0x00100000, 0x03100000, 1024 * SZ_1K},

	/* APE scratchpad */
	{0x61000000, 0x03300000, 1152 * SZ_1K},

	/* BONO scratchpad */
	{0x61600000, 0x03a00000, 512 * SZ_1K},

	/* KONG scratchpad */
	{0x61400000, 0x03800000, 512 * SZ_1K},

	/* Keep this last!! */
	{0, 0, 0}
};

/* nitro crash address configuration related macros */
#define BNXT_CRASH_INFO_SIGNATURE 0x20524444
#define BNXT_CRASH_INFO_VALID 0x1
#define MAX_CRASH_ADDR_ITEM 8
struct nitro_crash_addr_item {
	uint32_t info;
	uint32_t size;
	uint32_t addr_hi;
	uint32_t addr_lo;
};
typedef struct nitro_crash_addr_info {
	/* CRC of the struct content, starting at next field. */
	uint32_t crc;
	uint32_t signature;
	uint32_t version;
	struct nitro_crash_addr_item table[MAX_CRASH_ADDR_ITEM];
} t_crash_addr_info;

static uint32_t ape_host_view_addr_get(uint32_t bnxt_view_addr, uint32_t size)
{
	struct ape_mem_region_s *region = ape_mem_regions;
	uint32_t addr = 0;

	for ( ; region->size != 0; region++) {
		if (bnxt_view_addr < region->c_base)
			continue;

		if (bnxt_view_addr >= (region->c_base + region->size))
			continue;

		if (size > (region->c_base + region->size - bnxt_view_addr)) {
			EMSG("ERROR: 0x%x + 0x%x spans memory boundary\n",
			     bnxt_view_addr, size);
			break;
		}

		addr = bnxt_view_addr - region->c_base;
		addr += region->h_base;
		break;
	}

	return addr;
}

static uint32_t ape_hdr_crc_calc(const struct ape_bin_hdr_s *hdr)
{
	uint32_t crc;
	uint32_t dummy = 0;

	/* Compute the CRC up to, but not including, the checksum field */
	crc = CRC32(CRC32_INIT_VAL,
		    (const char *)hdr,
		    (uintptr_t)(&hdr->checksum) - (uintptr_t)hdr);

	/* Compute the CRC with the checksum field zeroed out */
	crc = CRC32(~crc, (const char *)&dummy, sizeof(uint32_t));

	/*
	 * Compute the remainder part of the image header, i.e., the
	 * section headers
	 */
	crc = CRC32(~crc,
		    (const char *)((uintptr_t)hdr + APE_BIN_HDR_SIZE),
		    hdr->num_total_sections * APE_SECTION_HDR_SIZE);

	return crc;
}

static int ape_bin_hdr_valid(const struct ape_bin_hdr_s *hdr)
{
	uint32_t checksum;

	if (!hdr) {
		EMSG("ERROR: no APE image header\n");
		return BNXT_FAILURE;
	}

	if (hdr->signature != APE_BIN_HDR_SIGNATURE) {
		EMSG("ERROR: bad APE image signature\n");
		return BNXT_FAILURE;
	}

	if (hdr->num_total_sections > APE_IMG_MAX_SECTIONS) {
		EMSG("ERROR: too many sections in APE image\n");
		return BNXT_FAILURE;
	}

	checksum = ape_hdr_crc_calc(hdr);
	if (hdr->checksum != checksum) {
		EMSG("ERROR: bad APE header checksum (exp: %x, act: %x)\n",
		       hdr->checksum, checksum);
		return BNXT_FAILURE;
	}

	return BNXT_SUCCESS;
}

static int get_char(uint8_t *inbuf, size_t *inbuf_idx, size_t inbuf_size)
{
	int c;

	if (*inbuf_idx >= inbuf_size)
		return EOF;

	c = inbuf[*inbuf_idx];
	*inbuf_idx += 1;

	return c;
}

static void put_char(uint8_t *outbuf,
		     size_t *outbuf_idx,
		     size_t outbuf_size,
		     uint8_t ch)
{
	if (*outbuf_idx >= outbuf_size)
		return;

	outbuf[*outbuf_idx] = ch;
	*outbuf_idx += 1;
}

static size_t ape_section_uncompress(uint8_t *inbuf,
				     size_t inbuf_size,
				     uint8_t *outbuf,
				     size_t outbuf_size)
{
	int i, j, k, r, c;
	uint32_t flags;
	size_t exp_size = 0, codesize = 0;
	size_t inbuf_idx = 0, outbuf_idx = 0;
#define CODE_8U_MASK		0xff00u	/* 8 code units count mask (8 bits) */
#define CODE_END_MASK		0x100u	/* End of code units mask */
#define CODE_IS_UNENCODED_MASK	1	/* Unencoded code unit mask */
#define CODE_POS_MASK		0xe0u	/* Encoded unit position mask and */
#define CODE_POS_SHIFT		3	/*   bit shift */
#define CODE_LEN_MASK		0x1fu	/* Encoded unit length mask */
#define NS			2048	/* Size of ring buffer */
#define F			34	/* Upper limit for match_length */
#define THRESHOLD		2	/* Encode string into position and
					 *   length, if match_length is
					 *   greater than this.
					 */
	/*
	 * Ring buffer of size NS, with an extra F-1 bytes to facilitate
	 * string comparisons.
	 */
	uint8_t text_buf[NS + F - 1];

	inbuf_idx = 0;
	outbuf_idx = 0;

	for (i = 0; i < NS - F; i++)
		text_buf[i] = ' ';

	r = NS - F;
	flags = 0;

	for (;;) {
		if (((flags >>= 1) & CODE_END_MASK) == 0) {
			c = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (c == EOF)
				break;
			++exp_size;

			if (exp_size > inbuf_size)
				break;

			/* Use higher byte cleverly to count to eight */
			flags = c | CODE_8U_MASK;
		}

		if (flags & CODE_IS_UNENCODED_MASK) {
			/* Not encoded; simply copy the unit */
			c = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (c == EOF)
				break;

			++exp_size;
			if (exp_size > inbuf_size)
				break;

			put_char(outbuf, &outbuf_idx, outbuf_size, c);
			text_buf[r++] = c;
			r &= (NS - 1);
			++codesize;
		} else {
			/* Encoded; get the position and length & duplicate */
			i = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (i == EOF)
				break;

			++exp_size;
			if (exp_size > inbuf_size)
				break;

			j = get_char(inbuf, &inbuf_idx, inbuf_size);
			if (j == EOF)
				break;

			++exp_size;
			if (exp_size > inbuf_size)
				break;

			i |= ((j & CODE_POS_MASK) << CODE_POS_SHIFT);
			j = ((j & CODE_LEN_MASK) + THRESHOLD);

			for (k = 0; k <= j; k++) {
				c = text_buf[((i + k) & (NS - 1))];
				put_char(outbuf, &outbuf_idx, outbuf_size, c);
				text_buf[r++] = c;
				r &= (NS - 1);
				++codesize;
			}
		}
	}

	return codesize;
}

static int ape_section_copy(struct ape_bin_hdr_s *bin_hdr,
			    struct ape_section_hdr_s *section)
{
	uintptr_t src;
	uintptr_t dst;
	uint32_t checksum;
	uint32_t i;
	size_t size;
	uint8_t *section_data;
	size_t work_buff_size = 0;
	void *work_buff = NULL;
	int rc = BNXT_FAILURE;

	if (SECTION_IS_ZIPPED(section)) {
		work_buff_size = section->org_data_len + BUFFER_PADDING;
		work_buff = (void *)phys_to_virt((paddr_t)TEMP_MEM,
						  MEM_AREA_RAM_SEC);
		if (work_buff == NULL) {
			EMSG("ERROR: buffer allocation\n");
			return BNXT_FAILURE;
		}

		section_data = (uint8_t *)((uintptr_t)bin_hdr +
					   SECTION_SRC_OFFSET(section));
		size = ape_section_uncompress(section_data,
					      section->zip_data_len,
					      work_buff,
					      work_buff_size);
		if (size >= work_buff_size) {
			EMSG("ERROR: section uncompress\n");
			goto ape_section_copy_exit;
		}
		if (size < section->org_data_len) {
			EMSG("ERROR: decompressed data size mismatch ");
			EMSG("(exp: %d, act: %ld)\n",
			       section->org_data_len, size);
			goto ape_section_copy_exit;
		}
		src = (uintptr_t)(work_buff);
	} else {
		src = (uintptr_t)bin_hdr + SECTION_SRC_OFFSET(section);
	}

	size = section->org_data_len;

	if (section->flags_src_offset & SECTION_FLAGS_IS_CRC) {
		checksum = CRC32(CRC32_INIT_VAL, (const char *)src, size);
	} else {
		checksum = 0;
		for (i = 0; i < (size / sizeof(uint32_t)); i++)
			checksum += ((uint32_t *)src)[i];
	}
	if (checksum != section->checksum) {
		EMSG("ERROR: checksum mismatch (exp: %x, act: %x)\n",
		       section->checksum, checksum);
		goto ape_section_copy_exit;
	}

	dst = ape_host_view_addr_get(section->dest_addr, size);
	if (dst == 0) {
		EMSG("ERROR: ChiMP-to-host address conversion of %x\n",
		       section->dest_addr);
		goto ape_section_copy_exit;
	}

	/* Copy the section */
	size = size / sizeof(uint32_t);
	while (size) {
		uint32_t copied;

		copied = bnxt_write32_multiple(dst, src, size,
					       SRC_ADDR_4BYTES_INC);
		if (copied < size) {
			dst += copied * sizeof(uint32_t);
			src += copied * sizeof(uint32_t);
			size -= copied;
		} else {
			size = 0;
		}
	}

	rc = BNXT_SUCCESS;

ape_section_copy_exit:
	return rc;
}

static int ape_section_zero(struct ape_section_hdr_s *section)
{
	uint32_t dst;
	uint32_t size = section->org_data_len;
	uint32_t zero = 0;

	if (section->org_data_len == 0)
		return BNXT_SUCCESS;

	/* Convert ChiMP's view of the address in the image to the host view */
	dst = ape_host_view_addr_get(section->dest_addr, size);
	if (dst == 0) {
		EMSG("ERROR: ChiMP-to-host address conversion of %x\n",
		       section->dest_addr);
		return BNXT_FAILURE;
	}

	/*
	 * Zero the section; we simply copy zeros and do not increment the
	 * source buffer address.
	 */
	size = size / sizeof(uint32_t);
	while (size) {
		uint32_t copied;

		copied = bnxt_write32_multiple(dst, (uintptr_t)&zero, size, 0);
		if (copied < size) {
			dst += copied * sizeof(uint32_t);
			size -= copied;
		} else {
			size = 0;
		}
	}

	return BNXT_SUCCESS;
}

static int bnxt_load(vaddr_t img_buffer)
{
	struct ape_bin_hdr_s *bin_hdr;
	struct ape_section_hdr_s *section;
	int sidx;
	int rc = BNXT_SUCCESS;


	bin_hdr = (struct ape_bin_hdr_s *)img_buffer;
	section = (struct ape_section_hdr_s *)(img_buffer +
					       APE_BIN_HDR_SIZE);

	if (ape_bin_hdr_valid(bin_hdr) != BNXT_SUCCESS)
		return BNXT_FAILURE;

	for (sidx = 0; sidx < bin_hdr->num_total_sections; sidx++, section++) {
		if (!SECTION_IS_LOADABLE(section))
			continue;

		if (!ADDR_IS_4BYTE_ALIGNED(section->dest_addr)) {
			EMSG("ERROR: unaligned section dest address 0x%x\n",
			       section->dest_addr);
			rc = BNXT_FAILURE;
			break;
		}

		if (!ADDR_IS_4BYTE_ALIGNED(SECTION_SRC_OFFSET(section))) {
			EMSG("ERROR: unaligned section src offset (0x%x)\n",
			       SECTION_SRC_OFFSET(section));
			rc = BNXT_FAILURE;
			break;
		}

		if (section->org_data_len % sizeof(uint32_t)) {
			EMSG("ERROR: section size (%d) not divisible by 4\n",
			       section->org_data_len);
			rc = BNXT_FAILURE;
			break;
		}

		if (SECTION_IS_TOBE_COPIED(section)) {
			rc = ape_section_copy(bin_hdr, section);
			if (rc != BNXT_SUCCESS)
				break;
		} else if (SECTION_IS_TOBE_ZEROED(section)) {
			rc = ape_section_zero(section);
			if (rc != BNXT_SUCCESS)
				break;
		}
	}

	/* Set up boot mode and take BNXT out of reset */
	if (rc == BNXT_SUCCESS) {
		bnxt_fastboot((bin_hdr->entry_address &
			       ~BCM_BNXT_FASTBOOT_MASK) |
			       BCM_BNXT_FASTBOOT_TYPE_1);
	}

	return rc;
}

static TEE_Result bnxt_crash_config(uintptr_t info_dst,
				    uint32_t crash_area_start,
				    uint32_t crash_len)
{
	struct nitro_crash_addr_item *item;
	uintptr_t dst;
	t_crash_addr_info *info;
	uintptr_t src;
	uint32_t crc;
	size_t size;

	/* first we write into local memory to calculate CRC before
	 * updating into Nitro memory
	 */
	info = (t_crash_addr_info *)malloc(sizeof(t_crash_addr_info));
	if (!info) {
		EMSG("ERROR: buffer allocation\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memset(info, 0, sizeof(t_crash_addr_info));

	info->signature = BNXT_CRASH_INFO_SIGNATURE;
	info->version = 0x01000000 | MAX_CRASH_ADDR_ITEM;

	/* as of now only one item is filled */
	item = &info->table[0];
	item->info = 0;
	item->size = crash_len | BNXT_CRASH_INFO_VALID;
	item->addr_hi = 0;
	item->addr_lo = crash_area_start;

	/* checksum calculation  */
	crc = CRC32(CRC32_INIT_VAL,
		    (const char *)info + sizeof(uint32_t),
		     sizeof(t_crash_addr_info) - sizeof(uint32_t));
	info->crc = crc;

	/* first we write the contents and then set valid bit */
	item->size &= ~BNXT_CRASH_INFO_VALID;

	size = sizeof(t_crash_addr_info) / sizeof(uint32_t);
	dst = info_dst;
	src = (uintptr_t)info;
	while (size) {
		uint32_t copied;

		copied = bnxt_write32_multiple(dst, src, size, 1);
		if (copied < size) {
			dst += copied * sizeof(uint32_t);
			src += copied * sizeof(uint32_t);
			size -= copied;
		} else {
			size = 0;
		}
	}

	/* set the valid bit */
	item->size |= BNXT_CRASH_INFO_VALID;
	dst = info_dst + offsetof(struct nitro_crash_addr_info, table) +
	      offsetof(struct nitro_crash_addr_item, size);
	bnxt_write32_multiple(dst, (uintptr_t)&item->size, 1, 1);

	free(info);

	return TEE_SUCCESS;
}

TEE_Result bnxt_load_fw(int chip_type)
{
	uint32_t size;
	uintptr_t dst;
	uintptr_t src;
	struct bnxt_images_info bnxt_src_image_info;

	if (get_bnxt_images_info(&bnxt_src_image_info, chip_type)
				 != BNXT_SUCCESS)
		return TEE_ERROR_ITEM_NOT_FOUND;

	bnxt_kong_halt();
	bnxt_chimp_halt();

	/* copy the configs */
	src = (uintptr_t) bnxt_src_image_info.bnxt_cfg_vaddr;
	dst = (uintptr_t)BNXT_CONFIG_NS3_DEST;
	size = bnxt_src_image_info.bnxt_cfg_len;
	size = size / sizeof(uint32_t);
	while (size) {
		uint32_t copied;

		copied = bnxt_write32_multiple(dst, src, size,
					       SRC_ADDR_4BYTES_INC);
		if (copied < size) {
			dst += copied * sizeof(uint32_t);
			src += copied * sizeof(uint32_t);
			size -= copied;
		} else {
			size = 0;
		}
	}

	/* copy bspd config */
	src = (uintptr_t) bnxt_src_image_info.bnxt_bspd_cfg_vaddr;
	size = bnxt_src_image_info.bnxt_bspd_cfg_len;
	dst = (uintptr_t)BNXT_CONFIG_NS3_BSPD_DEST;

	size = size / sizeof(uint32_t);
	while (size) {
		uint32_t copied;

		copied = bnxt_write32_multiple(dst, src, size,
					       SRC_ADDR_4BYTES_INC);
		if (copied < size) {
			dst += copied * sizeof(uint32_t);
			src += copied * sizeof(uint32_t);
			size -= copied;
		} else {
			size = 0;
		}
	}

	/* fill the bnxt crash dump info */
	bnxt_crash_config((uintptr_t)BNXT_CRASH_DUMP_INFO_NS3_BASE,
			  BNXT_CRASH_SEC_MEM,
			  BNXT_CRASH_LEN);

	/* load bnxt firmware and fastboot */
	bnxt_load(bnxt_src_image_info.bnxt_fw_vaddr);

	/* wait for handshke */
	bnxt_wait_handshake();

	return TEE_SUCCESS;
}
