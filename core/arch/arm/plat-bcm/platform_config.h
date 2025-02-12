/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define STACK_ALIGNMENT		64

#define CONSOLE_UART_CLK_IN_HZ	25000000
#define CONSOLE_BAUDRATE	115200

#define CONSOLE_UART_BASE	0x68a10000

#define GICD_BASE		0x63c00000

#define SMBUS0_BASE		0x689b0000
#define SMBUS0_END		(SMBUS0_BASE + 0xB0)

#define SECURE_GPIO_BASE0	0x689d0000
#define ASIU_GPIO_INTR		190
#define GPIO_NUM_START0		0
#define NUM_GPIOS0		256
#define SPI_0_BASE		0x68a80000
#define SPI_0_END		(SPI_0_BASE + 0x1000)
#define SPI_0_CLK_HZ		175000000
#define SPI_0_CS_MUX_PAD	0x68a40490

#define HWRNG_BASE		0x68b20000
#define HWRNG_END		(HWRNG_BASE + 0x28)

#define SOTP_BASE		0x68b50000

/* NO ECC bits are present from ROW_0 to ROW_20, i.e Section 0 to Section 3 */
#define SOTP_NO_ECC_ROWS	20

/* Secure Watch Dog */
#define SEC_WDT_BASE		0x68B30000
#define SEC_WDT_END		(SEC_WDT_BASE + 0x1000)
#define SEC_WDT_CLK_HZ		12500000
#define SEC_WDT_INTR		192

#define BNXT_BASE		0x60800000

#define QSPI_MEM_BASE		0x70000000

/* device memory ranges */
#define BCM_DEVICE0_BASE	GICD_BASE
#define BCM_DEVICE0_SIZE	CORE_MMU_PGDIR_SIZE
#define BCM_DEVICE1_BASE	SMBUS0_BASE
#define BCM_DEVICE1_SIZE	CORE_MMU_PGDIR_SIZE
#define BCM_DEVICE4_BASE	BNXT_BASE
#define BCM_DEVICE4_SIZE	0x800000
#define BCM_DEVICE5_BASE	QSPI_MEM_BASE
#define BCM_DEVICE5_SIZE	0x800000

/* NS DDR ranges */
#define BCM_DRAM0_NS_BASE      0x80000000
#define BCM_DRAM0_NS_SIZE      0xae00000
#define BCM_DRAM1_NS_BASE      0x90000000
#define BCM_DRAM1_NS_SIZE      0x70000000
#define BCM_DRAM2_NS_BASE      0x880400000
#define BCM_DRAM2_NS_SIZE      0x17fbfffff

/* Secure DDR ranges */
#define BCM_DRAM0_SEC_BASE     0x8ae00000
#define BCM_DRAM0_SEC_SIZE     0x2200000

#endif /*PLATFORM_CONFIG_H*/
