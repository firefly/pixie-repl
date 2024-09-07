/*
 * SPDX-FileCopyrightText: 2023-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>
#include "mpi_types.h"
#include "reg_base.h"

//#include "soc/hwcrypto_periph.h"
/* registers for RSA acceleration via Multiple Precision Integer ops */
#define RSA_MEM_M_BLOCK_BASE          ((DR_REG_RSA_BASE)+0x000)
/* RB & Z use the same memory block, depending on phase of operation */
#define RSA_MEM_RB_BLOCK_BASE         ((DR_REG_RSA_BASE)+0x200)
#define RSA_MEM_Z_BLOCK_BASE          ((DR_REG_RSA_BASE)+0x200)
#define RSA_MEM_Y_BLOCK_BASE          ((DR_REG_RSA_BASE)+0x400)
#define RSA_MEM_X_BLOCK_BASE          ((DR_REG_RSA_BASE)+0x600)

/* Configuration registers */
#define RSA_M_DASH_REG                (DR_REG_RSA_BASE + 0x800)
#define RSA_LENGTH_REG                (DR_REG_RSA_BASE + 0x804)
#define RSA_CONSTANT_TIME_REG         (DR_REG_RSA_BASE + 0x820)
#define RSA_SEARCH_ENABLE_REG         (DR_REG_RSA_BASE + 0x824)
#define RSA_SEARCH_POS_REG            (DR_REG_RSA_BASE + 0x828)

/* Initialization registers */
#define RSA_QUERY_CLEAN_REG           (DR_REG_RSA_BASE + 0x808)

/* Calculation start registers */
#define RSA_MODEXP_START_REG          (DR_REG_RSA_BASE + 0x80c)
#define RSA_MOD_MULT_START_REG        (DR_REG_RSA_BASE + 0x810)
#define RSA_MULT_START_REG            (DR_REG_RSA_BASE + 0x814)

/* Interrupt registers */
#define RSA_QUERY_INTERRUPT_REG       (DR_REG_RSA_BASE + 0x818)
#define RSA_CLEAR_INTERRUPT_REG       (DR_REG_RSA_BASE + 0x81C)
#define RSA_INTERRUPT_REG             (DR_REG_RSA_BASE + 0x82C)
#define RSA_DATE_REG                  (DR_REG_RSA_BASE + 0x82C)

//#include "soc/mpi_periph.h"
#define SOC_MPI_MEM_BLOCKS_NUM (4)
extern const uint32_t MPI_BLOCK_BASES[SOC_MPI_MEM_BLOCKS_NUM];

#define SOC_MPI_OPERATIONS_NUM (3)
extern const uint32_t MPI_OPERATIONS_REG[SOC_MPI_OPERATIONS_NUM];

#include "system_reg.h"
#include "system_struct.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Enable the bus clock for MPI peripheral module
 *
 * @param enable true to enable the module, false to disable the module
 */
static inline void mpi_ll_enable_bus_clock(bool enable)
{
    SYSTEM.perip_clk_en1.reg_crypto_rsa_clk_en = enable;
}

/// use a macro to wrap the function, force the caller to use it in a critical section
/// the critical section needs to declare the __DECLARE_RCC_ATOMIC_ENV variable in advance
//#define mpi_ll_enable_bus_clock(...) (void)__DECLARE_RCC_ATOMIC_ENV; mpi_ll_enable_bus_clock(__VA_ARGS__)

/**
 * @brief Reset the MPI peripheral module
 */
static inline void mpi_ll_reset_register(void)
{
    SYSTEM.perip_rst_en1.reg_crypto_rsa_rst = 1;
    SYSTEM.perip_rst_en1.reg_crypto_rsa_rst = 0;

    // Clear reset on digital signature also, otherwise RSA is held in reset
    SYSTEM.perip_rst_en1.reg_crypto_ds_rst = 0;
}

/// use a macro to wrap the function, force the caller to use it in a critical section
/// the critical section needs to declare the __DECLARE_RCC_ATOMIC_ENV variable in advance
//#define mpi_ll_reset_register(...) (void)__DECLARE_RCC_ATOMIC_ENV; mpi_ll_reset_register(__VA_ARGS__)

static inline size_t mpi_ll_calculate_hardware_words(size_t words)
{
    return words;
}

static inline void mpi_ll_power_up(void)
{
    REG_CLR_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);
}

static inline void mpi_ll_power_down(void)
{
    REG_SET_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);
}

static inline void mpi_ll_enable_interrupt(void)
{
    REG_WRITE(RSA_INTERRUPT_REG, 1);
}

static inline void mpi_ll_disable_interrupt(void)
{
    REG_WRITE(RSA_INTERRUPT_REG, 0);
}

static inline void mpi_ll_clear_interrupt(void)
{
    REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}

static inline bool mpi_ll_check_memory_init_complete(void)
{
    return REG_READ(RSA_QUERY_CLEAN_REG) == 0;
}

static inline void mpi_ll_start_op(mpi_op_t op)
{
    REG_WRITE(MPI_OPERATIONS_REG[op], 1);
}

static inline bool mpi_ll_get_int_status(void)
{
    return REG_READ(RSA_QUERY_INTERRUPT_REG) == 0;
}

/* Copy MPI bignum (p) to hardware memory block at 'mem_base'.

   If num_words is higher than the number of words (n) in the bignum then
   these additional words will be zeroed in the memory buffer.
*/
static inline void mpi_ll_write_to_mem_block(mpi_param_t param, size_t offset, const uint32_t* p, size_t n, size_t num_words)
{
    uint32_t mem_base = MPI_BLOCK_BASES[param] + offset;
    uint32_t* pbase = (uint32_t*) mem_base;
    uint32_t copy_words = MIN(num_words, n);

    /* Copy MPI data to memory block registers */
    for (int i = 0; i < copy_words; i++) {
        pbase[i] = p[i];
    }

    /* Zero any remaining memory block data */
    for (int i = copy_words; i < num_words; i++) {
        pbase[i] = 0;
    }
}

static inline void mpi_ll_write_m_prime(uint32_t Mprime)
{
    REG_WRITE(RSA_M_DASH_REG, Mprime);
}

static inline void mpi_ll_write_rinv(uint32_t rinv)
{
    REG_WRITE(MPI_BLOCK_BASES[MPI_PARAM_Z], rinv);
}

static inline void mpi_ll_write_at_offset(mpi_param_t param, int offset, uint32_t value)
{
    uint32_t mem_base = MPI_BLOCK_BASES[param] + offset;
    REG_WRITE(mem_base, value);
}

/* Read MPI bignum (p) back from hardware memory block.

   Reads z_words words from block.
*/
static inline void mpi_ll_read_from_mem_block(uint32_t* p, size_t n, size_t num_words)
{
    uint32_t mem_base = MPI_BLOCK_BASES[MPI_PARAM_Z];
    /* Copy data from memory block registers */
    const size_t REG_WIDTH = sizeof(uint32_t);
    for (size_t i = 0; i < num_words; i++) {
        p[i] = REG_READ(mem_base + (i * REG_WIDTH));
    }
    /* Zero any remaining limbs in the bignum, if the buffer is bigger
       than num_words */
    for (size_t i = num_words; i < n; i++) {
        p[i] = 0;
    }
}

static inline void mpi_ll_set_mode(size_t length)
{
    REG_WRITE(RSA_LENGTH_REG, length);
}

static inline void mpi_ll_disable_constant_time(void)
{
    REG_WRITE(RSA_CONSTANT_TIME_REG, 0);
}

static inline void mpi_ll_enable_constant_time(void)
{
    REG_WRITE(RSA_CONSTANT_TIME_REG, 1);
}

static inline void mpi_ll_disable_search(void)
{
    REG_WRITE(RSA_SEARCH_ENABLE_REG, 0);
}

static inline void mpi_ll_enable_search(void)
{
    REG_WRITE(RSA_SEARCH_ENABLE_REG, 1);
}

static inline void mpi_ll_set_search_position(size_t pos)
{
    REG_WRITE(RSA_SEARCH_POS_REG, pos);
}

#ifdef __cplusplus
}
#endif
