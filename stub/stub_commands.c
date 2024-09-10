/*
 * SPDX-FileCopyrightText: 2019-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <string.h>
#include "stub_commands.h"
#include "stub_flasher.h"
#include "rom_functions.h"
#include "slip.h"
#include "soc_support.h"
#include "stub_io.h"
#include "rom_functions.h"

#include "mbedtls/rsa.h"

static uint8_t entropy[64] = { 0 };

static void _fill_random(uint8_t *data, size_t length) {
    for (int i = 0; i < length; i++) {
        data[i] = READ_REG(WDEV_RND_REG);
    }
}

static void stir(uint8_t *data, size_t length) {
    uint8_t digest[32] = { 0 };
    _fill_random(digest, sizeof(digest));

    ets_sha_enable();

    SHA_CTX ctx;
    ets_sha_init(&ctx, SHA2_256);
    ets_sha_update(&ctx, entropy, sizeof(entropy), false);
    ets_sha_update(&ctx, digest, sizeof(digest), false);
    ets_sha_update(&ctx, data, length, false);
    ets_sha_finish(&ctx, digest);

    ets_sha_disable();

    memcpy(entropy, digest, sizeof(digest));
    _fill_random(&entropy[32], 32);
}

void esp_fill_random(uint8_t *data, size_t length) {
    uint8_t bounce[16];
    for (size_t i = 0; i < length; i++) {
        _fill_random(bounce, sizeof(bounce));
        stir(bounce, sizeof(bounce));

        for (size_t j = 0; j < sizeof(entropy) && i < length; j++) {
            data[i] = entropy[j];
        }
    }
}

static int _mbedtl_fill_random(void* ptr, unsigned char* data, size_t length) {
    esp_fill_random(data, length);
    return 0;
}


/////
// RSA Operations

#define EXPONENT 65537
#define KEY_SIZE 3072


typedef struct KeyPair {
    mbedtls_mpi N, E, P, Q, D, Rb;
    uint32_t key_size;
    uint32_t m_prime;

    uint8_t key[32];

    uint8_t cipherdata[sizeof(ets_ds_data_t)];
} KeyPair;

KeyPair keypair = { 0 };

static int compute_rinv_mprime(uint32_t keySize, mbedtls_mpi* N,
  mbedtls_mpi* rinv, uint32_t* mprime) {

    // python equivalent code:
    //
    //    key_size = private_key.key_size # in bits
    //
    //    # calculate rinv == Rb
    //    rr = 1 << (key_size * 2)
    //    rinv = rr % pub_numbers.n # RSA r inverse operand
    //
    //    # calculate MPrime
    //    a = rsa._modinv(M, 1 << 32)
    //    mprime = (a * -1) & 0xFFFFFFFF # RSA M prime operand

    // rr = 1 << (key_size * 2) # in bits
    mbedtls_mpi rr;
    mbedtls_mpi_init(&rr);
    mbedtls_mpi_lset(&rr, 1);
    mbedtls_mpi_shift_l(&rr, keySize * 2);

    // rinv = rr % rsa.N
    mbedtls_mpi_mod_mpi(rinv, &rr, N);

    // ls32 = 1 << 32
    mbedtls_mpi ls32;
    mbedtls_mpi_init(&ls32);
    mbedtls_mpi_lset(&ls32, 1);
    mbedtls_mpi_shift_l(&ls32, 32);

    // a = rsa._modinv(N, 1 << 32)
    mbedtls_mpi a;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_inv_mod(&a, N, &ls32);

    // a32 = a
    uint32_t a32 = 0;
    mbedtls_mpi_write_binary_le(&a, (uint8_t*) &a32, sizeof(uint32_t));

    // mprime
    *mprime = ((int32_t) a32 * -1) & 0xFFFFFFFF;

    return 0;
}

static void copy_value(uint8_t *dst, uint8_t *src, size_t length) {
    for (int i = 0; i < length; i++) { dst[i] = src[i]; }

    for (int i = 0; i < length / 2; i++) {
        uint8_t tmp = dst[i];
        dst[i] = dst[length - 1 - i];
        dst[length - 1 - i] = tmp;
    }
}

static int copy_mpi(uint32_t keySize, mbedtls_mpi* value, uint32_t *dst) {
    uint8_t tmp[keySize / 8];
    int ret = mbedtls_mpi_write_binary(value, tmp, keySize / 8);
    if (ret) { return ret; }
    copy_value((uint8_t*)dst, tmp, keySize / 8);
    return ret;
}

const char HEX[] = "0123456789abcdef";
void dumpData(const char* header, uint8_t *data, size_t length) {
    SLIP_send_debug("%s (%d bytes):", header, length);

    char hex[65];
    for (size_t i = 0; i < length; i += 32) {
        size_t o = 0;
        for (size_t j = 0; j < 32 && (i + j) < length; j++) {
            hex[o++] = HEX[data[i + j] >> 4];
            hex[o++] = HEX[data[i + j] & 0x0f];
        }
        hex[o++] = 0;
        SLIP_send_debug("    %s", hex);
    }
}

static int genkey() {
    int ret = 0;

    // Generate a new random eFuse key
    esp_fill_random(keypair.key, 32);

    // First time generating a key; initialize the bignums
    if (keypair.key_size == 0) {
        mbedtls_mpi_init(&keypair.N);
        mbedtls_mpi_init(&keypair.P);
        mbedtls_mpi_init(&keypair.Q);
        mbedtls_mpi_init(&keypair.D);
        mbedtls_mpi_init(&keypair.E);
        mbedtls_mpi_init(&keypair.Rb);
    }

    //
    // Generate an RSA keypair
    //

    // Prepare the RSA context
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);

    keypair.key_size = KEY_SIZE;

    uint32_t m_prime = 0;

    // Generate the keypair
    if ((ret = mbedtls_rsa_gen_key(&rsa, _mbedtl_fill_random, NULL,
      KEY_SIZE, EXPONENT))) {
        mbedtls_rsa_free(&rsa);
        return (ret << 4) | 1;;
    }

    // Store the keypair
    if ((ret = mbedtls_rsa_export(&rsa, &keypair.N, &keypair.P, &keypair.Q,
      &keypair.D, &keypair.E))) {
        mbedtls_rsa_free(&rsa);
        return (ret << 4) | 2;;
    }

    // Compute and store the optimization parameters
    if ((ret = compute_rinv_mprime(keypair.key_size, &keypair.N, &keypair.Rb,
      &m_prime))) {
        mbedtls_rsa_free(&rsa);
        return (ret << 4) | 3;;
    }
    keypair.m_prime = m_prime;

    //
    // Encrypt the keypair for use by the DS peripheral
    //

    ets_ds_p_data_t params = { 0 };

    params.length = (keypair.key_size / 32) - 1;

    if ((ret = copy_mpi(keypair.key_size, &keypair.N, params.M))) {
        mbedtls_rsa_free(&rsa);
        return (ret << 4) | 4;;
    }

    if ((ret = copy_mpi(keypair.key_size, &keypair.D, params.Y))) {
        mbedtls_rsa_free(&rsa);
        return (ret << 4) | 5;;
    }

    if ((ret = copy_mpi(keypair.key_size, &keypair.Rb, params.Rb))) {
        mbedtls_rsa_free(&rsa);
        return (ret << 4) | 6;;
    }

    params.M_prime = keypair.m_prime;

    ets_aes_enable();
    ets_sha_enable();

    uint8_t iv[16];
    esp_fill_random(iv, 16);

    if ((ret = ets_ds_encrypt_params((ets_ds_data_t*)keypair.cipherdata, iv, &params,
      keypair.key, ETS_DS_KEY_HMAC))) {
        mbedtls_rsa_free(&rsa);
        return (ret << 4) | 7;;
    }

    ets_sha_disable();
    ets_aes_disable();


    {
        uint8_t pubkeyN[384];
        mbedtls_mpi_write_binary(&keypair.N, pubkeyN, 384);

        size_t length = sizeof(pubkeyN);
        SLIP_send_frame_data('P');
        SLIP_send_frame_data((length >> 8) & 0xff);
        SLIP_send_frame_data(length & 0xff);
        SLIP_send_frame_data_buf(pubkeyN, length);
    }

    {
        size_t length = sizeof(keypair.cipherdata);
        SLIP_send_frame_data('C');
        SLIP_send_frame_data((length >> 8) & 0xff);
        SLIP_send_frame_data(length & 0xff);
        SLIP_send_frame_data_buf((uint8_t*)&keypair.cipherdata, length);
    }

    //dumpData("pubkey.N", pubkeyN, sizeof(pubkeyN));

    //dumpData("CIPHER", (uint8_t*)&keypair.cipherdata,
    //  sizeof(keypair.cipherdata));

    mbedtls_rsa_free(&rsa);
    return ESP_OK;
}


esp_command_error handle_ffx_verify(uint32_t offset, uint32_t length) {

    ets_sha_enable();

    SHA_CTX ctx;
    ets_sha_init(&ctx, SHA2_256);

    uint8_t data[FLASH_SECTOR_SIZE];
    for (uint32_t i = 0; i < length; i += FLASH_SECTOR_SIZE) {
        uint8_t res = SPIRead(offset + i, (uint32_t *)data, FLASH_SECTOR_SIZE);
        if (res != 0) {
            SLIP_send_debug("Hnnn");
            break;
        }

        size_t l = FLASH_SECTOR_SIZE;
        if (length - i < l) { l = length - i; }

        ets_sha_update(&ctx, data, l, false);
    }

    uint8_t digest[32] = { 0 };
    ets_sha_finish(&ctx, digest);

    ets_sha_disable();

    SLIP_send_frame_data_buf(digest, sizeof(digest));
    return ESP_OK;
}

esp_command_error handle_ffx_stir(uint8_t* data, size_t length) {
    stir(data, length);
    return ESP_OK;
}

esp_command_error handle_ffx_genkey(uint32_t *status) {
    int ret = genkey();
    if (ret) {
        SLIP_send_debug("GENKEY FAIL=%d seg=%d", (*status) >> 4, (*status) & 0x0f);
    }
    *status = ret;
    return ret ? FFX_FAILED_KEYGEN : ESP_OK;
}


#if defined(ESP32S3)
esp_rom_spiflash_result_t SPIRead4B(int spi_num, SpiFlashRdMode mode, uint32_t flash_addr, uint8_t* buf, int len)
{
    uint8_t cmd = mode == SPI_FLASH_FASTRD_MODE ? ROM_FLASH_CMD_FSTRD4B_GD :
                  mode == SPI_FLASH_OOUT_MODE ? ROM_FLASH_CMD_FSTRD4B_OOUT_GD :
                  mode == SPI_FLASH_OIO_STR_MODE ? ROM_FLASH_CMD_FSTRD4B_OIOSTR_GD :
                  mode == SPI_FLASH_OIO_DTR_MODE ? ROM_FLASH_CMD_FSTRD4B_OIODTR_GD :
                  mode == SPI_FLASH_SLOWRD_MODE ? ROM_FLASH_CMD_RD4B_GD : ROM_FLASH_CMD_RD4B_GD;
    int dummy = mode == SPI_FLASH_FASTRD_MODE ? 8 :
                  mode == SPI_FLASH_OOUT_MODE ? 8 :
                  mode == SPI_FLASH_OIO_STR_MODE ? 16 :
                  mode == SPI_FLASH_OIO_DTR_MODE ? 32 :
                  mode == SPI_FLASH_SLOWRD_MODE ? 0 : 0;
    uint8_t cmd_len = 8;

    esp_rom_opiflash_wait_idle(spi_num, SPI_FLASH_FASTRD_MODE);
    while (len > 0) {
        int rd_length;
        if (len > 16 ) {    //16 = read_sub_len
            rd_length = 16;
        } else {
            rd_length = len;
        }
        esp_rom_opiflash_exec_cmd(spi_num, mode,
                                cmd, cmd_len,
                                flash_addr, 32,
                                dummy,
                                NULL, 0,
                                buf, 8 * rd_length,
                                ESP_ROM_OPIFLASH_SEL_CS0,
                                false);

        len -= rd_length;
        buf += rd_length;
        flash_addr += rd_length;
    }
    return ESP_ROM_SPIFLASH_RESULT_OK;
}
#endif // ESP32S3

int handle_flash_erase(uint32_t addr, uint32_t len) {
  if (addr % FLASH_SECTOR_SIZE != 0) return 0x32;
  if (len % FLASH_SECTOR_SIZE != 0) return 0x33;
  if (SPIUnlock() != 0) return 0x34;

  while (len > 0 && (addr % FLASH_BLOCK_SIZE != 0)) {
    #if defined(ESP32S3)
      if (addr > 0x00ffffff) {
        if (esp_rom_opiflash_erase_sector(1, addr / FLASH_SECTOR_SIZE, SPI_FLASH_FASTRD_MODE) != 0) return 0x35; }
      else
        if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
    #else
      if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x35;
    #endif // ESP32S3
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  while (len > FLASH_BLOCK_SIZE) {
    #if defined(ESP32S3)
      if (addr > 0x00ffffff) {
        if (esp_rom_opiflash_erase_block_64k(1, addr / FLASH_BLOCK_SIZE, SPI_FLASH_FASTRD_MODE) != 0) return 0x36; }
      else
        if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    #else
      if (SPIEraseBlock(addr / FLASH_BLOCK_SIZE) != 0) return 0x36;
    #endif // ESP32S3
    len -= FLASH_BLOCK_SIZE;
    addr += FLASH_BLOCK_SIZE;
  }

  while (len > 0) {
    #if defined(ESP32S3)
      if (addr > 0x00ffffff) {
        if (esp_rom_opiflash_erase_sector(1, addr / FLASH_SECTOR_SIZE, SPI_FLASH_FASTRD_MODE) != 0) return 0x37; }
      else
        if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
    #else
      if (SPIEraseSector(addr / FLASH_SECTOR_SIZE) != 0) return 0x37;
    #endif // ESP32S3
    len -= FLASH_SECTOR_SIZE;
    addr += FLASH_SECTOR_SIZE;
  }

  return 0;
}

void handle_flash_read(uint32_t addr, uint32_t len, uint32_t block_size,
                  uint32_t max_in_flight) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  struct MD5Context ctx;
  uint32_t num_sent = 0, num_acked = 0;
  uint8_t res = 0;

  /* This is one routine where we still do synchronous I/O */
  stub_rx_async_enable(false);

  if (block_size > sizeof(buf)) {
    return;
  }
  MD5Init(&ctx);
  while (num_acked < len && num_acked <= num_sent) {
    while (num_sent < len && num_sent - num_acked < max_in_flight) {
      uint32_t n = len - num_sent;
      if (n > block_size) n = block_size;
      #if defined(ESP32S3)
        if (addr + len > 0x00ffffff)
          res = SPIRead4B(1, SPI_FLASH_FASTRD_MODE, addr, buf, n);
        else
          res = SPIRead(addr, (uint32_t *)buf, n);
      #else
        res = SPIRead(addr, (uint32_t *)buf, n);
      #endif // ESP32S3
      if (res != 0) {
        break;
      }
      SLIP_send(buf, n);
      MD5Update(&ctx, buf, n);
      addr += n;
      num_sent += n;
    }
    int r = SLIP_recv(&num_acked, sizeof(num_acked));
    if (r != 4) {
      break;
    }
  }
  MD5Final(digest, &ctx);
  SLIP_send(digest, sizeof(digest));

  /* Go back to async RX */
  stub_rx_async_enable(true);
}

int handle_flash_get_md5sum(uint32_t addr, uint32_t len) {
  uint8_t buf[FLASH_SECTOR_SIZE];
  uint8_t digest[16];
  uint8_t res = 0;
  struct MD5Context ctx;
  MD5Init(&ctx);
  while (len > 0) {
    uint32_t n = len;
    if (n > FLASH_SECTOR_SIZE) {
      n = FLASH_SECTOR_SIZE;
    }
    #if defined(ESP32S3)
      if (addr + len > 0x00ffffff)
        res = SPIRead4B(1, SPI_FLASH_FASTRD_MODE, addr, buf, n);
      else
        res = SPIRead(addr, (uint32_t *)buf, n);
    #else
      res = SPIRead(addr, (uint32_t *)buf, n);
    #endif // ESP32S3
    if (res != 0) {
      return 0x63;
    }
    MD5Update(&ctx, buf, n);
    addr += n;
    len -= n;
  }
  MD5Final(digest, &ctx);
  /* ESP32 ROM sends as hex, but we just send raw bytes - esptool.py can handle either. */
  SLIP_send_frame_data_buf(digest, sizeof(digest));
  return 0;
}

esp_command_error handle_spi_set_params(uint32_t *args, int *status)
{
  *status = SPIParamCfg(args[0], args[1], args[2], args[3], args[4], args[5]);
  return *status ? ESP_FAILED_SPI_OP : ESP_OK;
}

esp_command_error handle_spi_attach(uint32_t hspi_config_arg)
{
#ifdef ESP8266
        /* ESP8266 doesn't yet support SPI flash on HSPI, but could:
         see https://github.com/themadinventor/esptool/issues/98 */
        SelectSpiFunction();
#else
        /* spi_flash_attach calls SelectSpiFunction() and another
           function to initialise SPI flash interface.

           Second argument 'legacy' mode is not currently supported.
        */
        spi_flash_attach(hspi_config_arg, 0);
#endif
        return ESP_OK; /* neither function/attach command takes an arg */
}

static uint32_t *mem_offset;
static uint32_t mem_remaining;

esp_command_error handle_mem_begin(uint32_t size, uint32_t offset)
{
    mem_offset = (uint32_t *)offset;
    mem_remaining = size;
    return ESP_OK;
}

esp_command_error handle_mem_data(void *data, uint32_t length)
{
    uint32_t *data_words = (uint32_t *)data;
    if (mem_offset == NULL && length > 0) {
        return ESP_NOT_IN_FLASH_MODE;
    }
    if (length > mem_remaining) {
        return ESP_TOO_MUCH_DATA;
    }
    if (length % 4 != 0) {
        return ESP_BAD_DATA_LEN;
    }

    for(int i = 0; i < length; i+= 4) {
        *mem_offset++ = *data_words++;
        mem_remaining -= 4;
    }
    return ESP_OK;
}

esp_command_error handle_mem_finish()
{
    esp_command_error res = mem_remaining > 0 ? ESP_NOT_ENOUGH_DATA : ESP_OK;
    mem_remaining = 0;
    mem_offset = NULL;
    return res;
}

esp_command_error handle_write_reg(const write_reg_args_t *cmds, uint32_t num_commands)
{
    for (uint32_t i = 0; i < num_commands; i++) {
        const write_reg_args_t *cmd = &cmds[i];
        ets_delay_us(cmd->delay_us);
        uint32_t v = cmd->value & cmd->mask;
        if (cmd->mask != UINT32_MAX) {
            v |= READ_REG(cmd->addr) & ~cmd->mask;
        }
        WRITE_REG(cmd->addr, v);
    }
    return ESP_OK;
}

#if ESP32S2_OR_LATER && !ESP32H2BETA2 // TODO: ESPTOOL-350
esp_command_error handle_get_security_info()
{
  uint8_t buf[SECURITY_INFO_BYTES];
  esp_command_error ret;

  ret = GetSecurityInfoProc(NULL, NULL, buf);
  if (ret == ESP_OK)
    SLIP_send_frame_data_buf(buf, sizeof(buf));
  return ret;
}
#endif // ESP32S2_OR_LATER
