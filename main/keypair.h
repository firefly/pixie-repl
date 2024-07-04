#ifndef __KEYPAIR_H__
#define __KEYPAIR_H__

#include <stdint.h>

#include "esp_ds.h"

#include "mbedtls/bignum.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define KEY_SIZE   (ESP_DS_SIGNATURE_MAX_BIT_LEN)

#define EXPONENT 65537


typedef struct KeyPair {
    mbedtls_mpi N, E, P, Q, D, Rb;
    uint32_t key_size;
    uint32_t m_prime;
} KeyPair;


void keypair_dumpMpi(char *header, mbedtls_mpi* value);
int keypair_generate(KeyPair *keypair, uint32_t key_size, uint8_t *entropy, size_t entropyLength);
int keypair_getParams(KeyPair *keypair, esp_ds_p_data_t *params);
void keypair_dumpKey(int slot);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __KEYPAIR_H__ */
