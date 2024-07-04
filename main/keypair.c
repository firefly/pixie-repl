#include <string.h>

#include "keypair.h"

#include "esp_efuse.h"

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"


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

//https://github.com/espressif/esp_secure_cert_mgr/issues/8
static int compute_rinv_mprime(uint32_t keySize, mbedtls_mpi* N, mbedtls_mpi* rinv, uint32_t* mprime) {
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
//    mbedtls_mpi_shift_l(&rr, sizeof(pd_4096_bit_t) * 8 * 2);
    mbedtls_mpi_shift_l(&rr, keySize * 2); // RicMoo!

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
/*
int getKeyBlock(int slot) {
    switch(slot) {
        case 0: return EFUSE_BLK_KEY0;
        case 1: return EFUSE_BLK_KEY1;
        case 2: return EFUSE_BLK_KEY2;
        case 3: return EFUSE_BLK_KEY3;
        case 4: return EFUSE_BLK_KEY4;
    }
    return -1;
}

int getHmacKey(int slot) {
    switch(slot) {
        case 0: return HMAC_KEY0;
        case 1: return HMAC_KEY1;
        case 2: return HMAC_KEY2;
        case 3: return HMAC_KEY3;
        case 4: return HMAC_KEY4;
    }
    return -1;
}
*/
#define KEY_SIZE   (ESP_DS_SIGNATURE_MAX_BIT_LEN)


#define EXPONENT 65537


void keypair_dumpMpi(char *header, mbedtls_mpi* value) {
    char str[2048];
    size_t olen = 0;

    int ret = mbedtls_mpi_write_string(value, 16, str, sizeof(str), &olen);

    if (ret == 0) {
        printf("%s%s (length=%d bits)\n", header, str, (olen - 1) * 4);
    } else {
        printf("%s[FAILED]\n", header);
    }
}

int keypair_getParams(KeyPair *keypair, esp_ds_p_data_t *params) {
    int ret = 0;

    params->length = (keypair->key_size / 32) - 1;

    ret = copy_mpi(keypair->key_size, &keypair->N, params->M);
    if (ret) { return ret; }
    //dumpBuffer("<PARAMS-M=", (uint8_t*)params->M, sizeof(params->M));

    ret = copy_mpi(keypair->key_size, &keypair->D, params->Y);
    if (ret) { return ret; }
    //dumpBuffer("!<PARAMS-Y=", (uint8_t*)params->Y, sizeof(params->Y));

    ret = copy_mpi(keypair->key_size, &keypair->Rb, params->Rb);
    if (ret) { return ret; }

    params->M_prime = keypair->m_prime;

    return ret;
}

// https://github.com/Mbed-TLS/mbedtls/blob/development/programs/pkey/rsa_genkey.c
int keypair_generate(KeyPair *keypair, uint32_t key_size, uint8_t *extraEntropy, size_t extraLength) {
    keypair->key_size = key_size;

    int ret = 0;

    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    /**
      Public:
        N - the RSA modulus
        E - the public exponent
      Private:
        P - the first prime factor of N
        Q - the second prime factor of N
        D - the private exponent
     */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&rsa);
    mbedtls_mpi_init(&keypair->N);
    mbedtls_mpi_init(&keypair->P);
    mbedtls_mpi_init(&keypair->Q);
    mbedtls_mpi_init(&keypair->D);
    mbedtls_mpi_init(&keypair->E);
    mbedtls_mpi_init(&keypair->Rb);

    uint32_t m_prime = 0;


    //printf("[INFO] Seeding random number generator\n");

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
      &entropy, (const unsigned char *) extraEntropy, extraLength)) != 0) {
        printf("! mbedtls_ctr_drbg_seed=%d\n", ret);
        return -1;
    }


    //printf("[INFO] Generating the RSA key (%ld-bit)\n", key_size);

    if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random,
      &ctr_drbg, key_size, EXPONENT)) != 0) {
        printf("! mbedtls_rsa_gen_key=%d\n", ret);
        return -2;
    }


    if (mbedtls_rsa_export(&rsa, &keypair->N, &keypair->P,
      &keypair->Q, &keypair->D, &keypair->E)) {
        printf("! could not export RSA parameters\n");
        return -3;
    }

    //dumpMpi("<RSA-PUBKEY-N=", &keypair->N);
    //dumpMpi("<RSA-PUBKEY-E=", &keypair->E);
    //dumpMpi("!<RSA-PUBKEY-P=", &keypair->P);
    //dumpMpi("!<RSA-PUBKEY-Q=", &keypair->Q);
    //dumpMpi("!<RSA-PUBKEY-D=", &keypair->D);


    ret = compute_rinv_mprime(key_size, &keypair->N, &keypair->Rb, &m_prime);
    if (ret) { return -4; }
    //dumpMpi("!<RSA-PUBKEY-rInv=", &keypair->Rb);

    keypair->m_prime = m_prime;
    //printf("!<M_prime=%lx\n", m_prime);

    mbedtls_rsa_free(&rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}

/*
void keypair_dumpKey(int block) {
    bool unused = esp_efuse_key_block_unused(block);
    bool readProtect = esp_efuse_get_key_dis_read(block);
    bool writeProtect = esp_efuse_get_key_dis_write(block);
    printf("[INFO] BLK=%d, unused=%d, readProtect=%d, writeProtect=%d\n", block, unused, readProtect, writeProtect);

    uint8_t key[32];
    esp_efuse_read_block(block, key, 0, sizeof(key) * 8);
    //dumpBuffer("KEY=", key, sizeof(key));
}
*/
