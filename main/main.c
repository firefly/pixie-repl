#include <stdio.h>
#include <string.h>

#include "esp_ds.h"
#include "esp_efuse.h"
#include "esp_random.h"
#include "nvs_flash.h"

#include "keypair.h"
#include "sha2.h"
#include "utils.h"


#define DEVICE_INFO_BLOCK   (EFUSE_BLK3)
#define ATTEST_SLOT         (2)
#define ATTEST_KEY_BLOCK    (EFUSE_BLK_KEY2)
#define ATTEST_HMAC_KEY     (HMAC_KEY2)

// Device Info
// - reg0 (0x 01 00 00 ZZ)
//   - version 0x01
//   - zeros in the remaining register
// - reg1; model number
// - reg2; serial number

int _getHex(char value) {
    if (value >= '0' && value <= '9') { return value - '0'; }
    value &= ~0x20;
    if (value >= 'A' && value <= 'F') { return value - 'A' + 10; }
    return -1;
}

int getHex(char left, char right) {
    int l = _getHex(left), r = _getHex(right);
    if (l < 0 || r < 0) { return -1; }
    return (l << 4) | r;
}

int readNumber(const char* buffer, size_t length) {
    if (length > 7) { return -1; }

    int value = 0;
    for (int i = 0; i < length; i++) {
        if (buffer[i] < '0' || buffer[i] > '9') { return -1; }
        value *= 10;
        value += buffer[i] - '0';
    }

    return value;
}

int readBuffer(uint8_t *dst, char *buffer, size_t length) {
    if (length & 1) { return -1; }

    uint8_t tmp[length];
    for (int i = 0; i < length; i += 2) {
        int value = getHex(buffer[i], buffer[i + 1]);
        if (value < 0) { return -1; }
        tmp[i >> 1] = value;
    }
    memcpy(dst, tmp, length / 2);
    return 0;
}

int stir(uint8_t *dst, size_t dstLen, uint8_t* src, size_t srcLen) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    esp_fill_random(digest, sizeof(digest));

    Sha256Context ctx;
    sha2_initSha256(&ctx);
    sha2_updateSha256(&ctx, digest, sizeof(digest));
    sha2_updateSha256(&ctx, dst, dstLen);
    sha2_updateSha256(&ctx, src, srcLen);
    sha2_finalSha256(&ctx, digest);

    memcpy(dst, digest, dstLen);

    return 0;
}

int dumpKey(int slot) {
    int block;
    switch(slot) {
        case 0:
            block = EFUSE_BLK_KEY0;
            break;
        case 1:
            block = EFUSE_BLK_KEY1;
            break;
        case 2:
            block = EFUSE_BLK_KEY2;
            break;
        case 3:
            block = EFUSE_BLK_KEY3;
            break;
        case 4:
            block = EFUSE_BLK_KEY4;
            break;
        case 5:
            block = EFUSE_BLK_KEY5;
            break;
        default:
            printf("! invalid slot: %d\n", slot);
            return -1;
    }

    bool unused = esp_efuse_key_block_unused(block);
    printf("<efuse.key%d.unused=%d\n", slot, unused);
    if (!unused) {
        bool readProtect = esp_efuse_get_key_dis_read(block);
        bool writeProtect = esp_efuse_get_key_dis_write(block);
        if (readProtect && writeProtect) {
            printf("<efuse.key%d.protected=READ+WRITE\n", slot);
        } else if (readProtect) {
            printf("<efuse.key%d.protected=READ\n", slot);
        } else if (writeProtect) {
            printf("<efuse.key%d.protected=WRITE\n", slot);
        } else {
            printf("<efuse.key%d.protected=NONE\n", slot);
        }
    }

    uint8_t key[32];
    esp_efuse_read_block(block, key, 0, sizeof(key) * 8);
    printf("<efuse.keyHmac%d", slot);
    dumpBuffer("=", key, sizeof(key));

    return unused ? 0: 1;
}

int dumpNvs(nvs_handle_t nvs, char *key, size_t length) {

    uint8_t blob[length];
    size_t olen = length;
    int ret = nvs_get_blob(nvs, key, blob, &olen);
    if (ret) {
       printf("<nvs.%s=[ nil ]\n", key);
    } else {
       printf("<nvs.%s", key);
       dumpBuffer("=", blob, olen);
    }

    return olen;
}
void app_main() {
    int ret = 0;
    printf("? start provisioning\n");

    ret = nvs_flash_init_partition("attest");
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        panic("failed to init attest partition", ret);
    }

    nvs_handle_t nvs;

    ret = nvs_open_from_partition("attest", "secure", NVS_READWRITE, &nvs);
    //if (ret == ESP_ERR_NVS_PART_NOT_FOUND) {
        if (ret) { panic("failed to open attest partition", ret); }
    //}

    // Populated by GEN-KEY
    KeyPair keypair;
    esp_ds_p_data_t params = { 0 };
    esp_ds_data_t *cipherData = NULL;

    uint8_t attest[64];
    memset(attest, 0, sizeof(attest));

    uint8_t iv[16];
    esp_fill_random(iv, sizeof(iv));

    uint8_t key[32];
    esp_fill_random(key, sizeof(key));

    uint8_t entropy[32];
    esp_fill_random(entropy, sizeof(entropy));

    uint32_t modelNumber = 0;
    uint32_t serialNumber = 0;

    /*
    {
        uint8_t value[] = { 0x5f, 0x00, 0x00, 0x00, 0x7d, 0x26, 0x84, 0xe5, 0x39, 0xd1, 0x82, 0x0c, 0x2a, 0x0a, 0xc8, 0x3b, 0xed, 0xcb, 0x83, 0x10, 0xb7, 0x76, 0x53, 0x60, 0xc9, 0x40, 0xc4, 0x48, 0xd9, 0x1e, 0x72, 0xff, 0x86, 0x07, 0xaa, 0x9e, 0x1c, 0xc3, 0xe1, 0x23, 0x12, 0x19, 0xa5, 0xf8, 0x9e, 0xdb, 0x33, 0x5e, 0x5a, 0x90, 0x6c, 0x78, 0x4f, 0x1f, 0xcf, 0x97, 0x95, 0x8d, 0xd0, 0x3d, 0xa8, 0xdc, 0x29, 0x8c, 0x66, 0x67, 0x3d, 0x10, 0xfb, 0x0a, 0x71, 0x8e, 0xd0, 0xf5, 0x31, 0x08, 0x77, 0x16, 0x4c, 0x1a, 0xd1, 0xcb, 0x93, 0x3d, 0x7f, 0x50, 0x16, 0x75, 0x98, 0x0d, 0xc0, 0xed, 0x0d, 0x0b, 0x67, 0x7d, 0xcb, 0x83, 0x39, 0x60, 0xd7, 0xe5, 0x9d, 0x7b, 0x2b, 0xbe, 0xda, 0xc1, 0xbc, 0xc4, 0xd2, 0xa1, 0xb5, 0x9b, 0x63, 0xef, 0xf7, 0x43, 0x27, 0xad, 0x58, 0x15, 0xe7, 0x7d, 0x3f, 0x17, 0x75, 0xa6, 0x78, 0x30, 0xf4, 0x2f, 0xcb, 0x97, 0xbc, 0xe9, 0x69, 0x74, 0x57, 0x94, 0x35, 0xe7, 0xc3, 0x8e, 0xbe, 0x81, 0xdb, 0x9f, 0x39, 0x1a, 0x96, 0xe5, 0xaa, 0xd4, 0x11, 0xde, 0x6c, 0xf6, 0x5c, 0x7c, 0x2f, 0x2d, 0x31, 0x32, 0x1b, 0x21, 0x19, 0xfc, 0xa5, 0x81, 0x5e, 0x85, 0x63, 0xf3, 0xb1, 0xf8, 0x05, 0x09, 0x65, 0x82, 0x18, 0x73, 0xfa, 0xe2, 0x34, 0x45, 0x1f, 0xca, 0x32, 0x66, 0x1f, 0x3b, 0xa5, 0x2b, 0x9c, 0xe0, 0xd9, 0x69, 0x2f, 0x88, 0xab, 0xd1, 0x5d, 0xdd, 0x07, 0x29, 0x80, 0x1d, 0x3e, 0x83, 0x27, 0x2d, 0x03, 0x47, 0xde, 0x12, 0x77, 0x4f, 0xf4, 0x54, 0x70, 0xf3, 0x94, 0x6e, 0x37, 0xc0, 0xa3, 0xc3, 0x16, 0xb4, 0x1f, 0xb1, 0xf1, 0xa0, 0xfc, 0xaa, 0xf6, 0xaf, 0x17, 0x0e, 0xbf, 0x4a, 0x24, 0x06, 0xc2, 0xf4, 0xcf, 0x0e, 0xe8, 0xf1, 0x4a, 0x94, 0x05, 0x34, 0xdf, 0x9c, 0x6e, 0x89, 0x11, 0x42, 0x9a, 0xe8, 0xa3, 0x93, 0x28, 0x03, 0xee, 0x23, 0xd8, 0xc6, 0xbf, 0x04, 0x74, 0x48, 0x26, 0x6b, 0x52, 0x97, 0x91, 0x1d, 0x75, 0x7b, 0x2e, 0xd5, 0xd4, 0x59, 0xda, 0x80, 0x82, 0x4b, 0x55, 0x34, 0x01, 0x1d, 0x0a, 0xaf, 0x09, 0x03, 0x78, 0x45, 0x9a, 0x81, 0x2b, 0xe9, 0xb3, 0x6d, 0x41, 0x39, 0x86, 0x5d, 0x2b, 0x81, 0x30, 0x74, 0xeb, 0x88, 0x8b, 0x97, 0x76, 0x04, 0x7f, 0x55, 0x7d, 0x6c, 0x3e, 0x98, 0xe5, 0x38, 0xf6, 0xa1, 0xc1, 0xe4, 0x5e, 0x44, 0xa1, 0x44, 0x02, 0xae, 0x10, 0xa0, 0x8e, 0x0e, 0x41, 0xb2, 0x9e, 0x94, 0xf6, 0x72, 0xe4, 0x81, 0x43, 0x49, 0xd0, 0x61, 0x7a, 0x14, 0xc6, 0xeb, 0xcf, 0x88, 0x9e, 0xef, 0x75, 0x13, 0xb3, 0xd5, 0xbb, 0xf0, 0x93, 0x45, 0xb5, 0xb5, 0x58, 0x1d, 0x6e, 0x17, 0xcc, 0x94, 0xbd, 0xf5, 0x46, 0x21, 0xa3, 0x5a, 0xc9, 0xd8, 0x33, 0xdb, 0x36, 0xbc, 0x13, 0x68, 0x87, 0x7c, 0xd3, 0xeb, 0x3a, 0xea, 0xef, 0xa9, 0x7b, 0x55, 0x1e, 0x4b, 0x74, 0x2d, 0x27, 0x24, 0xaf, 0x1d, 0x24, 0x1b, 0x5e, 0xc9, 0xe8, 0x81, 0x79, 0x17, 0x25, 0x27, 0xfa, 0x65, 0xfc, 0x4d, 0xa1, 0xc3, 0x3e, 0xf1, 0xb4, 0xf4, 0x7d, 0xb0, 0xf4, 0xaa, 0x5d, 0xf0, 0x33, 0x9b, 0xa7, 0x54, 0x17, 0x32, 0xfa, 0xe9, 0xf7, 0x59, 0x21, 0xdc, 0x22, 0x86, 0x51, 0x37, 0xdc, 0xfb, 0xa3, 0x1e, 0xe1, 0x8e, 0x57, 0x8b, 0xab, 0xa1, 0xc4, 0xdc, 0xe8, 0x15, 0x77, 0xae, 0xcd, 0x7b, 0x95, 0x02, 0x76, 0x3a, 0xfd, 0x83, 0x03, 0x68, 0x8e, 0x8a, 0x14, 0x18, 0x5f, 0xe7, 0xfe, 0x76, 0xb3, 0x11, 0x50, 0x6e, 0x72, 0x82, 0x09, 0xba, 0x34, 0x94, 0x41, 0x53, 0xac, 0x63, 0x96, 0x5f, 0xe1, 0x08, 0x10, 0x3b, 0xe7, 0xaf, 0x38, 0x7b, 0x9f, 0x2f, 0xac, 0xed, 0xc8, 0x99, 0xc2, 0x62, 0x61, 0xdf, 0x70, 0xf4, 0xf9, 0xf0, 0xf8, 0xc4, 0x6e, 0xee, 0x9c, 0x50, 0x90, 0xe1, 0x6c, 0x63, 0xdc, 0x13, 0xb1, 0x84, 0x83, 0x13, 0xfb, 0xbd, 0x99, 0xed, 0xa1, 0xb3, 0xe4, 0x49, 0xd8, 0x15, 0x9b, 0x80, 0x12, 0x4b, 0xc3, 0xe9, 0xd6, 0x11, 0x49, 0x90, 0xe1, 0x82, 0x8a, 0x50, 0x21, 0x56, 0x48, 0x69, 0x47, 0xb9, 0x35, 0x15, 0xf5, 0xcc, 0x08, 0x5e, 0x73, 0x64, 0x51, 0xe4, 0xb4, 0x92, 0xa2, 0x54, 0x03, 0xcd, 0xba, 0xea, 0xac, 0x96, 0xb9, 0x68, 0x19, 0x1e, 0xdb, 0x28, 0x03, 0x4e, 0x7f, 0xa2, 0x1b, 0xb2, 0x45, 0x13, 0x69, 0x61, 0xa6, 0x3e, 0xf2, 0x25, 0x2a, 0x1b, 0x6f, 0x34, 0x3a, 0x1e, 0x5b, 0x54, 0x9f, 0x9e, 0x9d, 0x6e, 0x27, 0x01, 0xe5, 0xc4, 0x46, 0x04, 0xbb, 0x0d, 0x26, 0xa1, 0x1c, 0xc2, 0x6e, 0xa6, 0xbe, 0x6f, 0xda, 0x55, 0xdc, 0x30, 0xed, 0x41, 0x93, 0x7a, 0xf7, 0xfd, 0x29, 0x86, 0x84, 0x49, 0xfa, 0x24, 0x16, 0xd4, 0x56, 0xd6, 0x5e, 0xb7, 0x60, 0x09, 0xf7, 0xad, 0x0b, 0xd7, 0x1b, 0x8f, 0x6c, 0x75, 0xda, 0x12, 0xcd, 0xc9, 0x23, 0x48, 0xeb, 0x70, 0x48, 0x1f, 0xfb, 0x19, 0xbc, 0x07, 0x9b, 0x3b, 0xff, 0x15, 0x7e, 0x75, 0x53, 0xb4, 0xd5, 0x08, 0x07, 0x48, 0x56, 0xc3, 0xa4, 0x1c, 0xef, 0x2f, 0xd9, 0x2c, 0xd2, 0x94, 0x3e, 0x7e, 0x55, 0xf5, 0x96, 0xb1, 0x19, 0x95, 0x23, 0xfb, 0xd1, 0xdc, 0x67, 0x0e, 0x32, 0xa4, 0x31, 0x66, 0xdb, 0xf8, 0x4e, 0x1b, 0x2c, 0x7a, 0xff, 0x42, 0xd7, 0x1a, 0x55, 0x49, 0xed, 0x3b, 0x3a, 0x6c, 0x4f, 0x89, 0x30, 0x70, 0x0f, 0x69, 0x02, 0x81, 0xc6, 0x04, 0xf0, 0x9a, 0xe2, 0x88, 0x51, 0xb9, 0x2d, 0x91, 0x76, 0x36, 0x83, 0xc1, 0x35, 0xa1, 0xa4, 0xbd, 0xdf, 0x19, 0x86, 0xde, 0x20, 0x7c, 0xe6, 0xa0, 0xcb, 0x6b, 0x76, 0xfa, 0x6a, 0x15, 0x80, 0x68, 0x1e, 0x1d, 0x0d, 0x85, 0x76, 0x6a, 0xb8, 0x56, 0x9f, 0x7f, 0x15, 0xbe, 0x2f, 0x3f, 0x47, 0x9e, 0xde, 0xc6, 0xca, 0xf5, 0x88, 0x0c, 0x39, 0x11, 0x95, 0x29, 0xda, 0x59, 0xa0, 0xe2, 0xd1, 0xd7, 0xe2, 0xf4, 0x2a, 0xe3, 0x9d, 0x42, 0xa6, 0xba, 0x58, 0x15, 0x56, 0xc9, 0xfc, 0xea, 0x0c, 0x58, 0x21, 0x1f, 0xf9, 0xe3, 0xea, 0x67, 0x8b, 0xf4, 0xae, 0x6f, 0x48, 0x27, 0xbc, 0x62, 0xf9, 0xca, 0x9e, 0xdd, 0xa4, 0xff, 0xa8, 0xd8, 0x7a, 0x4c, 0x26, 0xe6, 0x1d, 0xb7, 0x5a, 0x2b, 0x66, 0xba, 0x13, 0xbc, 0x07, 0xcc, 0x4a, 0xe2, 0x9c, 0xcf, 0x57, 0x84, 0x84, 0xd2, 0x1f, 0x08, 0x0d, 0x8a, 0x19, 0x1c, 0xe5, 0x3a, 0x3b, 0x9f, 0x1a, 0x67, 0xe4, 0xf0, 0x39, 0x57, 0xd0, 0x7e, 0x27, 0xef, 0x20, 0x43, 0x05, 0x96, 0x11, 0x77, 0xf1, 0x24, 0x57, 0x62, 0xb2, 0x0b, 0xbe, 0x63, 0x8f, 0x05, 0x7d, 0x2c, 0x52, 0xf7, 0x4c, 0x54, 0xfc, 0x9d, 0x5f, 0x4f, 0x90, 0x55, 0xc8, 0x21, 0xe1, 0x6b, 0xdf, 0xad, 0x92, 0x78, 0x06, 0x7d, 0xb8, 0x36, 0x55, 0x8d, 0x84, 0x9d, 0x15, 0x0d, 0x01, 0x37, 0x11, 0xd5, 0xd1, 0xb8, 0x3d, 0x64, 0x08, 0x12, 0xa7, 0xbe, 0x38, 0x55, 0xe7, 0x19, 0x75, 0x7b, 0x36, 0xf8, 0xb2, 0x92, 0xb6, 0x17, 0xbd, 0xde, 0x58, 0x7d, 0xe7, 0x2d, 0x2c, 0x91, 0x74, 0x1f, 0x85, 0x68, 0x99, 0x85, 0x06, 0x53, 0xa4, 0xe8, 0x40, 0x21, 0x1e, 0x5e, 0xca, 0xe0, 0xee, 0x9d, 0x9a, 0x1a, 0x8c, 0x45, 0x31, 0x68, 0xe6, 0x0e, 0xd4, 0x5c, 0x47, 0xc5, 0xe1, 0xc0, 0xf0, 0xa2, 0xf3, 0x45, 0x06, 0x5b, 0x19, 0x9c, 0xde, 0x17, 0x23, 0x63, 0x52, 0x27, 0x31, 0x43, 0xe1, 0x12, 0xc2, 0xa3, 0x43, 0xd5, 0xd6, 0x3d, 0xdd, 0x68, 0x87, 0xe8, 0x64, 0x2c, 0x7f, 0xb3, 0xff, 0x30, 0xf7, 0xf2, 0xc5, 0x97, 0x59, 0x9f, 0x30, 0x8c, 0xe7, 0x8c, 0x0e, 0x89, 0x79, 0x0b, 0x38, 0xe3, 0xe8, 0xb2, 0xf0, 0xc3, 0x75, 0x86, 0xfc, 0x02, 0xed, 0x14, 0xe9, 0xd8, 0xd4, 0x98, 0xe0, 0xef, 0x23, 0xa7, 0x43, 0xd2, 0x98, 0xe2, 0xbd, 0x88, 0xdc, 0xf4, 0x4d, 0xf2, 0x15, 0xa8, 0x39, 0x78, 0x8c, 0x2e, 0xb5, 0xee, 0xec, 0xa0, 0x36, 0xd5, 0x54, 0x78, 0x01, 0x78, 0x42, 0x5b, 0x2e, 0x28, 0xac, 0x22, 0x91, 0x1e, 0xd4, 0x80, 0xd6, 0xdc, 0x9f, 0xd7, 0xc7, 0x9a, 0x27, 0x36, 0xb3, 0x25, 0x86, 0x02, 0x4d, 0xb4, 0xf3, 0xad, 0x35, 0xb8, 0xcd, 0x1c, 0xa3, 0xce, 0x9d, 0xb8, 0x15, 0xde, 0xea, 0xad, 0x3a, 0x03, 0x15, 0x1e, 0x0b, 0xc3, 0xed, 0x16, 0x44, 0x7a, 0xed, 0x76, 0xbe, 0x6a, 0xf5, 0x9c, 0xef, 0xa1, 0x7d, 0x03, 0xa9, 0x5d, 0x31, 0x19, 0xf0, 0x54, 0xe6, 0x90, 0x9e, 0x3e, 0x1b, 0x72, 0xcf, 0x00, 0x55, 0xfe, 0x9f, 0xe7, 0xae, 0x8c, 0xdb, 0xf9, 0x92, 0xe7, 0x76, 0xc4, 0x7c, 0x02, 0x8f, 0x28, 0xbb, 0x26, 0x0b, 0xf5, 0x76, 0xde, 0x65, 0x20, 0xed, 0x0f, 0xbc, 0x35, 0xdc, 0x71, 0x64, 0x93, 0xef, 0x88, 0x4f, 0x68, 0xe1, 0xec, 0x34, 0x3b, 0x1f, 0xb8, 0xdc, 0x7b, 0x71, 0x9a, 0xe4, 0x21, 0x77, 0x60 };
        memcpy((uint8_t*)cipherData, value, sizeof(esp_ds_data_t));
    }
    dumpBuffer("cipherData=", (uint8_t*)cipherData, sizeof(esp_ds_data_t));
    */

    // Begin accepting input from the provisioning service

    int readyCount = 0;

    char buffer[512];

    size_t offset = 0;
    buffer[0] = 0;

    while (1) {
        delay(1);

        // We keep announcing we are ready until we start receiving data
        // in case the provision script missed the first message
        if (readyCount == 0) {
            readyCount++;
            printf("<READY\n");
        } else if (readyCount > 0) {
            readyCount++;
            if (readyCount * portTICK_PERIOD_MS >= 4999) { readyCount = 0; }
        }

        // Not enough space left in the buffer; purge it
        if (sizeof(buffer) - offset - 1 < 1) {
            printf("[WARNING] buffer exceeded length, purging\n");

            // Purge the input buffer
            for (uint32_t i = 0; i < 128; i++) {
                fread(buffer, 1, sizeof(buffer) - 1, stdin);
                delay(1);
            }

            offset = 0;
            buffer[0] = 0;
        }

        // Read anything in the stdin buffer
        size_t length = fread(&buffer[offset], 1, sizeof(buffer) - offset - 1, stdin);

        // No new data
        if (length == 0) { continue; }

        // Got data; no longer announcing we're ready
        readyCount = -1;

        offset += length;
        buffer[offset] = 0;

        // We have received data; stop advertising we're ready

        int equals = -1;

        for (uint32_t i = 0; i < offset; i++) {

            // Null termination
            if (buffer[i] == 0) { break; }

            // Parameter value starts
            if (equals == -1 && buffer[i] == '=') { equals = i; }

            if (buffer[i] != 10) { continue; }

            // New line; we have a new command
            buffer[i] = 0;

            // These only make sense if the prefix ends in an `=`.
            int start = equals + 1;
            int length = i - start;

            if (startsWith(buffer, "ATTEST=", i)) {
                if (length != 16) {
                    printf("! ATTEST bad length\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                size_t nLen = KEY_SIZE / 8;

                uint8_t attestation[
                    1 +               // version
                    7 +               // random nonce
                    (length / 2) +    // provided timestamp
                    4 + 4 +           // model nunmber + serial number
                    nLen +            // pubkey.N
                    sizeof(attest) +  // attest
                    nLen              // signature
                ];
                memset(attestation, 0, sizeof(attestation));

                size_t offset = 0;

                attestation[offset++] = 0x01;

                esp_fill_random(&attestation[offset], 7);
                offset += 7;

                readBuffer(&attestation[offset], &buffer[start], length);
                offset += length / 2;

                uint32_t model = esp_efuse_read_reg(EFUSE_BLK3, 1);
                attestation[offset++] = (model >> 24) & 0xff;
                attestation[offset++] = (model >> 16) & 0xff;
                attestation[offset++] = (model >> 8) & 0xff;
                attestation[offset++] = (model >> 0) & 0xff;

                uint32_t serial = esp_efuse_read_reg(EFUSE_BLK3, 2);
                attestation[offset++] = (serial >> 24) & 0xff;
                attestation[offset++] = (serial >> 16) & 0xff;
                attestation[offset++] = (serial >> 8) & 0xff;
                attestation[offset++] = (serial >> 0) & 0xff;

                size_t olen = 384;
                nvs_get_blob(nvs, "pubkey-n", &attestation[offset], &olen);
                offset += nLen;

                olen = 64;
                nvs_get_blob(nvs, "attest", &attestation[offset], &olen);
                offset += olen;

                Sha256Context ctx;
                sha2_initSha256(&ctx);
                sha2_updateSha256(&ctx, attestation, offset);
                sha2_finalSha256(&ctx, &attestation[offset]);
                reverseBytes(&attestation[offset], 32);

                if (cipherData == NULL) {
                    cipherData = heap_caps_malloc(sizeof(esp_ds_data_t), MALLOC_CAP_DMA);
                    memset(cipherData, 0, sizeof(esp_ds_data_t));

                    olen = sizeof(esp_ds_data_t);
                    nvs_get_blob(nvs, "cipherdata", cipherData, &olen);
                    dumpBuffer("<nvs.cipherdata=", (uint8_t*)cipherData, sizeof(esp_ds_data_t));
                }

                ret = esp_ds_sign(&attestation[offset], cipherData,
                  ATTEST_HMAC_KEY, &attestation[offset]);
                reverseBytes(&attestation[offset], 384);
                dumpBuffer("<attest=", attestation, sizeof(attestation));

                printf("<OK\n");

            } else if (startsWith(buffer, "BURN", i)) {
                ret = esp_efuse_batch_write_begin();
                if (ret) { panic("failed efuse batch begin", ret); }
                ret = esp_efuse_write_reg(EFUSE_BLK3, 0, 0x00000001);
                if (ret) { panic("failed efuse write version", ret); }
                ret = esp_efuse_write_reg(EFUSE_BLK3, 1, modelNumber);
                if (ret) { panic("failed efuse write version", ret); }
                ret = esp_efuse_write_reg(EFUSE_BLK3, 2, serialNumber);
                if (ret) { panic("failed efuse write version", ret); }
                ret = esp_efuse_batch_write_commit();
                if (ret) { panic("failed efuse batch commit", ret); }

                ret = esp_efuse_write_key(ATTEST_KEY_BLOCK,
                  ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, key, 32);
                if (ret) { panic("failed to write key", ret); }
                printf("<OK\n");

            } else if (startsWith(buffer, "DUMP", i)) {
                int inUse = dumpKey(ATTEST_SLOT);
                if (inUse) {
                    printf("! attestation keyHmac block already burned\n");
                }

                uint32_t valueCheck = 0;
                printf("<efuse.blk3=");
                for (int j = 0; j < 8; j++) {
                    uint32_t value = esp_efuse_read_reg(DEVICE_INFO_BLOCK, j);
                    valueCheck |= value;
                    printf("%08lx", value);
                }
                printf(" (length=32 bytes)\n");

                if (valueCheck) {
                    printf("! device info block already burned\n");
                }

                dumpNvs(nvs, "attest", 64);
                dumpNvs(nvs, "pubkey-n", 384);
                dumpNvs(nvs, "cipherdata", 1220);

                printf("<pending.modelNumber=%ld\n", modelNumber);
                printf("<pending.serialNumber=%ld\n", serialNumber);

                if (cipherData) {
                    keypair_dumpMpi("<pending.pubkey.N=", &keypair.N);
                    keypair_dumpMpi("<pending.pubkey.E=", &keypair.E);
                    dumpBuffer("<pending.cipherData=", (uint8_t*)cipherData, sizeof(esp_ds_data_t));
                }

                dumpBuffer("<pending.attest=", attest, sizeof(attest));

                if (inUse || valueCheck) {
                    printf("<ERROR\n");
                } else {
                    printf("<OK\n");
                }

            } else if (startsWith(buffer, "GEN-KEY", i)) {
                if (cipherData != NULL) {
                    printf("! GEN-KEY already called\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                printf("? starting key generation (%d-bit)\n", KEY_SIZE);

                // Create an RSA keypair
                ret = keypair_generate(&keypair, KEY_SIZE, entropy, sizeof(entropy));
                if (ret) { panic("failed to generate RSA key", ret); }
                keypair_dumpMpi("<pubkey.N=", &keypair.N);
                keypair_dumpMpi("<pubkey.E=", &keypair.E);

                // Convert it to the ESP format
                ret = keypair_getParams(&keypair, &params);
                if (ret) { panic("failed to generate RSA key", ret); }
                //dumpBuffer("!PRIVATE<params=", (uint8_t*)&params, sizeof(esp_ds_p_data_t));

                cipherData = heap_caps_malloc(sizeof(esp_ds_data_t), MALLOC_CAP_DMA);
                memset(cipherData, 0, sizeof(esp_ds_data_t));

                // Encrypt it using the hardware
                ret = esp_ds_encrypt_params(cipherData, iv, &params, key);
                if (ret) { panic("failed to encrypt params", ret); }
                dumpBuffer("<cipherData=", (uint8_t*)cipherData, sizeof(esp_ds_data_t));

                printf("<OK\n");

            } else if (startsWith(buffer, "PING", i)) {
                readyCount = 0;
                printf("<OK\n");

            } else if (startsWith(buffer, "SET-ATTEST=", i)) {
                if (length != 128) {
                    printf("! SET-ATTEST invalid length\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }
                ret = readBuffer(attest, &buffer[start], length);

                printf("<OK\n");

            } else if (startsWith(buffer, "SET-MODEL=", i)) {
                ret = readNumber(&buffer[start], length);
                if (ret <= 0) {
                    printf("! SET-SERIAL invalid number\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }
                modelNumber = ret;
                printf("<OK\n");

            } else if (startsWith(buffer, "SET-SERIAL=", i)) {
                ret = readNumber(&buffer[start], length);
                if (ret <= 0) {
                    printf("! SET-SERIAL invalid number\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }
                serialNumber = ret;
                printf("<OK\n");

            } else if (startsWith(buffer, "STIR-ENTROPY=", i)) {
                if (cipherData != NULL) {
                    printf("! GEN-KEY already called\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }
                stir(entropy, sizeof(entropy), (uint8_t*)&buffer[start], length);
                printf("<OK\n");

            } else if (startsWith(buffer, "STIR-IV=", i)) {
                if (cipherData != NULL) {
                    printf("! GEN-KEY already called\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }
                stir(iv, sizeof(iv), (uint8_t*)&buffer[start], length);
                printf("<OK\n");


            } else if (startsWith(buffer, "STIR-KEY=", i)) {
                if (cipherData != NULL) {
                    printf("! GEN-KEY already called\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }
                stir(key, sizeof(key), (uint8_t*)&buffer[start], length);
                printf("<OK\n");

            } else if (startsWith(buffer, "WRITE", i)) {
                if (cipherData == NULL) {
                    printf("! GEN-KEY not called\n");
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                ret = nvs_set_blob(nvs, "attest", attest, sizeof(attest));
                if (ret) { panic("failed to write attest", ret); }

                uint8_t encN[KEY_SIZE / 8];
                ret = mbedtls_mpi_write_binary(&keypair.N, encN, sizeof(encN));
                if (ret) { panic("failed to write encN", ret); }
                ret = nvs_set_blob(nvs, "pubkey-n", encN, sizeof(encN));
                if (ret) { panic("failed to write pubkey-n", ret); }

                ret = nvs_set_blob(nvs, "cipherdata", cipherData, sizeof(esp_ds_data_t) );
                if (ret) { panic("failed to write cipherdata", ret); }

                printf("<OK\n");

            } else {
                printf("! unknown command(%ld): %s (start=%d, length=%d)\n", i, buffer, start, length);
                printf("<ERROR\n");
            }

            offset = 0; buffer[0] = 0;
            break;
        }
    }

    //heap_caps_free(cipherData);

    while (1) {
        printf("<DONE\n");
        delay(10000);
    }
}
