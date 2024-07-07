#include <stdio.h>
#include <string.h>

#include "esp_ds.h"
#include "esp_efuse.h"
#include "esp_random.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "keypair.h"
#include "sha2.h"
#include "utils.h"

#include "firefly-display.h"
#include "firefly-scene.h"

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

void provision_repl() {
    int ret = 0;
    printf("? start provisioning\n");

    ret = nvs_flash_init_partition("attest");
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        panic("failed to init attest partition", ret);
    }

    nvs_handle_t nvs;

    ret = nvs_open_from_partition("attest", "secure", NVS_READWRITE, &nvs);
    if (ret) { panic("failed to open attest partition", ret); }


    uint8_t pubkeyN[384] = { 0 };
    bool hasPubKey = false;

    uint8_t cipherdata[sizeof(esp_ds_data_t)] = { 0 };
    bool hasCipherdata = false;

    uint8_t attest[64] = { 0 };
    bool hasAttest = false;

    uint8_t iv[16];
    esp_fill_random(iv, sizeof(iv));

    uint8_t key[32];
    esp_fill_random(key, sizeof(key));

    uint8_t entropy[32];
    esp_fill_random(entropy, sizeof(entropy));

    uint32_t modelNumber = 0;
    uint32_t serialNumber = 0;

    uint32_t randMarker = esp_random();


    // Begin accepting input from the provisioning service

    int readyCount = 0;

    char buffer[4096];

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
            printf("! buffer exceeded length, purging\n");
            printf("<ERROR\n");

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
                bool error = false;

                if (length != 16) {
                    printf("! ATTEST bad parameter length (%d != 16)\n", length);
                    error = true;
                }

                if (modelNumber == 0) {
                    printf("! ATTEST no model number present (use SET-MODEL or LOAD-EFUSE)\n");
                    error = true;
                }

                if (serialNumber == 0) {
                    printf("! ATTEST no serial number present (use SET-MODEL or LOAD-EFUSE)\n");
                    error = true;
                }

                if (!hasPubKey) {
                    printf("! ATTEST no pubkey present (use GEN-KEY, LOAD-NVS or SET-PUBKEYN)\n");
                    error = true;
                }

                if (!hasCipherdata) {
                    printf("! ATTEST no cipherdata present (use GEN-KEY, LOAD-NVS or SET-CIPHERDATA)\n");
                    error = true;
                }

                if (!hasAttest) {
                    printf("! ATTEST no attest present (use SET-ATTEST or LOAD-NVS)\n");
                    error = true;
                }

                if (error) {
                    printf("<ERROR\n");

                    offset = 0;
                    buffer[0] = 0;
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

                ret = readBuffer(&attestation[offset], &buffer[start], length);
                if (ret < 0) { panic("! ATTEST invalid data", ret); }
                offset += length / 2;

                //uint32_t model = esp_efuse_read_reg(EFUSE_BLK3, 1);
                attestation[offset++] = (modelNumber >> 24) & 0xff;
                attestation[offset++] = (modelNumber >> 16) & 0xff;
                attestation[offset++] = (modelNumber >> 8) & 0xff;
                attestation[offset++] = (modelNumber >> 0) & 0xff;

                //uint32_t serial = esp_efuse_read_reg(EFUSE_BLK3, 2);
                attestation[offset++] = (serialNumber >> 24) & 0xff;
                attestation[offset++] = (serialNumber >> 16) & 0xff;
                attestation[offset++] = (serialNumber >> 8) & 0xff;
                attestation[offset++] = (serialNumber >> 0) & 0xff;


                memcpy(&attestation[offset], pubkeyN, nLen);
                offset += nLen;

                //size_t olen = 384;
                //nvs_get_blob(nvs, "pubkey-n", &attestation[offset], &olen);
                //offset += nLen;

                memcpy(&attestation[offset], attest, 64);
                offset += 64;

                //olen = 64;
                //nvs_get_blob(nvs, "attest", &attestation[offset], &olen);
                //offset += olen;

                Sha256Context ctx;
                sha2_initSha256(&ctx);
                sha2_updateSha256(&ctx, attestation, offset);
                sha2_finalSha256(&ctx, &attestation[offset]);
                reverseBytes(&attestation[offset], 32);

                esp_ds_data_t *encParams = heap_caps_malloc(sizeof(esp_ds_data_t), MALLOC_CAP_DMA);
                memcpy((uint8_t*)encParams, cipherdata, sizeof(esp_ds_data_t));

                ret = esp_ds_sign(&attestation[offset], encParams,
                  ATTEST_HMAC_KEY, &attestation[offset]);
                reverseBytes(&attestation[offset], nLen);
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
                ret = esp_efuse_write_reg(EFUSE_BLK3, 4, randMarker);
                if (ret) { panic("failed efuse write version", ret); }
                ret = esp_efuse_batch_write_commit();
                if (ret) { panic("failed efuse batch commit", ret); }

                ret = esp_efuse_write_key(ATTEST_KEY_BLOCK,
                  ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, key, 32);
                if (ret) { panic("failed to write key", ret); }
                printf("<OK\n");

            } else if (startsWith(buffer, "DUMP", i)) {
                int inUse = dumpKey(ATTEST_SLOT);
                printf("<efuse.key.burned=%d\n", inUse);

                uint32_t valueCheck = 0;
                printf("<efuse.blk3=");
                for (int j = 0; j < 8; j++) {
                    uint32_t value = esp_efuse_read_reg(DEVICE_INFO_BLOCK, j);
                    valueCheck |= value;
                    printf("%08lx", value);
                }
                printf(" (length=32 bytes)\n");

                printf("<efuse.blk3.burned=%d\n", valueCheck != 0);
                if (valueCheck) {
                    printf("<efuse.model=%ld\n", esp_efuse_read_reg(DEVICE_INFO_BLOCK, 1));
                    printf("<efuse.serial=%ld\n", esp_efuse_read_reg(DEVICE_INFO_BLOCK, 2));
                    printf("<efuse.randMarker=%lu\n", esp_efuse_read_reg(DEVICE_INFO_BLOCK, 4));
                }

                dumpNvs(nvs, "attest", 64);
                dumpNvs(nvs, "pubkey-n", 384);
                dumpNvs(nvs, "cipherdata", sizeof(esp_ds_data_t));

                if (modelNumber) {
                    printf("<pending.modelNumber=%ld\n", modelNumber);
                }

                if (serialNumber) {
                    printf("<pending.serialNumber=%ld\n", serialNumber);
                }

                printf("<pending.randMarker=%lu\n", randMarker);

                if (hasPubKey) {
                    dumpBuffer("<pending.pubkey.N=", pubkeyN, sizeof(pubkeyN));
                }

                if (hasCipherdata) {
                    dumpBuffer("<pending.cipherdata=", (uint8_t*)cipherdata, sizeof(esp_ds_data_t));
                }

                if (hasAttest) {
                    dumpBuffer("<pending.attest=", attest, sizeof(attest));
                }

                printf("<ready=%d\n", (inUse || valueCheck));

                printf("<OK\n");

            } else if (startsWith(buffer, "GEN-KEY", i)) {
                if (hasCipherdata) {
                    printf("? GEN-KEY resetting cipherdata\n");
                    hasCipherdata = false;
                }

                if (hasPubKey) {
                    printf("? GEN-KEY resetting key\n");
                    hasPubKey = false;
                }

                printf("? starting key generation (%d-bit)\n", KEY_SIZE);

                // Create an RSA keypair
                KeyPair keypair = { 0 };
                ret = keypair_generate(&keypair, KEY_SIZE, entropy, sizeof(entropy));
                if (ret) { panic("failed to generate RSA key", ret); }
                keypair_dumpMpi("<pubkey.N=", &keypair.N);
                mbedtls_mpi_write_binary(&keypair.N, pubkeyN, 384);

                // Convert it to the ESP format
                esp_ds_p_data_t params = { 0 };
                ret = keypair_getParams(&keypair, &params);
                if (ret) { panic("failed to generate RSA key", ret); }
                //dumpBuffer("!PRIVATE<params=", (uint8_t*)&params, sizeof(esp_ds_p_data_t));

                esp_ds_data_t *encParams = heap_caps_malloc(sizeof(esp_ds_data_t), MALLOC_CAP_DMA);
                memset(encParams, 0, sizeof(esp_ds_data_t));

                // Encrypt it using the hardware
                ret = esp_ds_encrypt_params(encParams, iv, &params, key);
                if (ret) { panic("failed to encrypt params", ret); }
                memcpy(cipherdata, encParams, sizeof(esp_ds_data_t));
                dumpBuffer("<cipherdata=", cipherdata, sizeof(cipherdata));

                hasPubKey = true;
                hasCipherdata = true;

                printf("<OK\n");

            } else if (startsWith(buffer, "LOAD-EFUSE", i)) {
                modelNumber = esp_efuse_read_reg(EFUSE_BLK3, 1);
                serialNumber = esp_efuse_read_reg(EFUSE_BLK3, 2);
                printf("<OK\n");

            } else if (startsWith(buffer, "LOAD-NVS", i)) {

                {
                    size_t olen = 64;
                    uint8_t blob[olen];
                    int ret = nvs_get_blob(nvs, "attest", blob, &olen);
                    if (!ret && olen == 64) {
                        memcpy(attest, blob, olen);
                        dumpBuffer("<nvs.attest=", attest, olen);
                        hasAttest = true;
                    }
                }

                {
                    size_t olen = 384;
                    uint8_t blob[olen];
                    ret = nvs_get_blob(nvs, "pubkey-n", blob, &olen);
                    if (!ret && olen == 384) {
                        memcpy(pubkeyN, blob, olen);
                        dumpBuffer("<nvs.pubkey.N=", pubkeyN, olen);
                        hasPubKey = true;
                    }
                }

                {
                    size_t olen = sizeof(esp_ds_data_t);
                    uint8_t blob[olen];
                    ret = nvs_get_blob(nvs, "cipherdata", blob, &olen);
                    if (!ret && olen == sizeof(esp_ds_data_t)) {
                        memcpy(cipherdata, blob, olen);
                        dumpBuffer("<nvs.cipherdata=", cipherdata, olen);
                        hasCipherdata = true;
                    }
                }

                printf("<OK\n");

            } else if (startsWith(buffer, "NOP", i)) {
                printf("<OK\n");

            } else if (startsWith(buffer, "PING", i)) {
                readyCount = 0;
                printf("\n<OK\n");
                // @TODO: PING often gets clobbered so we need the newline;
                //        we should proably do this for everything

            } else if (startsWith(buffer, "RESET", i)) {
                printf("<OK\n");

                delay(1000);
                esp_restart();
                while (1) { delay(1000); }

            } else if (startsWith(buffer, "SET-ATTEST=", i)) {
                if (length != 2 * sizeof(attest)) {
                    printf("! SET-ATTEST invalid length %d != %d\n", length, 2 * sizeof(attest));
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                ret = readBuffer(attest, &buffer[start], length);
                if (ret < 0) { panic("! SET-ATTEST invalid data", ret); }

                hasAttest = true;

                printf("<OK\n");

            } else if (startsWith(buffer, "SET-CIPHERDATA=", i)) {
                if (length != 2 * sizeof(cipherdata)) {
                    printf("! SET-CIPHERDATA bad parameter length (%d != %d)\n",
                      length, 2 * sizeof(cipherdata));
                    printf("? FOO=%s\n", &buffer[start]);
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                ret = readBuffer(cipherdata, &buffer[start], length);
                if (ret < 0) { panic("! SET-CIPHERDATA invalid data", ret); }

                hasCipherdata = true;

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

            } else if (startsWith(buffer, "SET-PUBKEYN=", i)) {
                if (length != 2 * sizeof(pubkeyN)) {
                    printf("! SET-PUBKEYN bad parameter length (%d != %d)\n",
                      length, 2 * sizeof(pubkeyN));
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                ret = readBuffer(pubkeyN, &buffer[start], length);
                if (ret < 0) { panic("! SET-PUBKEYN invalid data", ret); }

                hasPubKey = true;

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
                stir(entropy, sizeof(entropy), (uint8_t*)&buffer[start], length);
                printf("<OK\n");

            } else if (startsWith(buffer, "STIR-IV=", i)) {
                stir(iv, sizeof(iv), (uint8_t*)&buffer[start], length);
                printf("<OK\n");


            } else if (startsWith(buffer, "STIR-KEY=", i)) {
                stir(key, sizeof(key), (uint8_t*)&buffer[start], length);
                printf("<OK\n");

            } else if (startsWith(buffer, "VERSION", i)) {
                printf("<version=1\n");
                printf("<OK\n");

            } else if (startsWith(buffer, "WRITE", i)) {
                bool error = false;

                if (!hasAttest) {
                    printf("! WRITE missing attest (use LOAD-NVS or SET-ATTEST)\n");
                    error = true;
                }

                if (!hasCipherdata) {
                    printf("! WRITE missing cipherdata (use LOAD-NVS or SET-CIPHERDATA)\n");
                    error = true;
                }

                if (!hasPubKey) {
                    printf("! WRITE missing key (use GEN-KEY or SET-PUBKEYN)\n");
                    error = true;
                }

                if (error) {
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                ret = nvs_set_blob(nvs, "attest", attest, sizeof(attest));
                if (ret) { panic("failed to write attest", ret); }

                ret = nvs_set_blob(nvs, "pubkey-n", pubkeyN, sizeof(pubkeyN));
                if (ret) { panic("failed to write pubkey-n", ret); }

                ret = nvs_set_blob(nvs, "cipherdata", cipherdata, sizeof(esp_ds_data_t) );
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
}

#define DISPLAY_BUS        (FfxDisplaySpiBus2)
#define PIN_DISPLAY_DC     (4)
#define PIN_DISPLAY_RESET  (5)

void render_scene(uint8_t *fragment, uint32_t y0, void *context) {
    FfxScene scene = context;
    ffx_scene_render(scene, fragment, y0, FfxDisplayFragmentHeight);
}

void splash_screen() {
    int ret = nvs_flash_init_partition("attest");
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        panic("failed to init attest partition", ret);
    }

    nvs_handle_t nvs;
    ret = nvs_open_from_partition("attest", "secure", NVS_READONLY, &nvs);
    if (ret) { panic("failed to open attest partition", ret); }

    FfxScene scene = ffx_scene_init(128);
    FfxNode root = ffx_scene_root(scene);

    FfxNode fill = ffx_scene_createFill(scene, ffx_color_rgb(0, 0, 0, 0x20));
    ffx_scene_appendChild(root, fill);

    FfxDisplayContext display = ffx_display_init(DISPLAY_BUS, PIN_DISPLAY_DC,
      PIN_DISPLAY_RESET, FfxDisplayRotationRibbonRight, render_scene, scene);
    printf("[app] init display\n");

    char strModel[20];
    char strSerial[20];
    char strVerify[20];

   {
        uint32_t model = esp_efuse_read_reg(EFUSE_BLK3, 1);
        if ((model >> 8) == 1) {
            snprintf(strModel, sizeof(strModel), "Pixie (rev.%ld)", model & 0xff);
        } else {
            snprintf(strModel, sizeof(strModel), "Model: unknown (%ld)", model);
        }
        FfxNode text = ffx_scene_createText(scene, strModel, strlen(strModel));
        ffx_scene_appendChild(root, text);
        FfxPoint *point = ffx_scene_nodePosition(text);
        point->x = 10;
        point->y = 120;
    }

    {
        uint32_t serial = esp_efuse_read_reg(EFUSE_BLK3, 2);
        snprintf(strSerial, sizeof(strSerial), "S/N: %ld", serial);
        FfxNode text = ffx_scene_createText(scene, strSerial, strlen(strSerial));
        ffx_scene_appendChild(root, text);
        FfxPoint *point = ffx_scene_nodePosition(text);
        point->x = 10;
        point->y = 150;
    }

    {
        esp_ds_data_t *cipherdata = heap_caps_malloc(sizeof(esp_ds_data_t), MALLOC_CAP_DMA);
        memset(cipherdata, 0, sizeof(esp_ds_data_t));

        size_t olen = sizeof(esp_ds_data_t);
        nvs_get_blob(nvs, "cipherdata", cipherdata, &olen);

        uint8_t digest[384];
        memset(digest, 0x42, sizeof(digest));
        digest[0] = 0xff;
        //esp_fill_random(digest, 384);

        uint8_t sig[384];
        memset(sig, 0, sizeof(sig));

        ret = esp_ds_sign(digest, cipherdata, ATTEST_HMAC_KEY, sig);

        reverseBytes(digest, sizeof(digest));

        mbedtls_mpi mpiResult, mpiSig, mpiE, mpiN, mpiRR;

        mbedtls_mpi_init(&mpiResult);
        mbedtls_mpi_init(&mpiSig);
        mbedtls_mpi_init(&mpiE);
        mbedtls_mpi_init(&mpiN);
        mbedtls_mpi_init(&mpiRR);

        reverseBytes(sig, sizeof(sig));
        mbedtls_mpi_read_binary(&mpiSig, sig, sizeof(sig));

        uint8_t n[384];
        olen = 384;
        nvs_get_blob(nvs, "pubkey-n", n, &olen);
        mbedtls_mpi_read_binary(&mpiN, n, olen);

        mbedtls_mpi_read_string(&mpiE, 10, "65537");

        mbedtls_mpi_exp_mod(&mpiResult, &mpiSig, &mpiE, &mpiN, &mpiRR);

        uint8_t result[384];
        mbedtls_mpi_write_binary(&mpiResult, result, sizeof(result));

        int miss = -1;
        for (int i = 0; i < sizeof(result); i++) {
            if (result[i] != digest[i]) {
                miss = 0;
                break;
            }
        }

        if (miss >= 0) {
            snprintf(strVerify, sizeof(strVerify), "Verify: bad %d", miss);
        } else {
            snprintf(strVerify, sizeof(strVerify), "Verify: ok");
        }

        FfxNode text = ffx_scene_createText(scene, strVerify, strlen(strVerify));
        ffx_scene_appendChild(root, text);
        FfxPoint *point = ffx_scene_nodePosition(text);
        point->x = 10;
        point->y = 180;
    }

    TickType_t lastFrameTime = ticks();

    ffx_scene_sequence(scene);

    while (1) {
        uint32_t frameDone = ffx_display_renderFragment(display);

        if (frameDone) {
            //ffx_scene_sequence(scene);
            break;
            /*
            BaseType_t didDelay = xTaskDelayUntil(&lastFrameTime, 1000 / 60);
            if (didDelay == pdFALSE) {
                delay(1);
                lastFrameTime = xTaskGetTickCount();
            }
            */
        }
    }
}

void app_main() {
    uint32_t version = esp_efuse_read_reg(EFUSE_BLK3, 0);
    if (version) { splash_screen(); }

    provision_repl();

    while (1) { delay(10000); }
}
