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

#include "image-logo.h"

#define DEVICE_INFO_BLOCK   (EFUSE_BLK3)
#define ATTEST_SLOT         (2)
#define ATTEST_KEY_BLOCK    (EFUSE_BLK_KEY2)
#define ATTEST_HMAC_KEY     (HMAC_KEY2)

// Device Info
// - reg0 (0x 01 00 00 ZZ)
//   - Versin 1
//     - version 0x 00 00 00 01
//   - Version 2+
//     - version 0b zzzz zvvv vvvv vvvv vvvv vvvv vvvv vvv0
//     - v = version - 2 (v2 = 0, v3 = 1, etc)
//     - z = count zero bits in v (1 to 26)
// - reg1; model number
// - reg2; serial number
// - reg3: secret marker

int _getHex(char value) {
    if (value >= '0' && value <= '9') { return value - '0'; }
    value &= ~0x20;
    if (value >= 'A' && value <= 'F') { return value - 'A' + 10; }
    if (value >= 'a' && value <= 'f') { return value - 'a' + 10; }
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
    printf("<efuse.key.%d.unused=number:%d\n", slot, unused);
    if (!unused) {
        bool readProtect = esp_efuse_get_key_dis_read(block);
        bool writeProtect = esp_efuse_get_key_dis_write(block);
        printf("<efuse.key.%d.readProtect=number:%d\n", slot, readProtect);
        printf("<efuse.key.%d.writeProtect=number:%d\n", slot, writeProtect);
    }

    uint8_t key[32];
    esp_efuse_read_block(block, key, 0, sizeof(key) * 8);

    char name[32];
    snprintf(name, sizeof(name), "efuse.keyHmac.%d", slot);
    dumpBuffer(name, key, sizeof(key));

    return unused ? 0: 1;
}

int dumpNvs(nvs_handle_t nvs, char *key, size_t length) {

    uint8_t blob[length];
    size_t olen = length;
    int ret = nvs_get_blob(nvs, key, blob, &olen);
    if (ret) {
       printf("<nvs.%s=void:\n", key);
    } else {
        char name[32];
        snprintf(name, sizeof(name), "nvs.%s", key);
        dumpBuffer(name, blob, olen);
    }

    return olen;
}

#define DISPLAY_BUS        (FfxDisplaySpiBus2)
#define PIN_DISPLAY_DC     (4)
#define PIN_DISPLAY_RESET  (5)

void render_scene(uint8_t *fragment, uint32_t y0, void *context) {
    FfxScene scene = context;
    ffx_scene_render(scene, fragment, y0, FfxDisplayFragmentHeight);
}

static nvs_handle_t nvs;
void _nvs_open() {
    int ret = nvs_flash_init_partition("attest");
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        panic("failed to init attest partition", ret);
    }

    ret = nvs_open_from_partition("attest", "secure", NVS_READWRITE, &nvs);
    if (ret) {
        panic("failed to open attest partition", ret);
    }
}

#define LINE_COUNT    (5)
#define LINE_LENGTH   (20)

static size_t line = 0;
static char _lines[LINE_COUNT * LINE_LENGTH * 2] = { 0 };
static FfxNode lines[LINE_COUNT];
static FfxScene scene;
static FfxDisplayContext display;
void scene_init() {
    scene = ffx_scene_init(64);

    display = ffx_display_init(DISPLAY_BUS, PIN_DISPLAY_DC,
      PIN_DISPLAY_RESET, FfxDisplayRotationRibbonRight, render_scene, scene);

    // Blank screen
    while (!ffx_display_renderFragment(display));

    FfxNode root = ffx_scene_root(scene);

    FfxNode fill = ffx_scene_createFill(scene, ffx_color_rgb(0, 0, 0, 0x20));
    ffx_scene_appendChild(root, fill);

    {
        FfxNode logo = ffx_scene_createImage(scene, image_logo, sizeof(image_logo));
        ffx_scene_appendChild(root, logo);
        FfxPoint *point = ffx_scene_nodePosition(logo);
        point->x = 82;
        point->y = 0;
    }

    for (int i = 0; i < LINE_COUNT; i++) {
        lines[i] = ffx_scene_createTextFlip(scene, &_lines[i * 2 * LINE_LENGTH], LINE_LENGTH * 2);
        ffx_scene_appendChild(root, lines[i]);
        FfxPoint *point = ffx_scene_nodePosition(lines[i]);
        point->x = 10;
        point->y = 110 + i * 26;
    }
}

void scene_addText(char *text) {

    if (line < LINE_COUNT) {
        ffx_scene_textSetText(lines[line], text, strlen(text) + 1);
        line++;
        return;
    }

    for (int i = 1; i < line; i++) {
        char tmp[20];
        size_t length = ffx_scene_textGetText(lines[i], tmp, sizeof(tmp));
        ffx_scene_textSetText(lines[i - 1], tmp, length);
    }

    ffx_scene_textSetText(lines[line - 1], text, strlen(text) + 1);
    if (line < LINE_COUNT) { line++; }
}

void scene_flush() {
    ffx_scene_sequence(scene);
    while (!ffx_display_renderFragment(display));
}

void scene_checkAttest() {
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

    int ret = esp_ds_sign(digest, cipherdata, ATTEST_HMAC_KEY, sig);

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
        scene_addText("Attest: fail");
    } else {
        scene_addText("Attest: ok");
    }
}

void scene_checkEfuse() {
    char text[20];

    uint32_t model = esp_efuse_read_reg(EFUSE_BLK3, 1);
    if ((model >> 8) == 1) {
        snprintf(text, sizeof(text), "Pixie (rev.%ld)", model & 0xff);
        scene_addText(text);
    } else if (model) {
        scene_addText("Unknown Model");
    }

    uint32_t version = esp_efuse_read_reg(EFUSE_BLK3, 0);
    if (version > 1) {
        snprintf(text, sizeof(text), "Version: %ld", version);
        scene_addText(text);
    }

    if (model != 0) {
        snprintf(text, sizeof(text), "Model: 0x%lx", model);
        scene_addText(text);
    }

    uint32_t serial = esp_efuse_read_reg(EFUSE_BLK3, 2);
    if (serial) {
       snprintf(text, sizeof(text), "S/N: %ld", serial);
       scene_addText(text);
    }

    if (version) {
        scene_checkAttest();
    }
}


void app_main() {
    _nvs_open();

    scene_init();

    TickType_t lastFrameTicks = ticks();

    ffx_scene_sequence(scene);

    scene_checkEfuse();


    printf("? start provisioning\n");

    uint8_t pubkey[384] = { 0 };
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

    int ret;

    int readyCount = 0;

    char buffer[4096];

    size_t offset = 0;
    buffer[0] = 0;

    while (1) {
        delay(1);

        // 30-ish fps (no effort to enforce constant interval)
        if ((ticks() - lastFrameTicks) > 33) {
            scene_flush();
            lastFrameTicks = ticks();
        }

        // We keep announcing we are ready until we start receiving data
        // in case the provision script missed the first message
        if (readyCount == 0) {
            readyCount++;
            printf("<READY\n");

        } else if (readyCount > 0) {
            // Only annouce every 5s
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

            // Next character
            if (buffer[i] != 10) { continue; }

            // NL; we have a new command, change the NL to NULL
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
                    printf("! ATTEST no pubkey present (use GEN-KEY, LOAD-NVS or SET-PUBKEY)\n");
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

                memcpy(&attestation[offset], pubkey, nLen);
                offset += nLen;

                memcpy(&attestation[offset], attest, 64);
                offset += 64;

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
                dumpBuffer("attest", attestation, sizeof(attestation));

                printf("<OK\n");

            } else if (startsWith(buffer, "BURN", i)) {
                scene_addText("BURN");

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
                printf("<efuse.key.burned=number:%d\n", inUse);

                uint32_t valueCheck = 0;
                printf("<efuse.blk3=buffer:");
                for (int j = 0; j < 8; j++) {
                    uint32_t value = esp_efuse_read_reg(DEVICE_INFO_BLOCK, j);
                    valueCheck |= value;
                    printf("%08lx", value);
                }
                printf(" (32 bytes)\n");

                printf("<efuse.blk3.burned=number:%d\n", valueCheck != 0);
                if (valueCheck) {
                    printf("<efuse.model=number:%ld\n", esp_efuse_read_reg(DEVICE_INFO_BLOCK, 1));
                    printf("<efuse.serial=number:%ld\n", esp_efuse_read_reg(DEVICE_INFO_BLOCK, 2));
                    printf("<efuse.randMarker=number:%lu\n", esp_efuse_read_reg(DEVICE_INFO_BLOCK, 4));
                }

                dumpNvs(nvs, "attest", 64);
                dumpNvs(nvs, "pubkey-n", 384);
                dumpNvs(nvs, "cipherdata", sizeof(esp_ds_data_t));

                if (modelNumber) {
                    printf("<pending.modelNumber=number:%ld\n", modelNumber);
                }

                if (serialNumber) {
                    printf("<pending.serialNumber=number:%ld\n", serialNumber);
                }

                printf("<pending.randMarker=number:%lu\n", randMarker);

                if (hasPubKey) {
                    dumpBuffer("pending.pubkey", pubkey, sizeof(pubkey));
                }

                if (hasCipherdata) {
                    dumpBuffer("pending.cipherdata", (uint8_t*)cipherdata, sizeof(esp_ds_data_t));
                }

                if (hasAttest) {
                    dumpBuffer("pending.attest", attest, sizeof(attest));
                }

                printf("<ready=number:%d\n", (inUse || valueCheck));

                printf("<OK\n");

            } else if (startsWith(buffer, "GEN-KEY", i)) {
                uint32_t t0 = ticks();
                scene_addText("> GEN-KEY");
                scene_flush();

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
                keypair_dumpMpi("pubkey", &keypair.N);
                mbedtls_mpi_write_binary(&keypair.N, pubkey, 384);

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
                dumpBuffer("cipherdata", cipherdata, sizeof(cipherdata));

                printf("<marker=number:%lu\n", randMarker);

                hasPubKey = true;
                hasCipherdata = true;

                printf("<OK\n");

                uint32_t dt = ticks() - t0;

                char tmp[20];
                snprintf(tmp, sizeof(tmp), "  %ld.%03lds", dt / 1000, dt % 1000);
                scene_addText(tmp);
                scene_flush();

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
                        dumpBuffer("nvs.attest", attest, olen);
                        hasAttest = true;
                    }
                }

                {
                    size_t olen = 384;
                    uint8_t blob[olen];
                    ret = nvs_get_blob(nvs, "pubkey-n", blob, &olen);
                    if (!ret && olen == 384) {
                        memcpy(pubkey, blob, olen);
                        dumpBuffer("nvs.pubkey", pubkey, olen);
                        hasPubKey = true;
                    }
                }

                {
                    size_t olen = sizeof(esp_ds_data_t);
                    uint8_t blob[olen];
                    ret = nvs_get_blob(nvs, "cipherdata", blob, &olen);
                    if (!ret && olen == sizeof(esp_ds_data_t)) {
                        memcpy(cipherdata, blob, olen);
                        dumpBuffer("nvs.cipherdata", cipherdata, olen);
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

            } else if (startsWith(buffer, "SET-PUBKEY=", i)) {
                if (length != 2 * sizeof(pubkey)) {
                    printf("! SET-PUBKEY bad parameter length (%d != %d)\n",
                      length, 2 * sizeof(pubkey));
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                ret = readBuffer(pubkey, &buffer[start], length);
                if (ret < 0) { panic("! SET-PUBKEY invalid data", ret); }

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
                printf("<version=number:1\n");
                printf("<OK\n");

            } else if (startsWith(buffer, "WRITE", i)) {
                scene_addText("> WRITE");

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
                    printf("! WRITE missing key (use GEN-KEY or SET-PUBKEY)\n");
                    error = true;
                }

                if (error) {
                    printf("<ERROR\n");

                    offset = 0; buffer[0] = 0;
                    break;
                }

                ret = nvs_set_blob(nvs, "attest", attest, sizeof(attest));
                if (ret) { panic("failed to write attest", ret); }

                ret = nvs_set_blob(nvs, "pubkey-n", pubkey, sizeof(pubkey));
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
