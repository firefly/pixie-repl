#include <string.h>

#include "utils.h"


uint32_t ticks() {
    return xTaskGetTickCount();
}

void delay(uint32_t duration) {
    vTaskDelay((duration + portTICK_PERIOD_MS - 1) / portTICK_PERIOD_MS);
}

void panic(char *message, int code) {
    printf("! [PANIC] %s (code=%d; %s)\n\n", message, code,
      esp_err_to_name(code));
    while(1) { delay(1000); }
}

void reverseBytes(uint8_t *data, size_t length) {
    for (int i = 0; i < length / 2; i++) {
        uint8_t tmp = data[i];
        data[i] = data[length - 1 - i];
        data[length - 1 - i] = tmp;
    }
}

void dumpBuffer(char *header, uint8_t *buffer, size_t length) {
    static char *hex = "0123456789abcdef";

    printf("%s", header);
    for (uint32_t i = 0; i < length; i++) {
        printf("%c%c", hex[buffer[i] >> 4], hex[buffer[i] & 0x0f]);
    }
    printf("  (%d bytes)\n", length);
}

void dumpArray(char *header, uint8_t *buffer, size_t length) {
    static char *hex = "0123456789abcdef";

    printf("%s = {", header);
    for (uint32_t i = 0; i < length; i++) {
        printf("0x%c%c, ", hex[buffer[i] >> 4], hex[buffer[i] & 0x0f]);
    }
    printf("  }\n");
}

int startsWith(const char* buffer, const char *prefix, size_t length) {
    size_t prefixLen = strlen(prefix);
    if (length < prefixLen) { return 0; }
    return (strncmp(buffer, prefix, prefixLen) == 0) ? 1: 0;
}
