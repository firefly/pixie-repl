#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


uint32_t ticks();
void delay(uint32_t duration);

void panic(char *message, int code);

void dumpBuffer(char *header, uint8_t *buffer, size_t length);
void dumpArray(char *header, uint8_t *buffer, size_t length);

int startsWith(const char* buffer, const char *prefix, size_t length);

void reverseBytes(uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UTILS_H__ */
