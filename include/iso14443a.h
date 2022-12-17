#ifndef ISO14443A_H
#define ISO14443A_H

#include <stdint.h>

typedef struct
{
    void *device;
    void (*tx_reqa_fn)(void *);
    void (*tx_fn)(void *, uint16_t, uint8_t *);
    void (*tx_fn_crc)(void *, uint16_t, uint8_t *);
    uint16_t (*rx_fn)(void *, uint16_t, uint8_t *);

    uint8_t fsc;
} iso14443a_ctx_t;

uint8_t iso14443a_anticollision_loop(iso14443a_ctx_t *, uint8_t *);

void iso14443a_request_ats(iso14443a_ctx_t *);

int iso14443a_dx(void *ctx, unsigned int len, uint8_t *data, unsigned int max, const char **strerr);

#endif // ISO14443A_H