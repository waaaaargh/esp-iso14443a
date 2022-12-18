#include "./iso14443a.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "esp_log.h"

uint8_t buf[256];

uint8_t iso14443a_anticollision_loop(iso14443a_ctx_t *ctx, uint8_t *uid)
{
    uint8_t bytes_rx = 0;
    uint8_t uid_len = 0;

    // Send  REQA
    ctx->tx_reqa_fn(ctx->device);

    // Receive ATQA
    uint8_t atqa[2] = {0x00, 0x00};
    bytes_rx = ctx->rx_fn(ctx->device, sizeof(atqa), atqa);
    if (bytes_rx <= 0)
        return 0;
    ESP_LOGI("iso14443a", "recv atqa: %02X%02X", atqa[0], atqa[1]);

    for (uint8_t cascade_level = 0x93; cascade_level <= 0x97; cascade_level += 0x02)
    {

        // Send SEL
        uint8_t sel[2] = {cascade_level, 0x20};
        ctx->tx_fn(ctx->device, sizeof(sel), sel);

        // Receive UID
        bytes_rx = ctx->rx_fn(ctx->device, sizeof(buf), buf);
        if (bytes_rx <= 0)
        {
            ESP_LOGE("iso4443a", "error receiving UID");
            return 0;
        }

        // Copy UID chunk
        if (buf[0] == 0x88)
        {
            // If the first byte is 0x88, the chunk of UUID we read is 3 bytes
            memcpy(uid + uid_len, buf + 1, 3);
            uid_len += 3;
        }
        else
        {
            // Rest of our UID is one chunk.
            memcpy(uid + uid_len, buf, 4);
            uid_len += 4;
        }

        // Send SEL w/ UID
        uint8_t sel_uid[7] = {cascade_level, 0x70, buf[0], buf[1], buf[2], buf[3], buf[4]};
        ctx->tx_fn_crc(ctx->device, sizeof(sel_uid), sel_uid);

        // Receive SAK
        bytes_rx = ctx->rx_fn(ctx->device, sizeof(buf), buf);
        if (bytes_rx <= 0)
        {
            ESP_LOGE("iso4443a", "error receiving SAK");
            return 0;
        }
        ESP_LOGI("iso14443a", "SAK: %02X%02X", buf[0], buf[1]);

        // Validate SAK
        if ((buf[0] >> 2) & 1U)
        {
            // Need to cascade
            ESP_LOGI("iso14443a", "UID incomplete, need to cascade");
            continue;
        }
        else if ((buf[0] >> 5) & 1U)
        {
            // PICC compliant with ISO/IEC 14443-4
            ESP_LOGI("iso14443a", "Anticollision complete");
            return uid_len;
        }

        ESP_LOGI("iso14443a", "non-compliant PICC");
        break;
    }
    return uid_len;
}

void iso14443a_request_ats(iso14443a_ctx_t *ctx)
{
    uint8_t rx_bytes = 0;

    // src: https://github.com/JPG-Consulting/rfid-desfire/blob/master/Desfire.cpp#L8
    uint8_t rats[2] = {0xE0, 0x50};
    ctx->tx_fn_crc(ctx->device, 2, rats);
    rx_bytes = ctx->rx_fn(ctx->device, sizeof(buf), buf);
    if (rx_bytes == 0)
    {
        ESP_LOGE("iso14443a", "error receiving ATS");
    }
    else
    {
        uint8_t ats_format_byte = buf[1];
        ctx->fsc = ats_format_byte &= ~(0b00001111);
        ESP_LOGI("iso14443a", "received ATS, FSC=0x%02x", ctx->fsc);
    }
}

// uint16_t iso14443a_dx(iso14443a_ctx_t *ctx, uint8_t *txbuf, uint16_t tx_bytes, uint8_t *rxbuf)
// {
//     uint8_t payload_length = ctx->fsc - 1 - 2;

//     uint8_t pcb = 0;

//     // Send
//     for (uint8_t chunk = 0; chunk <= (tx_bytes / payload_length); chunk += 1)
//     {
//         // determine chunk_size
//         uint8_t chunk_size = (tx_bytes - (chunk * payload_length)) <= payload_length ? tx_bytes - (chunk * payload_length) : payload_length;

//         // Construct PCB
//         pcb = 0b00000010; // I-Block

//         // Block Number
//         if (chunk % 2 == 1)
//         {
//             pcb |= 1 << 0;
//         }

//         // Chaining Bit
//         if (((chunk + 1) * payload_length) < (tx_bytes - payload_length))
//         {
//             pcb |= 1 << 4;
//         }

//         buf[0] = pcb;
//         memcpy(buf + 1, txbuf + (chunk * payload_length), chunk_size);

//         ctx->tx_fn_crc(ctx->device, buf, chunk_size + 1);
//     }

//     // Receive
//     bool rx_last_block = false;
//     while (!rx_last_block)
//     {
//         memset(buf, 0x00, sizeof(buf));
//         uint8_t rx_bytes = ctx->rx_fn(ctx->device, sizeof(buf), buf);
//         ESP_LOGI("iso14443a", "received %d bytes", rx_bytes);
//         break;
//     }

//     return 0;
// }

#define ISO14443_4_PCB_I_BLOCK 0b00000000
#define ISO14443_4_PCB_R_BLOCK 0b10000000
#define ISO14443_4_PCB_BIT_BLOCK_NUMBER 1
#define ISO14443_4_PCB_BIT_CHAINING_OR_ACK 4

uint8_t iso14443_pcb(uint8_t block, bool ack, bool chaining, bool block_number)
{
    uint8_t pcb = 0b00000010; // b2 is always on;

    pcb |= block;
    pcb |= ((chaining | !ack) ? 1 : 0 << ISO14443_4_PCB_BIT_CHAINING_OR_ACK);
    return pcb;
}

int iso14443a_dx(void *df_ctx, unsigned int len, uint8_t *data, unsigned int max, const char **strerr)
{
    iso14443a_ctx_t *ctx = (iso14443a_ctx_t *)df_ctx;
    uint8_t max_chunk_length = ctx->fsc - 1 - 2;

    // Send Data
    uint16_t cursor = 0;
    bool block_number_odd = false;
    while (cursor < len)
    {
        uint8_t chunk_size = len - cursor < max_chunk_length ? len - cursor : max_chunk_length;
        bool last_chunk = cursor + chunk_size >= len;
        memset(buf, 0x00, sizeof(buf));

        buf[0] = iso14443_pcb(
            ISO14443_4_PCB_I_BLOCK,
            false,
            !last_chunk,
            block_number_odd);

        memcpy(buf + 1, data, chunk_size);

        ctx->tx_fn_crc(ctx->device, chunk_size + 1, buf);
        ESP_LOGI("iso14443a", "transmitting %d bytes", chunk_size);
        ESP_LOG_BUFFER_HEX("iso14443a_tx", buf, chunk_size + 1);

        cursor += chunk_size;
        block_number_odd = !block_number_odd;

        // Receive ACK
        if (!last_chunk)
        {
            memset(buf, 0x00, sizeof(buf));
            uint8_t rx_bytes = ctx->rx_fn(ctx->device, sizeof(buf), buf);
            ESP_LOGI("iso14443a", "received %d bytes", rx_bytes);

            // TODO: validate R-Block
        }
    }

    // Receive Data
    memset(data, 0x00, max);

    bool rx_last_block = false;
    while (!rx_last_block)
    {
        memset(buf, 0x00, sizeof(buf));
        uint8_t rx_bytes = ctx->rx_fn(ctx->device, sizeof(buf), buf);
        ESP_LOGI("iso14443a", "received %d bytes", rx_bytes);
        ESP_LOG_BUFFER_HEX("iso14443a_rx", buf, rx_bytes);
        break;
    }

    return 0;
}