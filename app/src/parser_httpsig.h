/*******************************************************************************
* Modifications copyright 2026 Forward Research. Apache-2.0.
********************************************************************************/
#pragma once

#include "parser_common.h"

#define HTTPSIG_DIGEST_LEN 64

#ifdef __cplusplus
extern "C" {
#endif

parser_error_t httpsig_parse(parser_context_t *ctx, const uint8_t *data, size_t data_len);
parser_error_t httpsig_validate(const parser_context_t *ctx);
parser_error_t httpsig_getDigest(uint8_t *digest, uint16_t digest_len);
parser_error_t httpsig_getNumItems(const parser_context_t *ctx, uint8_t *num_items);
parser_error_t httpsig_getItem(const parser_context_t *ctx, uint16_t display_idx,
                               char *out_key, uint16_t out_key_len,
                               char *out_val, uint16_t out_val_len,
                               uint8_t page_idx, uint8_t *page_count);

#ifdef __cplusplus
}
#endif
