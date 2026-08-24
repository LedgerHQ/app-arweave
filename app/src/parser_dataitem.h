/*******************************************************************************
*  (c) 2019 Zondax GmbH
*  Modifications (c) 2026 Forward Research
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#pragma once

#include "parser.h"
#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DATAITEM_SIGNATURE_TYPE_ARWEAVE 1
#define DATAITEM_SIGNATURE_LEN 512
#define DATAITEM_OWNER_LEN 512
#define DATAITEM_TARGET_LEN 32
#define DATAITEM_ANCHOR_LEN 32
#define DATAITEM_MAX_TAGS MAX_NUMBER_TAGS

typedef struct {
    uint16_t signature_type;
    parser_element_t owner;
    parser_element_t target;
    parser_element_t anchor;
    uint16_t tags_count;
    parser_tag_t tags[DATAITEM_MAX_TAGS];
    parser_element_t raw_tags;
    parser_element_t data;
} parser_dataitem_t;

parser_error_t dataitem_parse(parser_context_t *ctx, const uint8_t *data, size_t data_len);
parser_error_t dataitem_validate(const parser_context_t *ctx);
parser_error_t dataitem_getDigest(uint8_t *digest, uint16_t digest_len);
parser_error_t dataitem_getCachedDigest(uint8_t *digest, uint16_t digest_len);
parser_error_t dataitem_getNumItems(const parser_context_t *ctx, uint8_t *num_items);
parser_error_t dataitem_getItem(const parser_context_t *ctx,
                                uint16_t display_idx,
                                char *out_key, uint16_t out_key_len,
                                char *out_val, uint16_t out_val_len,
                                uint8_t page_idx, uint8_t *page_count);

#ifdef __cplusplus
}
#endif
