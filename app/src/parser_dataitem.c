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

#include <stdio.h>
#include <string.h>
#include <zxformat.h>
#include <zxmacros.h>
#include "app_mode.h"
#include "b64url.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "parser_dataitem.h"

parser_dataitem_t parser_dataitem_obj;
static uint8_t parser_dataitem_digest[SHA384_DIGEST_LEN];
static bool parser_dataitem_digest_ready = false;

typedef union {
    struct {
        uint8_t tag_hash[SHA384_DIGEST_LEN];
        uint8_t data_hash[SHA384_DIGEST_LEN];
    };
    uint8_t blob[SHA384_DIGEST_LEN * 2];
} dataitem_tagged_hash_t;

typedef union {
    struct {
        uint8_t acc[SHA384_DIGEST_LEN];
        uint8_t hash[SHA384_DIGEST_LEN];
    };
    uint8_t pair[SHA384_DIGEST_LEN * 2];
} dataitem_deep_hash_t;

#define HASH_OR_RETURN(CALL) do { if ((CALL) != zxerr_ok) return parser_unexpected_error; } while (0)

static parser_error_t read_u8(parser_context_t *ctx, uint8_t *value) {
    CTX_CHECK_AVAIL(ctx, 1)
    *value = ctx->buffer[ctx->offset];
    CTX_CHECK_AND_ADVANCE(ctx, 1)
    return parser_ok;
}

static parser_error_t read_le16(parser_context_t *ctx, uint16_t *value) {
    CTX_CHECK_AVAIL(ctx, 2)
    *value = (uint16_t)ctx->buffer[ctx->offset] |
             ((uint16_t)ctx->buffer[ctx->offset + 1] << 8);
    CTX_CHECK_AND_ADVANCE(ctx, 2)
    return parser_ok;
}

static parser_error_t read_le64_bounded(parser_context_t *ctx, uint16_t *value) {
    CTX_CHECK_AVAIL(ctx, 8)
    for (uint8_t i = 2; i < 8; i++) {
        if (ctx->buffer[ctx->offset + i] != 0) return parser_value_out_of_range;
    }
    *value = (uint16_t)ctx->buffer[ctx->offset] |
             ((uint16_t)ctx->buffer[ctx->offset + 1] << 8);
    CTX_CHECK_AND_ADVANCE(ctx, 8)
    return parser_ok;
}

static parser_error_t read_fixed(parser_context_t *ctx, parser_element_t *value, uint16_t len) {
    CTX_CHECK_AVAIL(ctx, len)
    value->ptr = ctx->buffer + ctx->offset;
    value->len = len;
    CTX_CHECK_AND_ADVANCE(ctx, len)
    return parser_ok;
}

static parser_error_t read_optional_32(parser_context_t *ctx, parser_element_t *value) {
    uint8_t present = 0;
    CHECK_PARSER_ERR(read_u8(ctx, &present))
    if (present > 1) return parser_unexpected_value;
    value->ptr = ctx->buffer + ctx->offset;
    value->len = 0;
    if (present == 1) CHECK_PARSER_ERR(read_fixed(ctx, value, 32))
    return parser_ok;
}

static parser_error_t read_avro_long(parser_context_t *ctx, int64_t *value) {
    uint64_t encoded = 0;
    uint8_t shift = 0;
    uint8_t byte = 0;
    do {
        if (shift >= 63) return parser_value_out_of_range;
        CHECK_PARSER_ERR(read_u8(ctx, &byte))
        encoded |= ((uint64_t)(byte & 0x7f)) << shift;
        shift += 7;
    } while ((byte & 0x80) != 0);
    *value = (int64_t)((encoded >> 1) ^ (uint64_t)-(int64_t)(encoded & 1));
    return parser_ok;
}

static parser_error_t read_avro_string(parser_context_t *ctx, parser_element_t *value) {
    int64_t len = 0;
    CHECK_PARSER_ERR(read_avro_long(ctx, &len))
    if (len < 0 || len > UINT16_MAX) return parser_value_out_of_range;
    return read_fixed(ctx, value, (uint16_t)len);
}

static parser_error_t parse_avro_tags(parser_context_t *ctx, uint16_t expected_count,
                                      parser_tag_t tags[DATAITEM_MAX_TAGS]) {
    uint16_t parsed = 0;
    while (true) {
        int64_t block_count = 0;
        uint16_t block_size = 0;
        uint16_t block_start = 0;
        CHECK_PARSER_ERR(read_avro_long(ctx, &block_count))
        if (block_count == 0) break;

        if (block_count < 0) {
            int64_t encoded_block_size = 0;
            block_count = -block_count;
            CHECK_PARSER_ERR(read_avro_long(ctx, &encoded_block_size))
            if (encoded_block_size < 0 || encoded_block_size > UINT16_MAX) {
                return parser_value_out_of_range;
            }
            block_size = (uint16_t)encoded_block_size;
            block_start = ctx->offset;
        }
        if (block_count > DATAITEM_MAX_TAGS || parsed + block_count > expected_count) {
            return parser_value_out_of_range;
        }
        for (int64_t i = 0; i < block_count; i++) {
            CHECK_PARSER_ERR(read_avro_string(ctx, &tags[parsed].key))
            CHECK_PARSER_ERR(read_avro_string(ctx, &tags[parsed].value))
            parsed++;
        }
        if (block_size > 0 && ctx->offset - block_start != block_size) {
            return parser_unexpected_value;
        }
    }
    return parsed == expected_count ? parser_ok : parser_unexpected_number_items;
}

static bool is_printable(const parser_element_t *element, bool allow_empty) {
    if (!allow_empty && element->len == 0) return false;
    for (uint16_t i = 0; i < element->len; i++) {
        if (element->ptr[i] < 0x20 || element->ptr[i] > 0x7e) return false;
    }
    return true;
}

static parser_error_t validate_tags(void) {
    for (uint16_t i = 0; i < parser_dataitem_obj.tags_count; i++) {
        const parser_tag_t *tag = &parser_dataitem_obj.tags[i];
        if (!is_printable(&tag->key, false) || !is_printable(&tag->value, true)) {
            return parser_unexpected_characters;
        }
        for (uint16_t j = 0; j < i; j++) {
            const parser_element_t *previous = &parser_dataitem_obj.tags[j].key;
            if (tag->key.len == previous->len &&
                MEMCMP(tag->key.ptr, previous->ptr, tag->key.len) == 0) {
                return parser_unexpected_field;
            }
        }
    }
    return parser_ok;
}

parser_error_t dataitem_parse(parser_context_t *ctx, const uint8_t *data, size_t data_len) {
    MEMZERO(&parser_dataitem_obj, sizeof(parser_dataitem_obj));
    MEMZERO(parser_dataitem_digest, sizeof(parser_dataitem_digest));
    parser_dataitem_digest_ready = false;
    if (data == NULL || data_len == 0 || data_len > UINT16_MAX) return parser_no_data;
    CHECK_PARSER_ERR(parser_init(ctx, data, (uint16_t)data_len))

    CHECK_PARSER_ERR(read_le16(ctx, &parser_dataitem_obj.signature_type))
    if (parser_dataitem_obj.signature_type != DATAITEM_SIGNATURE_TYPE_ARWEAVE) {
        return parser_unexpected_type;
    }
    CTX_CHECK_AND_ADVANCE(ctx, DATAITEM_SIGNATURE_LEN)
    CHECK_PARSER_ERR(read_fixed(ctx, &parser_dataitem_obj.owner, DATAITEM_OWNER_LEN))
    CHECK_PARSER_ERR(read_optional_32(ctx, &parser_dataitem_obj.target))
    CHECK_PARSER_ERR(read_optional_32(ctx, &parser_dataitem_obj.anchor))

    uint16_t tag_bytes_len = 0;
    CHECK_PARSER_ERR(read_le64_bounded(ctx, &parser_dataitem_obj.tags_count))
    CHECK_PARSER_ERR(read_le64_bounded(ctx, &tag_bytes_len))
    if (parser_dataitem_obj.tags_count > DATAITEM_MAX_TAGS) return parser_value_out_of_range;
    CTX_CHECK_AVAIL(ctx, tag_bytes_len)
    parser_dataitem_obj.raw_tags.ptr = ctx->buffer + ctx->offset;
    parser_dataitem_obj.raw_tags.len = tag_bytes_len;

    if ((parser_dataitem_obj.tags_count == 0) != (tag_bytes_len == 0)) {
        return parser_unexpected_number_items;
    }
    if (tag_bytes_len > 0) {
        parser_context_t tags_ctx = {
            .buffer = parser_dataitem_obj.raw_tags.ptr,
            .bufferLen = parser_dataitem_obj.raw_tags.len,
            .offset = 0,
        };
        CHECK_PARSER_ERR(parse_avro_tags(&tags_ctx, parser_dataitem_obj.tags_count,
                                         parser_dataitem_obj.tags))
        if (tags_ctx.offset != tags_ctx.bufferLen) return parser_unexpected_buffer_end;
        CHECK_PARSER_ERR(validate_tags())
    }
    CTX_CHECK_AND_ADVANCE(ctx, tag_bytes_len)

    parser_dataitem_obj.data.ptr = ctx->buffer + ctx->offset;
    parser_dataitem_obj.data.len = ctx->bufferLen - ctx->offset;
    ctx->offset = ctx->bufferLen;
    return parser_ok;
}

parser_error_t dataitem_validate(const parser_context_t *ctx) {
    if (ctx == NULL || ctx->offset != ctx->bufferLen) return parser_unexpected_buffer_end;
#if defined(TARGET_NANOS) || defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    uint8_t key_part[RSA_MODULUS_HALVE];
    for (uint8_t i = 0; i < 2; i++) {
        MEMZERO(key_part, sizeof(key_part));
        if (crypto_getpubkey_part(key_part, sizeof(key_part), i) != zxerr_ok) {
            return parser_unexpected_error;
        }
        if (MEMCMP(parser_dataitem_obj.owner.ptr + i * RSA_MODULUS_HALVE,
                   key_part, RSA_MODULUS_HALVE) != 0) return parser_unexpected_error;
    }
#endif
    uint8_t num_items = 0;
    CHECK_PARSER_ERR(dataitem_getNumItems(ctx, &num_items))
    char key[40];
    char value[40];
    for (uint8_t i = 0; i < num_items; i++) {
        uint8_t pages = 0;
        CHECK_PARSER_ERR(dataitem_getItem(ctx, i, key, sizeof(key), value, sizeof(value), 0, &pages))
    }
    CHECK_PARSER_ERR(dataitem_getDigest(parser_dataitem_digest,
                                        sizeof(parser_dataitem_digest)))
    parser_dataitem_digest_ready = true;
    return parser_ok;
}

static parser_error_t hash_tag(uint8_t out[SHA384_DIGEST_LEN], const char *kind, uint16_t len) {
    uint8_t buffer[32] = {0};
    const size_t kind_len = strlen(kind);
    if (kind_len >= sizeof(buffer)) return parser_unexpected_buffer_end;

    MEMCPY(buffer, kind, kind_len);
    uint8_t digits[5] = {0};
    uint8_t digits_len = 0;
    do {
        digits[digits_len++] = (uint8_t)('0' + (len % 10));
        len /= 10;
    } while (len > 0 && digits_len < sizeof(digits));

    if (kind_len + digits_len > sizeof(buffer)) return parser_unexpected_buffer_end;
    for (uint8_t i = 0; i < digits_len; i++) {
        buffer[kind_len + i] = digits[digits_len - i - 1];
    }
    HASH_OR_RETURN(crypto_sha384(buffer, kind_len + digits_len, out, SHA384_DIGEST_LEN));
    return parser_ok;
}

static parser_error_t hash_blob(uint8_t out[SHA384_DIGEST_LEN], const uint8_t *data, uint16_t len) {
    dataitem_tagged_hash_t tagged = {0};
    CHECK_PARSER_ERR(hash_tag(tagged.tag_hash, "blob", len))
    HASH_OR_RETURN(crypto_sha384(data, len, tagged.data_hash, SHA384_DIGEST_LEN));
    HASH_OR_RETURN(crypto_sha384(tagged.blob, sizeof(tagged.blob), out, SHA384_DIGEST_LEN));
    return parser_ok;
}

static parser_error_t accumulate(dataitem_deep_hash_t *ctx, const uint8_t *data, uint16_t len) {
    uint8_t next[SHA384_DIGEST_LEN] = {0};
    CHECK_PARSER_ERR(hash_blob(ctx->hash, data, len))
    HASH_OR_RETURN(crypto_sha384(ctx->pair, sizeof(ctx->pair), next, SHA384_DIGEST_LEN));
    MEMCPY(ctx->acc, next, sizeof(next));
    return parser_ok;
}

parser_error_t dataitem_getDigest(uint8_t *digest, uint16_t digest_len) {
    if (digest == NULL || digest_len < SHA384_DIGEST_LEN) return parser_unexpected_buffer_end;
    static const uint8_t kind[] = "dataitem";
    static const uint8_t version[] = "1";
    static const uint8_t signature_type[] = "1";
    dataitem_deep_hash_t ctx = {0};
    CHECK_PARSER_ERR(hash_tag(ctx.acc, "list", 8))
    CHECK_PARSER_ERR(accumulate(&ctx, kind, sizeof(kind) - 1))
    CHECK_PARSER_ERR(accumulate(&ctx, version, sizeof(version) - 1))
    CHECK_PARSER_ERR(accumulate(&ctx, signature_type, sizeof(signature_type) - 1))
    CHECK_PARSER_ERR(accumulate(&ctx, parser_dataitem_obj.owner.ptr, parser_dataitem_obj.owner.len))
    CHECK_PARSER_ERR(accumulate(&ctx, parser_dataitem_obj.target.ptr, parser_dataitem_obj.target.len))
    CHECK_PARSER_ERR(accumulate(&ctx, parser_dataitem_obj.anchor.ptr, parser_dataitem_obj.anchor.len))
    CHECK_PARSER_ERR(accumulate(&ctx, parser_dataitem_obj.raw_tags.ptr, parser_dataitem_obj.raw_tags.len))
    CHECK_PARSER_ERR(accumulate(&ctx, parser_dataitem_obj.data.ptr, parser_dataitem_obj.data.len))
    MEMCPY(digest, ctx.acc, SHA384_DIGEST_LEN);
    return parser_ok;
}

parser_error_t dataitem_getCachedDigest(uint8_t *digest, uint16_t digest_len) {
    if (!parser_dataitem_digest_ready) return parser_unexpected_error;
    if (digest == NULL || digest_len < sizeof(parser_dataitem_digest)) {
        return parser_unexpected_buffer_end;
    }
    MEMCPY(digest, parser_dataitem_digest, sizeof(parser_dataitem_digest));
    return parser_ok;
}

parser_error_t dataitem_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    if (ctx == NULL || num_items == NULL) return parser_unexpected_error;
    *num_items = 3 + parser_dataitem_obj.tags_count +
                 (parser_dataitem_obj.target.len > 0 ? 1 : 0) +
                 (parser_dataitem_obj.anchor.len > 0 ? 1 : 0);
    return parser_ok;
}

static parser_error_t print_bytes(const parser_element_t *element, char *out, uint16_t out_len,
                                  uint8_t page_idx, uint8_t *page_count) {
    char encoded[200] = {0};
    if (b64url_encode(encoded, sizeof(encoded), element->ptr, element->len) == 0) {
        return parser_unexpected_buffer_end;
    }
    pageStringExt(out, out_len, encoded, strnlen(encoded, sizeof(encoded)), page_idx, page_count);
    return parser_ok;
}

parser_error_t dataitem_getItem(const parser_context_t *ctx, uint16_t display_idx,
                                char *out_key, uint16_t out_key_len,
                                char *out_val, uint16_t out_val_len,
                                uint8_t page_idx, uint8_t *page_count) {
    uint8_t count = 0;
    CHECK_PARSER_ERR(dataitem_getNumItems(ctx, &count))
    if (display_idx >= count) return parser_no_data;
    MEMZERO(out_key, out_key_len);
    MEMZERO(out_val, out_val_len);
    *page_count = 1;

    uint16_t index = 0;
    snprintf(out_key, out_key_len, "Type");
    if (display_idx == index++) {
        snprintf(out_val, out_val_len, "ANS-104 Data Item");
        return parser_ok;
    }
    if (parser_dataitem_obj.target.len > 0) {
        if (display_idx == index++) {
            snprintf(out_key, out_key_len, "Target");
            return print_bytes(&parser_dataitem_obj.target, out_val, out_val_len, page_idx, page_count);
        }
    }
    if (parser_dataitem_obj.anchor.len > 0) {
        if (display_idx == index++) {
            snprintf(out_key, out_key_len, "Anchor");
            return print_bytes(&parser_dataitem_obj.anchor, out_val, out_val_len, page_idx, page_count);
        }
    }
    if (display_idx < index + parser_dataitem_obj.tags_count) {
        const parser_tag_t *tag = &parser_dataitem_obj.tags[display_idx - index];
        const uint16_t key_len = tag->key.len < out_key_len - 1 ? tag->key.len : out_key_len - 1;
        MEMCPY(out_key, tag->key.ptr, key_len);
        pageStringExt(out_val, out_val_len, (const char *)tag->value.ptr, tag->value.len,
                      page_idx, page_count);
        return parser_ok;
    }
    index += parser_dataitem_obj.tags_count;
    if (display_idx == index) {
        snprintf(out_key, out_key_len, "Data size");
        snprintf(out_val, out_val_len, "%u bytes", parser_dataitem_obj.data.len);
        return parser_ok;
    }
    index++;
    if (display_idx == index) {
        parser_element_t hash_element = {.len = SHA384_DIGEST_LEN};
        uint8_t hash[SHA384_DIGEST_LEN] = {0};
        if (crypto_sha384(parser_dataitem_obj.data.ptr, parser_dataitem_obj.data.len,
                          hash, sizeof(hash)) != zxerr_ok) {
            return parser_unexpected_error;
        }
        hash_element.ptr = hash;
        snprintf(out_key, out_key_len, "Data hash");
        return print_bytes(&hash_element, out_val, out_val_len, page_idx, page_count);
    }
    return parser_no_data;
}
