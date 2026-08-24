/*******************************************************************************
* Modifications copyright 2026 Forward Research. Apache-2.0.
********************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <zxformat.h>
#include <zxmacros.h>
#include "crypto_helper.h"
#include "crypto.h"
#include "parser_httpsig.h"
#include "parser_txdef.h"

typedef struct {
    parser_tag_t fields[32];
    parser_element_t key_id;
    uint16_t fields_count;
    uint16_t bytes_len;
} parser_httpsig_t;

static parser_httpsig_t httpsig_obj;
static uint8_t httpsig_digest[HTTPSIG_DIGEST_LEN];
static bool httpsig_digest_ready = false;

static bool matches(const uint8_t *ptr, uint16_t len, const char *expected) {
    const size_t expected_len = strlen(expected);
    return len == expected_len && MEMCMP(ptr, expected, expected_len) == 0;
}

static parser_error_t parse_signature_params(const uint8_t *value, uint16_t value_len) {
    uint16_t offset = 0;
    if (value_len == 0 || value[offset++] != '(') return parser_unexpected_value;

    // The component list must commit to exactly the fields shown to the user.
    for (uint16_t i = 0; i < httpsig_obj.fields_count; i++) {
        if (i > 0 && (offset >= value_len || value[offset++] != ' ')) {
            return parser_unexpected_field;
        }
        if (offset >= value_len || value[offset++] != '"') return parser_unexpected_field;
        const parser_element_t *key = &httpsig_obj.fields[i].key;
        if (key->len > value_len - offset || MEMCMP(value + offset, key->ptr, key->len) != 0) {
            return parser_unexpected_field;
        }
        offset += key->len;
        if (offset >= value_len || value[offset++] != '"') return parser_unexpected_field;
    }
    if (offset >= value_len || value[offset++] != ')') return parser_unexpected_field;

    bool algorithm_seen = false;
    bool key_id_seen = false;
    while (offset < value_len) {
        if (value[offset++] != ';') return parser_unexpected_value;
        const uint16_t name_start = offset;
        while (offset < value_len && value[offset] != '=') offset++;
        if (offset == name_start || offset >= value_len) return parser_unexpected_value;
        const uint8_t *name = value + name_start;
        const uint16_t name_len = offset - name_start;
        offset++;

        const uint16_t value_start = offset;
        uint16_t parameter_len = 0;
        if (offset < value_len && value[offset] == '"') {
            offset++;
            const uint16_t quoted_start = offset;
            while (offset < value_len && value[offset] != '"') {
                if (value[offset] == '\\') return parser_unexpected_characters;
                offset++;
            }
            if (offset >= value_len) return parser_unexpected_value;
            parameter_len = offset - quoted_start;
            offset++;
        } else {
            while (offset < value_len && value[offset] != ';') offset++;
            parameter_len = offset - value_start;
        }
        if (parameter_len == 0) return parser_unexpected_value;

        if (matches(name, name_len, "alg")) {
            if (algorithm_seen || value[value_start] != '"' ||
                !matches(value + value_start + 1, parameter_len, "rsa-pss-sha512")) {
                return parser_unexpected_value;
            }
            algorithm_seen = true;
        } else if (matches(name, name_len, "keyid")) {
            if (key_id_seen || value[value_start] != '"') return parser_unexpected_value;
            httpsig_obj.key_id.ptr = value + value_start + 1;
            httpsig_obj.key_id.len = parameter_len;
            key_id_seen = true;
        }
    }

    return algorithm_seen && key_id_seen ? parser_ok : parser_unexpected_value;
}

static parser_error_t parse_line(const uint8_t *line, uint16_t len, bool is_last) {
    if (len < 5 || line[0] != '"') return parser_unexpected_field;
    uint16_t closing = 1;
    while (closing < len && line[closing] != '"') closing++;
    if (closing + 2 >= len || line[closing + 1] != ':' || line[closing + 2] != ' ') {
        return parser_unexpected_field;
    }
    const uint8_t *name = line + 1;
    const uint16_t name_len = closing - 1;
    const uint8_t *value = line + closing + 3;
    const uint16_t value_len = len - closing - 3;

    if (is_last) {
        if (name_len != strlen("@signature-params") ||
            MEMCMP(name, "@signature-params", name_len) != 0) {
            return parser_unexpected_field;
        }
        return parse_signature_params(value, value_len);
    }

    if (httpsig_obj.fields_count >= 32 || name_len == 0 || name_len >= 68) {
        return parser_value_out_of_range;
    }
    if (name_len == strlen("@signature-params") &&
        MEMCMP(name, "@signature-params", name_len) == 0) {
        return parser_unexpected_field;
    }
    for (uint16_t i = 0; i < httpsig_obj.fields_count; i++) {
        if (httpsig_obj.fields[i].key.len == name_len &&
            MEMCMP(httpsig_obj.fields[i].key.ptr, name, name_len) == 0) {
            return parser_unexpected_field;
        }
    }
    httpsig_obj.fields[httpsig_obj.fields_count].key.ptr = name;
    httpsig_obj.fields[httpsig_obj.fields_count].key.len = name_len;
    httpsig_obj.fields[httpsig_obj.fields_count].value.ptr = value;
    httpsig_obj.fields[httpsig_obj.fields_count].value.len = value_len;
    httpsig_obj.fields_count++;
    return parser_ok;
}

parser_error_t httpsig_parse(parser_context_t *ctx, const uint8_t *data, size_t data_len) {
    MEMZERO(&httpsig_obj, sizeof(httpsig_obj));
    MEMZERO(httpsig_digest, sizeof(httpsig_digest));
    httpsig_digest_ready = false;
    if (ctx == NULL || data == NULL || data_len == 0 || data_len > UINT16_MAX) {
        return parser_no_data;
    }
    ctx->buffer = data;
    ctx->bufferLen = (uint16_t)data_len;
    ctx->offset = 0;
    httpsig_obj.bytes_len = (uint16_t)data_len;

    uint16_t start = 0;
    while (start < data_len) {
        uint16_t end = start;
        while (end < data_len && data[end] != '\n') {
            if (data[end] < 0x20 || data[end] > 0x7e) return parser_unexpected_characters;
            end++;
        }
        if (end == start) return parser_unexpected_field;
        const bool is_last = end == data_len;
        CHECK_PARSER_ERR(parse_line(data + start, end - start, is_last))
        if (is_last) break;
        start = end + 1;
        if (start == data_len) return parser_unexpected_field;
    }
    if (httpsig_obj.fields_count == 0) return parser_unexpected_field;
    ctx->offset = ctx->bufferLen;
    if (crypto_sha512(data, data_len, httpsig_digest, sizeof(httpsig_digest)) != zxerr_ok) {
        return parser_unexpected_error;
    }
    httpsig_digest_ready = true;
    return parser_ok;
}

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
static int8_t base64_value(uint8_t character) {
    if (character >= 'A' && character <= 'Z') return character - 'A';
    if (character >= 'a' && character <= 'z') return character - 'a' + 26;
    if (character >= '0' && character <= '9') return character - '0' + 52;
    if (character == '+' || character == '-') return 62;
    if (character == '/' || character == '_') return 63;
    return -1;
}

static bool key_id_matches_device(void) {
    const uint8_t prefix[] = "publickey:";
    const uint8_t *encoded = httpsig_obj.key_id.ptr;
    uint16_t encoded_len = httpsig_obj.key_id.len;
    if (encoded_len >= sizeof(prefix) - 1 &&
        MEMCMP(encoded, prefix, sizeof(prefix) - 1) == 0) {
        encoded += sizeof(prefix) - 1;
        encoded_len -= sizeof(prefix) - 1;
    }
    while (encoded_len > 0 && encoded[encoded_len - 1] == '=') encoded_len--;
    if (encoded_len != 683) return false;

    uint8_t key_part[RSA_MODULUS_HALVE] = {0};
    if (crypto_getpubkey_part(key_part, sizeof(key_part), 0) != zxerr_ok) return false;
    uint32_t accumulator = 0;
    uint8_t bits = 0;
    uint16_t output_index = 0;
    for (uint16_t i = 0; i < encoded_len; i++) {
        const int8_t value = base64_value(encoded[i]);
        if (value < 0) return false;
        accumulator = (accumulator << 6) | (uint8_t)value;
        bits += 6;
        if (bits < 8) continue;
        bits -= 8;
        const uint8_t decoded = (accumulator >> bits) & 0xff;
        if (output_index == RSA_MODULUS_HALVE) {
            MEMZERO(key_part, sizeof(key_part));
            if (crypto_getpubkey_part(key_part, sizeof(key_part), 1) != zxerr_ok) return false;
        }
        if (output_index >= RSA_MODULUS_LEN ||
            decoded != key_part[output_index % RSA_MODULUS_HALVE]) return false;
        output_index++;
        accumulator &= bits == 0 ? 0 : (1u << bits) - 1;
    }
    return output_index == RSA_MODULUS_LEN && accumulator == 0;
}
#endif

parser_error_t httpsig_validate(const parser_context_t *ctx) {
    if (ctx == NULL || ctx->offset != ctx->bufferLen || !httpsig_digest_ready) {
        return parser_unexpected_error;
    }
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    if (!key_id_matches_device()) return parser_unexpected_value;
#endif
    return parser_ok;
}

parser_error_t httpsig_getDigest(uint8_t *digest, uint16_t digest_len) {
    if (!httpsig_digest_ready || digest == NULL || digest_len < sizeof(httpsig_digest)) {
        return parser_unexpected_error;
    }
    MEMCPY(digest, httpsig_digest, sizeof(httpsig_digest));
    return parser_ok;
}

parser_error_t httpsig_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    if (ctx == NULL || num_items == NULL) return parser_unexpected_error;
    *num_items = 2 + httpsig_obj.fields_count;
    return parser_ok;
}

parser_error_t httpsig_getItem(const parser_context_t *ctx, uint16_t display_idx,
                               char *out_key, uint16_t out_key_len,
                               char *out_val, uint16_t out_val_len,
                               uint8_t page_idx, uint8_t *page_count) {
    uint8_t count = 0;
    CHECK_PARSER_ERR(httpsig_getNumItems(ctx, &count))
    if (display_idx >= count) return parser_no_data;
    MEMZERO(out_key, out_key_len);
    MEMZERO(out_val, out_val_len);
    *page_count = 1;

    uint16_t index = 0;
    if (display_idx == index++) {
        snprintf(out_key, out_key_len, "Type");
        snprintf(out_val, out_val_len, "AO HTTP Signature");
        return parser_ok;
    }
    if (display_idx < index + httpsig_obj.fields_count) {
        const parser_tag_t *field = &httpsig_obj.fields[display_idx - index];
        const uint16_t key_len = field->key.len < out_key_len - 1
                                     ? field->key.len : out_key_len - 1;
        MEMCPY(out_key, field->key.ptr, key_len);
        pageStringExt(out_val, out_val_len, (const char *)field->value.ptr,
                      field->value.len, page_idx, page_count);
        return parser_ok;
    }
    index += httpsig_obj.fields_count;
    if (display_idx == index) {
        snprintf(out_key, out_key_len, "Request size");
        snprintf(out_val, out_val_len, "%u bytes", httpsig_obj.bytes_len);
        return parser_ok;
    }
    return parser_no_data;
}
