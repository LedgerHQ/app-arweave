/*******************************************************************************
*  Modifications (c) 2026 Forward Research
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
********************************************************************************/

#include <gtest/gtest.h>
#include <cstdio>
#include <vector>
#include "parser_dataitem.h"

static const uint8_t TAGS[] = {
    0x0c, 0x1a, 0x44, 0x61, 0x74, 0x61, 0x2d, 0x50, 0x72, 0x6f, 0x74, 0x6f,
    0x63, 0x6f, 0x6c, 0x04, 0x61, 0x6f, 0x0e, 0x56, 0x61, 0x72, 0x69, 0x61,
    0x6e, 0x74, 0x0e, 0x61, 0x6f, 0x2e, 0x54, 0x4e, 0x2e, 0x31, 0x08, 0x54,
    0x79, 0x70, 0x65, 0x0e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x0c,
    0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x10, 0x54, 0x72, 0x61, 0x6e, 0x73,
    0x66, 0x65, 0x72, 0x12, 0x52, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e,
    0x74, 0x22, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x2d,
    0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x10, 0x51, 0x75, 0x61, 0x6e,
    0x74, 0x69, 0x74, 0x79, 0x08, 0x31, 0x30, 0x30, 0x30, 0x00,
};

static void append_u64(std::vector<uint8_t> &out, uint64_t value) {
    for (uint8_t i = 0; i < 8; i++) out.push_back((value >> (8 * i)) & 0xff);
}

static void append_avro_long(std::vector<uint8_t> &out, int64_t value) {
    uint64_t encoded = value >= 0
        ? static_cast<uint64_t>(value) * 2
        : static_cast<uint64_t>(-(value + 1)) * 2 + 1;
    do {
        uint8_t byte = encoded & 0x7f;
        encoded >>= 7;
        if (encoded != 0) byte |= 0x80;
        out.push_back(byte);
    } while (encoded != 0);
}

static void append_avro_string(std::vector<uint8_t> &out, const std::string &value) {
    append_avro_long(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

static std::vector<uint8_t> tag_block(uint16_t count) {
    std::vector<uint8_t> tags;
    append_avro_long(tags, count);
    for (uint16_t i = 0; i < count; i++) {
        append_avro_string(tags, "Tag-" + std::to_string(i));
        append_avro_string(tags, "Value-" + std::to_string(i));
    }
    append_avro_long(tags, 0);
    return tags;
}

static std::vector<uint8_t> valid_dataitem() {
    std::vector<uint8_t> out = {1, 0};
    out.insert(out.end(), 512, 0);
    out.insert(out.end(), 512, 0x11);
    out.push_back(1);
    out.insert(out.end(), 32, 0x22);
    out.push_back(0);
    append_u64(out, 6);
    append_u64(out, sizeof(TAGS));
    out.insert(out.end(), TAGS, TAGS + sizeof(TAGS));
    const char data[] = "hello ao";
    out.insert(out.end(), data, data + sizeof(data) - 1);
    return out;
}

static std::vector<uint8_t> dataitem_with_tags(uint64_t count,
                                                const std::vector<uint8_t> &tags) {
    std::vector<uint8_t> out = {1, 0};
    out.insert(out.end(), 512, 0);
    out.insert(out.end(), 512, 0x11);
    out.push_back(0);
    out.push_back(0);
    append_u64(out, count);
    append_u64(out, tags.size());
    out.insert(out.end(), tags.begin(), tags.end());
    return out;
}

TEST(DataItem, ParsesCanonicalANS104AndMatchesArbundlesDigest) {
    const auto blob = valid_dataitem();
    parser_context_t ctx;
    ASSERT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_ok);
    ASSERT_EQ(dataitem_validate(&ctx), parser_ok);

    uint8_t digest[48] = {0};
    ASSERT_EQ(dataitem_getDigest(digest, sizeof(digest)), parser_ok);
    char digest_hex[97] = {0};
    for (size_t i = 0; i < sizeof(digest); i++) {
        snprintf(digest_hex + i * 2, sizeof(digest_hex) - i * 2, "%02x", digest[i]);
    }
    EXPECT_STREQ(digest_hex,
                 "27b0e89d5e4be7c252f835ad57fc0999d4cf9c7d859e6853640a4dac4c15c871"
                 "b5415abbb66dbb37a0f7daab2d197300");

    uint8_t cached_digest[48] = {0};
    ASSERT_EQ(dataitem_getCachedDigest(cached_digest, sizeof(cached_digest)), parser_ok);
    EXPECT_EQ(memcmp(cached_digest, digest, sizeof(digest)), 0);

    uint8_t items = 0;
    ASSERT_EQ(dataitem_getNumItems(&ctx, &items), parser_ok);
    EXPECT_EQ(items, 10);
}

TEST(DataItem, RejectsWrongSignatureType) {
    auto blob = valid_dataitem();
    blob[0] = 2;
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_type);
}

TEST(DataItem, RejectsTruncatedAvroTags) {
    auto blob = valid_dataitem();
    blob.resize(blob.size() - 12);
    parser_context_t ctx;
    EXPECT_NE(dataitem_parse(&ctx, blob.data(), blob.size()), parser_ok);
}

TEST(DataItem, AcceptsAnEmptyTagBlock) {
    std::vector<uint8_t> blob = {1, 0};
    blob.insert(blob.end(), 512, 0);
    blob.insert(blob.end(), 512, 0x11);
    blob.push_back(0);
    blob.push_back(0);
    append_u64(blob, 0);
    append_u64(blob, 0);

    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_ok);
}

TEST(DataItem, RejectsTagCountWithoutTagBytes) {
    std::vector<uint8_t> blob = {1, 0};
    blob.insert(blob.end(), 512, 0);
    blob.insert(blob.end(), 512, 0x11);
    blob.push_back(0);
    blob.push_back(0);
    append_u64(blob, 1);
    append_u64(blob, 0);

    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_number_items);
}

TEST(DataItem, RejectsDuplicateTagNames) {
    const std::vector<uint8_t> tags = {4, 2, 'A', 2, '1', 2, 'A', 2, '2', 0};
    const auto blob = dataitem_with_tags(2, tags);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_field);
}

TEST(DataItem, RejectsControlCharactersInTags) {
    const std::vector<uint8_t> tags = {2, 2, 1, 2, '1', 0};
    const auto blob = dataitem_with_tags(1, tags);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_characters);
}

TEST(DataItem, RejectsEmptyInputAndClearsCachedDigest) {
    const auto valid = valid_dataitem();
    parser_context_t ctx;
    ASSERT_EQ(dataitem_parse(&ctx, valid.data(), valid.size()), parser_ok);
    ASSERT_EQ(dataitem_validate(&ctx), parser_ok);

    EXPECT_EQ(dataitem_parse(&ctx, nullptr, 0), parser_no_data);
    uint8_t digest[48] = {0};
    EXPECT_EQ(dataitem_getCachedDigest(digest, sizeof(digest)), parser_unexpected_error);
}

TEST(DataItem, RejectsTruncatedFixedFields) {
    auto blob = valid_dataitem();
    blob.resize(1025);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_buffer_end);
}

TEST(DataItem, RejectsInvalidOptionalFieldFlags) {
    auto target = valid_dataitem();
    target[1026] = 2;
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, target.data(), target.size()), parser_unexpected_value);

    auto anchor = valid_dataitem();
    anchor[1059] = 2;
    EXPECT_EQ(dataitem_parse(&ctx, anchor.data(), anchor.size()), parser_unexpected_value);
}

TEST(DataItem, RejectsUnboundedTagLengths) {
    auto blob = valid_dataitem();
    blob[1062] = 1;
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_value_out_of_range);

    blob = valid_dataitem();
    blob[1070] = 1;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_value_out_of_range);
}

TEST(DataItem, RejectsTagBytesBeyondInput) {
    auto blob = valid_dataitem();
    blob[1068] = 0xff;
    blob[1069] = 0x7f;
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_buffer_end);
}

TEST(DataItem, RejectsTrailingBytesInsideTagBlock) {
    std::vector<uint8_t> tags = {2, 2, 'A', 2, '1', 0, 0xff};
    const auto blob = dataitem_with_tags(1, tags);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_buffer_end);
}

TEST(DataItem, AcceptsNegativeAvroTagBlockWithExactByteSize) {
    const std::vector<uint8_t> tags = {1, 8, 2, 'A', 2, '1', 0};
    const auto blob = dataitem_with_tags(1, tags);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_ok);
    EXPECT_EQ(dataitem_validate(&ctx), parser_ok);
}

TEST(DataItem, RejectsNegativeAvroTagBlockWithWrongByteSize) {
    const std::vector<uint8_t> tags = {1, 6, 2, 'A', 2, '1', 0};
    const auto blob = dataitem_with_tags(1, tags);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_unexpected_value);
}

TEST(DataItem, AcceptsMaximumTagCountAndEmptyValues) {
    auto tags = tag_block(DATAITEM_MAX_TAGS);
    const auto blob = dataitem_with_tags(DATAITEM_MAX_TAGS, tags);
    parser_context_t ctx;
    ASSERT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_ok);
    ASSERT_EQ(dataitem_validate(&ctx), parser_ok);
    uint8_t items = 0;
    ASSERT_EQ(dataitem_getNumItems(&ctx, &items), parser_ok);
    EXPECT_EQ(items, 3 + DATAITEM_MAX_TAGS);

    const std::vector<uint8_t> empty_value = {2, 2, 'A', 0, 0};
    const auto empty_value_blob = dataitem_with_tags(1, empty_value);
    EXPECT_EQ(dataitem_parse(&ctx, empty_value_blob.data(), empty_value_blob.size()), parser_ok);
}

TEST(DataItem, RejectsTagsBeyondMaximumAndEmptyNames) {
    auto tags = tag_block(DATAITEM_MAX_TAGS + 1);
    const auto too_many = dataitem_with_tags(DATAITEM_MAX_TAGS + 1, tags);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, too_many.data(), too_many.size()), parser_value_out_of_range);

    const std::vector<uint8_t> empty_name = {2, 0, 2, '1', 0};
    const auto empty_name_blob = dataitem_with_tags(1, empty_name);
    EXPECT_EQ(dataitem_parse(&ctx, empty_name_blob.data(), empty_name_blob.size()),
              parser_unexpected_characters);
}

TEST(DataItem, ParsesDeviceSizedPayloadAtSixteenKiB) {
    auto blob = dataitem_with_tags(0, {});
    ASSERT_LT(blob.size(), 16 * 1024);
    blob.resize(16 * 1024, 0x42);
    parser_context_t ctx;
    EXPECT_EQ(dataitem_parse(&ctx, blob.data(), blob.size()), parser_ok);
    EXPECT_EQ(dataitem_validate(&ctx), parser_ok);
}
