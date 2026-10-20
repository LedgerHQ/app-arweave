/*******************************************************************************
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

#include <gmock/gmock.h>
#include <cstring>
#include <string>
#include "parser.h"

static std::string formatted(uint64_t bytes) {
    char out[64];
    EXPECT_EQ(parser_formatDataSize(bytes, out, sizeof(out)), parser_ok);
    return out;
}

TEST(DataSize, Formats) {
    EXPECT_EQ(formatted(0), "0 bytes");
    EXPECT_EQ(formatted(1), "1 byte");
    EXPECT_EQ(formatted(999), "999 bytes");
    EXPECT_EQ(formatted(1000), "1.00 KB (1000 bytes)");
    EXPECT_EQ(formatted(1005), "1.01 KB (1005 bytes)");
    EXPECT_EQ(formatted(999994), "999.99 KB (999994 bytes)");
    EXPECT_EQ(formatted(999995), "1.00 MB (999995 bytes)");
    EXPECT_EQ(formatted(1048576), "1.05 MB (1048576 bytes)");
    EXPECT_EQ(formatted(2147483648ULL), "2.15 GB (2147483648 bytes)");
    EXPECT_EQ(formatted(1000000000000ULL), "1.00 TB (1000000000000 bytes)");
    EXPECT_EQ(formatted(18446744073709551615ULL), "18.45 EB (18446744073709551615 bytes)");
}

TEST(DataSize, RefusesAShortBuffer) {
    char out[10];
    EXPECT_NE(parser_formatDataSize(1048576, out, sizeof(out)), parser_ok);
}

static parser_error_t read(const char *s, uint64_t *out) {
    parser_element_t e = {(uint16_t) strlen(s), (const uint8_t *) s};
    return parser_readDecimalU64(&e, out);
}

TEST(DataSize, ReadsDecimalStrings) {
    uint64_t v = 1;
    EXPECT_EQ(read("0", &v), parser_ok);
    EXPECT_EQ(v, 0u);
    EXPECT_EQ(read("1048576", &v), parser_ok);
    EXPECT_EQ(v, 1048576u);
    EXPECT_EQ(read("18446744073709551615", &v), parser_ok);
    EXPECT_EQ(v, 18446744073709551615ULL);

    EXPECT_NE(read("", &v), parser_ok);
    EXPECT_NE(read("12a", &v), parser_ok);
    EXPECT_NE(read("-1", &v), parser_ok);
    EXPECT_NE(read("18446744073709551616", &v), parser_ok);
    EXPECT_NE(read("99999999999999999999", &v), parser_ok);
    EXPECT_NE(read("000000000000000000001", &v), parser_ok);
}
