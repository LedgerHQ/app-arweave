/*******************************************************************************
*  Modifications (c) 2026 Forward Research
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
********************************************************************************/

#include <cassert>
#include <cstddef>
#include <cstdint>
#include "parser_common.h"
#include "parser_dataitem.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parser_context_t ctx;
    if (dataitem_parse(&ctx, data, size) != parser_ok) return 0;
    if (dataitem_validate(&ctx) != parser_ok) return 0;

    uint8_t count = 0;
    assert(dataitem_getNumItems(&ctx, &count) == parser_ok);
    for (uint8_t i = 0; i < count; i++) {
        char key[40] = {0};
        char value[40] = {0};
        uint8_t page = 0;
        uint8_t pages = 1;
        while (page < pages) {
            assert(dataitem_getItem(&ctx, i, key, sizeof(key), value, sizeof(value),
                                    page, &pages) == parser_ok);
            page++;
        }
    }
    uint8_t digest[48] = {0};
    assert(dataitem_getDigest(digest, sizeof(digest)) == parser_ok);
    return 0;
}
