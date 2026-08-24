/*******************************************************************************
* Modifications copyright 2026 Forward Research. Apache-2.0.
********************************************************************************/

#include <gtest/gtest.h>
#include <string>
#include <vector>

extern "C" {
#include "parser_httpsig.h"
}

static std::string valid_signature_base() {
    return
        "\"@method\": POST\n"
        "\"@path\": /~process@1.0/push\n"
        "\"content-digest\": sha-256=:YWJjZA==:\n"
        "\"@signature-params\": (\"@method\" \"@path\" \"content-digest\")"
        ";alg=\"rsa-pss-sha512\";keyid=\"AAAA\"";
}

TEST(HttpSignature, ParsesMainnetSignatureBaseAndHashesExactBytes) {
    const std::string base = valid_signature_base();
    parser_context_t ctx;
    ASSERT_EQ(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(base.data()), base.size()),
              parser_ok);
    EXPECT_EQ(httpsig_validate(&ctx), parser_ok);

    uint8_t count = 0;
    ASSERT_EQ(httpsig_getNumItems(&ctx, &count), parser_ok);
    EXPECT_EQ(count, 5);

    uint8_t digest[HTTPSIG_DIGEST_LEN] = {0};
    ASSERT_EQ(httpsig_getDigest(digest, sizeof(digest)), parser_ok);
    EXPECT_NE(std::vector<uint8_t>(digest, digest + sizeof(digest)),
              std::vector<uint8_t>(sizeof(digest)));
}

TEST(HttpSignature, AcceptsCurrentAoCoreMainnetFieldShape) {
    const std::string base =
        "\"action\": Ping\n"
        "\"body\": hello\n"
        "\"data-protocol\": ao\n"
        "\"signing-format\": httpsig\n"
        "\"@signature-params\": (\"action\" \"body\" \"data-protocol\" \"signing-format\")"
        ";alg=\"rsa-pss-sha512\";keyid=\"BwcHBwcH\"";
    parser_context_t ctx;
    ASSERT_EQ(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(base.data()), base.size()),
              parser_ok);
    EXPECT_EQ(httpsig_validate(&ctx), parser_ok);
    uint8_t count = 0;
    ASSERT_EQ(httpsig_getNumItems(&ctx, &count), parser_ok);
    EXPECT_EQ(count, 6);
}

TEST(HttpSignature, RejectsWrongAlgorithmAndTrailingNewline) {
    parser_context_t ctx;
    std::string wrong_alg = valid_signature_base();
    wrong_alg.replace(wrong_alg.find("rsa-pss-sha512"), 15, "rsa-pss-sha256");
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(wrong_alg.data()),
                            wrong_alg.size()), parser_ok);

    std::string trailing = valid_signature_base() + "\n";
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(trailing.data()),
                            trailing.size()), parser_ok);
}

TEST(HttpSignature, RejectsBinaryAndMissingCommittedField) {
    parser_context_t ctx;
    std::string binary = valid_signature_base();
    binary[5] = '\0';
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(binary.data()),
                            binary.size()), parser_ok);

    std::string missing = valid_signature_base();
    missing.replace(missing.rfind("\"content-digest\"") + 1, 14, "content-missing");
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(missing.data()),
                            missing.size()), parser_ok);
}

TEST(HttpSignature, RequiresComponentsInReviewedOrderWithoutExtras) {
    parser_context_t ctx;

    std::string reordered = valid_signature_base();
    const std::string original = "(\"@method\" \"@path\" \"content-digest\")";
    const auto components = reordered.find(original);
    ASSERT_NE(components, std::string::npos);
    reordered.replace(components, original.size(),
                      "(\"@path\" \"@method\" \"content-digest\")");
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(reordered.data()),
                            reordered.size()), parser_ok);

    std::string extra = valid_signature_base();
    extra.insert(extra.find(");alg"), " \"content-length\"");
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(extra.data()), extra.size()),
              parser_ok);
}

TEST(HttpSignature, AcceptsAdditionalParametersAndRejectsDuplicateSecurityParameters) {
    parser_context_t ctx;
    std::string created = valid_signature_base();
    created.insert(created.find(";alg"), ";created=1784123456");
    EXPECT_EQ(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(created.data()),
                            created.size()), parser_ok);

    std::string duplicate_alg = valid_signature_base() + ";alg=\"rsa-pss-sha512\"";
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(duplicate_alg.data()),
                            duplicate_alg.size()), parser_ok);

    std::string duplicate_key = valid_signature_base() + ";keyid=\"BBBB\"";
    EXPECT_NE(httpsig_parse(&ctx, reinterpret_cast<const uint8_t *>(duplicate_key.data()),
                            duplicate_key.size()), parser_ok);
}
