// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/evidence.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#if defined(OE_USE_OPENSSL)
#include "../../../enclave/crypto/openssl/cert.h"
#endif

/* Test the internal API that is only avaiable on OpenSSL-based implementation.
 */
#if defined(OE_USE_OPENSSL)
static void _test_X509_parse_name()
{
    X509_NAME* name = NULL;
    char buf[OE_X509_MAX_NAME_SIZE];

    printf("=== begin %s()\n", __FUNCTION__);

    /* Basic case */
    name = X509_parse_name("CN=Open Enclave SDK,O=OESDK TLS,C=US");
    OE_TEST(name != NULL);
    X509_NAME_get_text_by_NID(name, NID_commonName, buf, 256);
    OE_TEST(strcmp(buf, "Open Enclave SDK") == 0);
    X509_NAME_get_text_by_NID(name, NID_organizationName, buf, 256);
    OE_TEST(strcmp(buf, "OESDK TLS") == 0);
    X509_NAME_get_text_by_NID(name, NID_countryName, buf, 256);
    OE_TEST(strcmp(buf, "US") == 0);
    X509_NAME_free(name);

    /* Spaces after a comma should be allowed */
    name = X509_parse_name("CN=Open Enclave SDK, O=OESDK TLS,    C=US");
    OE_TEST(name != NULL);
    X509_NAME_get_text_by_NID(name, NID_commonName, buf, 256);
    OE_TEST(strcmp(buf, "Open Enclave SDK") == 0);
    X509_NAME_get_text_by_NID(name, NID_organizationName, buf, 256);
    OE_TEST(strcmp(buf, "OESDK TLS") == 0);
    X509_NAME_get_text_by_NID(name, NID_countryName, buf, 256);
    OE_TEST(strcmp(buf, "US") == 0);
    X509_NAME_free(name);

    /* Escaping commas should be allowed  */
    name = X509_parse_name("CN=Open Enclave SDK\\,OE SDK,O=OESDK TLS,C=US");
    OE_TEST(name != NULL);
    X509_NAME_get_text_by_NID(name, NID_commonName, buf, 256);
    OE_TEST(strcmp(buf, "Open Enclave SDK,OE SDK") == 0);
    X509_NAME_get_text_by_NID(name, NID_organizationName, buf, 256);
    OE_TEST(strcmp(buf, "OESDK TLS") == 0);
    X509_NAME_get_text_by_NID(name, NID_countryName, buf, 256);
    OE_TEST(strcmp(buf, "US") == 0);
    X509_NAME_free(name);

    /* Spaces arround the key should not be allowed (i.e., invalid keys) */
    name = X509_parse_name(" CN=Open Enclave SDK,O=OESDK TLS,C=US");
    OE_TEST(name == NULL);

    /* Setting a content larger than 255 byte should not be allowed  */
    {
        char test[1024];
        memset(test, 'B', 1024);
        test[256] = '=';
        test[258] = '\0';
        /* BBBB...BBB(256)=B */
        name = X509_parse_name(test);
        OE_TEST(name == NULL);
    }

    /* Setting a content larger than 255 byte should not be allowed  */
    {
        char test[1024];
        memset(test, 'B', 1024);
        test[0] = 'L';
        test[1] = '=';
        test[258] = '\0';
        /* L=BBBB..BBB(256) */
        name = X509_parse_name(test);
        OE_TEST(name == NULL);
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_decode_oid_to_str()
{
    char* oid_str;

    printf("=== begin %s()\n", __FUNCTION__);

    {
        const unsigned char oid_oe_report[] = X509_OID_FOR_QUOTE_EXT;
        oid_str =
            decode_oid_to_str((char*)oid_oe_report, sizeof(oid_oe_report));
        OE_TEST(strcmp(oid_str, X509_OID_FOR_QUOTE_STRING) == 0);
        free(oid_str);
    }

    {
        const unsigned char oid_oe_report[] = X509_OID_FOR_NEW_QUOTE_EXT;
        oid_str =
            decode_oid_to_str((char*)oid_oe_report, sizeof(oid_oe_report));
        OE_TEST(strcmp(oid_str, X509_OID_FOR_NEW_QUOTE_STRING) == 0);
        free(oid_str);
    }

    {
        const unsigned char oid_oe_evidence[] = X509_OID_FOR_OE_EVIDENCE_EXT;
        oid_str =
            decode_oid_to_str((char*)oid_oe_evidence, sizeof(oid_oe_evidence));
        OE_TEST(strcmp(oid_str, X509_OID_FOR_OE_EVIDENCE_STRING) == 0);
        free(oid_str);
    }

    {
        const unsigned char oid_oe_evidence[] =
            X509_OID_FOR_NEW_OE_EVIDENCE_EXT;
        oid_str =
            decode_oid_to_str((char*)oid_oe_evidence, sizeof(oid_oe_evidence));
        OE_TEST(strcmp(oid_str, X509_OID_FOR_NEW_OE_EVIDENCE_STRING) == 0);
        free(oid_str);
    }

    /* Negative test: NULL input. */
    {
        oid_str = decode_oid_to_str(NULL, 100);
        OE_TEST(oid_str == NULL);
    }

    /* Negative test: 0 length. */
    {
        oid_str = decode_oid_to_str("\x00", 0);
        OE_TEST(oid_str == NULL);
    }

    /* Positive test: Basic case. */
    {
        oid_str = decode_oid_to_str("\xff", 1);
        OE_TEST(strcmp(oid_str, "2.175") == 0);
        free(oid_str);
    }

    /* Positive test: Basic case. */
    {
        oid_str = decode_oid_to_str("\x2a\x03", 2);
        OE_TEST(strcmp(oid_str, "1.2.3") == 0);
        free(oid_str);
    }

    /* Positive test: 0x80 is valid for the first byte/block. */
    {
        oid_str = decode_oid_to_str("\x80\x03", 2);
        OE_TEST(strcmp(oid_str, "2.48.3") == 0);
        free(oid_str);
    }

    /* Negative test: 0x80 at the beginning of a block. */
    {
        oid_str = decode_oid_to_str("\x2a\x80\x03", 3);
        OE_TEST(oid_str == NULL);
    }

    /* Negative test: Non-ended block. */
    {
        oid_str = decode_oid_to_str("\xff\xff", 2);
        OE_TEST(oid_str == NULL);
    }

    /* Postitve test: Single block less than the maximum value (INT_MAX) */
    {
        oid_str = decode_oid_to_str("\xff\xff\xff\xff\x7f", 5);
        OE_TEST(strcmp(oid_str, "2.175.268435455") == 0);
        free(oid_str);
    }

    /* Negative test: Single block exceeds the maximum value (INT_MAX) */
    {
        oid_str = decode_oid_to_str("\xff\xff\xff\xff\xff\x7f", 6);
        OE_TEST(oid_str == NULL);
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

#endif

void TestCert(void)
{
#if defined(OE_USE_OPENSSL)
    _test_X509_parse_name();
    _test_decode_oid_to_str();
#endif
}
