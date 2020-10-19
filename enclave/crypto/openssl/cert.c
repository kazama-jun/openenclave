// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "cert.h"
#include <ctype.h>
#include <openenclave/bits/result.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <string.h>

/*
 * Value used by the _decode_oid_to_str() function. Although the OID
 * standard does not limit the depth of an OID definition tree (i.e., the
 * number of arcs), our implementation only supports a simple decoding
 * with a limited depth (i.e., decoding into a fixed size string).
 */
#define OE_OID_MAX_LENGTH 200

/*
 * Parse the name string into X509_NAME struct. The format of the string is
 * "KEY1=VALUE1,KEY2=VALUE2,KEY3=VALUE3...". The implementation is based
 * on the mbedtls_x509_string_to_names from Mbed TLS.
 */
X509_NAME* X509_parse_name(const char* name_string)
{
    const char* s = name_string;
    const char* c = s;
    const char* end = s + strlen(s);
    int in_tag = 1;
    char key[OE_X509_MAX_NAME_SIZE];
    char value[OE_X509_MAX_NAME_SIZE];
    char data[OE_X509_MAX_NAME_SIZE];
    char* d = data;
    X509_NAME* name = NULL;
    int error = 1;

    name = X509_NAME_new();
    if (name == NULL)
        goto done;

    while (c <= end)
    {
        if (in_tag && *c == '=')
        {
            size_t len = (size_t)(c - s) + 1;
            if (len > OE_X509_MAX_NAME_SIZE)
                goto done;

            if (oe_memcpy_s(key, OE_X509_MAX_NAME_SIZE, s, len) != OE_OK)
                goto done;
            key[len - 1] = '\0';
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if (!in_tag && *c == '\\' && c != end)
        {
            c++;
            /* Only support escaping commas */
            if (c == end || *c != ',')
                goto done;
        }
        else if (!in_tag && (*c == ',' || c == end))
        {
            /*
             * The check of if(d - data == OE_X509_MAX_NAME_SIZE)
             * below ensures that len should never exceed OE_X509_MAX_NAME_SIZE.
             * We do not perform additional checks here.
             */
            size_t len = (size_t)(d - data) + 1;
            if (oe_memcpy_s(value, OE_X509_MAX_NAME_SIZE, data, len) != OE_OK)
                goto done;
            value[len - 1] = '\0';
            if (!X509_NAME_add_entry_by_txt(
                    name, key, MBSTRING_ASC, (unsigned char*)value, -1, -1, 0))
                goto done;

            /* Skip the spaces after the comma */
            while (c < end && *(c + 1) == ' ')
                c++;
            s = c + 1;
            in_tag = 1;
        }

        if (!in_tag && s != c + 1)
        {
            *(d++) = *c;
            if (d - data == OE_X509_MAX_NAME_SIZE)
                goto done;
        }

        c++;
    }

    error = 0;

done:
    if (error && name)
    {
        X509_NAME_free(name);
        name = NULL;
    }

    return name;
}

/*
 * Decode the OID from its BER format (byte-encoding) into a dot-notation string
 */
char* decode_oid_to_str(char* oid, int oid_size)
{
    char* oid_str = NULL;
    /*
     * 20 characters are suffuficnet to hold the maximum string (".2147483647")
     * where a block has the maximum value (i.e., INT_MAX).
     */
    char tmp_buf[20];
    char oid_buf[OE_OID_MAX_LENGTH] = {0};
    unsigned char byte = 0;
    int index = 0;
    int len = 0;

    if (!oid || oid_size <= 0)
        goto done;

    /*
     * The first block (single byte) requires special handling. The value of the
     * block (z) is decoded into two integers (x and y). The rule is as follows.
     * z = 40 * x + y, where x = 0, 1, or 2.
     */
    {
        long first;
        long second;

        byte = (unsigned char)oid[index++];
        first = byte / 40;
        /*
         * When x equals to 2, y can be arbitrarily large. However, y is bounded
         * by 175 in this implementation according to the equation y = z - 40 *
         * x, where z is the maximum value of a single byte (255) and x is 2.
         */
        if (first > 2)
            first = 2;

        second = byte - 40 * first;
        len = snprintf(tmp_buf, sizeof(tmp_buf), "%ld.%ld", first, second);
        if (len <= 0 || len >= OE_OID_MAX_LENGTH)
            goto done;

        strncat(oid_buf, tmp_buf, (size_t)len);
    }

    /*
     * Break the hex string into blocks, each of which represents a integer,
     * and then concatenate these integers into a dot-notation string.
     */
    while (index < oid_size)
    {
        long block = 0;
        byte = (unsigned char)oid[index++];
        /*
         * A block ends with a byte with bit 8 cleared. If the bit 8 is set,
         * appending the lower 7 bits of the byte into the current block.
         */
        while (byte & 0x80)
        {
            /*
             * Error out on the illegal 0x80 placement (i.e., at the beginning
             * of a block) to enforce unique OID encodings.
             */
            if (byte == 0x80 && block == 0)
                goto done;

            block <<= 7L;
            block |= byte & 0x7f;
            /*
             * Limit the value of a block to INT_MAX (align with OpenSSL
             * implementation). See ASN1_get_object in asn1_lib.c for the
             * reference.
             */
            if (block > (OE_INT_MAX >> 7L))
                goto done;

            if (index == oid_size)
                goto done;

            byte = (unsigned char)oid[index++];
        }

        /* Append the ending byte to the block. */
        block <<= 7L;
        block |= byte;

        len = snprintf(tmp_buf, sizeof(tmp_buf), ".%ld", block);
        if (len <= 0 || (strlen(oid_buf) + (size_t)len >= OE_OID_MAX_LENGTH))
            goto done;

        strncat(oid_buf, tmp_buf, (size_t)len);
    }

    /* Copy from buffer */
    size_t oid_len = strlen(oid_buf) + 1;
    oid_str = (char*)oe_malloc(oid_len);
    if (oid_str == NULL)
        goto done;

    strncpy(oid_str, oid_buf, oid_len);

done:
    return oid_str;
}

oe_result_t oe_gen_custom_x509_cert(
    oe_cert_config_t* config,
    unsigned char* cert_buf,
    size_t cert_buf_size,
    size_t* bytes_written)
{
    oe_result_t result = OE_CRYPTO_ERROR;
    X509* x509cert = NULL;
    X509V3_CTX ctx;
    BIO* bio = NULL;
    X509_NAME* name = NULL;
    EVP_PKEY* subject_issuer_key_pair = NULL;
    X509_EXTENSION* ext = NULL;
    ASN1_OBJECT* obj = NULL;
    ASN1_OCTET_STRING* data = NULL;
    BASIC_CONSTRAINTS* bc = NULL;
    unsigned char* buf = NULL;
    unsigned char* p = NULL;
    char* oid = NULL;
    char date_str[16];
    int len = 0;
    int ret = 0;

    x509cert = X509_new();
    subject_issuer_key_pair = EVP_PKEY_new();

    /* Allocate buffer for certificate */
    if ((buf = oe_malloc(cert_buf_size)) == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Set certificate info */

    /* Parse public key */
    bio = BIO_new_mem_buf(
        (const void*)config->public_key_buf, (int)config->public_key_buf_size);
    if (bio == NULL)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "bio = NULL");

    if (!PEM_read_bio_PUBKEY(bio, &subject_issuer_key_pair, NULL, NULL))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "subject_key read failed");

    OE_TRACE_VERBOSE(
        "custom_x509_cert: key type:%d",
        EVP_PKEY_base_id(subject_issuer_key_pair));

    BIO_free(bio);
    bio = NULL;

    /* Parse private key */
    bio = BIO_new_mem_buf(
        (const void*)config->private_key_buf,
        (int)config->private_key_buf_size);
    if (bio == NULL)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "bio = NULL");

    if (!PEM_read_bio_PrivateKey(bio, &subject_issuer_key_pair, NULL, NULL))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "issuer_key read failed");

    BIO_free(bio);
    bio = NULL;

    /* Set version to V3 */
    ret = X509_set_version(x509cert, 2);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set version failed");

    /* Set key */
    ret = X509_set_pubkey(x509cert, subject_issuer_key_pair);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set pubkey failed");

    /* Covert the subject string to X509_name struct */
    name = X509_parse_name((const char*)config->subject_name);
    if (!name)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "parse subject name failed");

    /* Set subject name */
    ret = X509_set_subject_name(x509cert, name);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set subject name failed");

    X509_NAME_free(name);
    name = NULL;

    /* Covert the issuer string to X509_name struct */
    name = X509_parse_name((const char*)config->issuer_name);
    if (!name)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "parse issuer name failed");

    /* Set issuer name */
    ret = X509_set_issuer_name(x509cert, name);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set issuer name failed");

    X509_NAME_free(name);
    name = NULL;

    /* Set serial number */
    ret = ASN1_INTEGER_set(X509_get_serialNumber(x509cert), 1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set serial number failed");

    /* Convert the format YYYYMMDDHHMMSS to YYYYMMDDHHMMSSZ */
    strncpy(date_str, (const char*)config->date_not_valid_before, 14);
    date_str[14] = 'Z';
    date_str[15] = '\0';

    /* Set validity start date */
    ret = ASN1_TIME_set_string(X509_getm_notBefore(x509cert), date_str);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set validity date not before failed");

    /* Convert the format YYYYMMDDHHMMSS to YYYYMMDDHHMMSSZ */
    strncpy(date_str, (const char*)config->date_not_valid_after, 14);
    date_str[14] = 'Z';
    date_str[15] = '\0';

    /* Set validity end date */
    ret = ASN1_TIME_set_string(X509_getm_notAfter(x509cert), date_str);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set validity date not after failed");

    /* Initialize the ctx. Required by X509V3_EXT_conf_nid. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Use the target as both issuer and subject for the self-signed
     * certificate. */
    X509V3_set_ctx(&ctx, x509cert, x509cert, NULL, NULL, 0);

    /* Set the basic constraints extention */
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (!ext)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "create basic constraint extension failed");

    ret = X509_add_ext(x509cert, ext, -1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "add basic constraint extension failed");

    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Set the subject key identifier extension */
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (!ext)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "create subject key identifier extension failed");

    ret = X509_add_ext(x509cert, ext, -1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "add basic constraint extension failed");

    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Set the authority key identifier extension */
    ext = X509V3_EXT_conf_nid(
        NULL, &ctx, NID_authority_key_identifier, "keyid:always");
    if (!ext)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "create subject key identifier extension failed");

    ret = X509_add_ext(x509cert, ext, -1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "add basic constraint extension failed");
    X509_EXTENSION_free(ext);
    ext = NULL;

    /* Set the custom extension */
    data = ASN1_OCTET_STRING_new();
    if (!data)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ASN1_OCTET_STRING_new failed");

    ret = ASN1_OCTET_STRING_set(
        data,
        (const unsigned char*)config->ext_data_buf,
        (int)config->ext_data_buf_size);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "set octet string failed");

    /*
     * By default, the config->oid_ext stores the OID in the encoded form
     * (BER-TLV) that can directly be consumed by Mbed TLS APIs. However,
     * OpenSSL APIs require the OID in the decoded form. Therefore, we need to
     * decode the OID first.
     */
    oid = decode_oid_to_str((char*)config->ext_oid, (int)config->ext_oid_size);
    if (!oid)
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "decode oid failed");

    obj = OBJ_txt2obj((char*)oid, 1);
    if (!obj)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "create custom extension obj failed");

    if (!X509_EXTENSION_create_by_OBJ(&ext, obj, 0, data))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "create custom extension failed");

    ret = X509_add_ext(x509cert, ext, -1);
    if (!ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "add custom extension failed");

    /* Sign the certificate */
    if (!X509_sign(x509cert, subject_issuer_key_pair, EVP_sha256()))
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "sign cert failed");

    /*
     * Write to DER
     * The use of temporary variable is mandatory.
     * If p is not NULL, the i2d_x509 function writes the DER encoded data to
     * the buffer at *p and increments p to point after the data just written.
     */
    p = buf;
    len = i2d_X509(x509cert, &p);
    if (len <= 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "i2d_X509 failed");

    *bytes_written = (size_t)len;

    /* Copy DER data to buffer */
    OE_CHECK(oe_memcpy_s(
        (void*)cert_buf, cert_buf_size, (const void*)buf, *bytes_written));
    OE_TRACE_VERBOSE("bytes_written = 0x%x", (unsigned int)*bytes_written);

    result = OE_OK;

done:
    if (x509cert)
        X509_free(x509cert);
    if (ext)
        X509_EXTENSION_free(ext);
    if (name)
        X509_NAME_free(name);
    if (bio)
        BIO_free(bio);
    if (obj)
        ASN1_OBJECT_free(obj);
    if (data)
        ASN1_OCTET_STRING_free(data);
    if (bc)
        BASIC_CONSTRAINTS_free(bc);
    if (subject_issuer_key_pair)
        EVP_PKEY_free(subject_issuer_key_pair);
    if (buf)
    {
        oe_free(buf);
        buf = NULL;
    }
    if (oid)
    {
        oe_free(oid);
        oid = NULL;
    }
    p = NULL;

    return result;
}
