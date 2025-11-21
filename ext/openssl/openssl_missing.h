/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'COPYING'.)
 */
#if !defined(_OSSL_OPENSSL_MISSING_H_)
#define _OSSL_OPENSSL_MISSING_H_

#include "ruby/config.h"

/* added in 3.0.0 */
#ifndef HAVE_EVP_MD_CTX_GET0_MD
#  define EVP_MD_CTX_get0_md(ctx) EVP_MD_CTX_md(ctx)
#endif

/*
 * OpenSSL 1.1.0 added EVP_MD_CTX_pkey_ctx(), and then it was renamed to
 * EVP_MD_CTX_get_pkey_ctx(x) in OpenSSL 3.0.
 */
#ifndef HAVE_EVP_MD_CTX_GET_PKEY_CTX
#  define EVP_MD_CTX_get_pkey_ctx(x) EVP_MD_CTX_pkey_ctx(x)
#endif

#ifndef HAVE_EVP_PKEY_EQ
#  define EVP_PKEY_eq(a, b) EVP_PKEY_cmp(a, b)
#endif

/*
 * OpenSSL 4.0 made ASN1_STRING opaque. Accessors did not exist earlier
 * versions.
 */
#ifndef HAVE_ASN1_BIT_STRING_SET1
static inline int
ossl_ASN1_BIT_STRING_set1(ASN1_BIT_STRING *bstr, const unsigned char *data,
                          int len, int unused_bits)
{
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    if (ASN1_STRING_set(bstr, data, len) != 1)
        return 0;
    bstr->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07); /* clear */
    bstr->flags |= ASN1_STRING_FLAG_BITS_LEFT | unused_bits;
    return 1;
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
}
#define ASN1_BIT_STRING_set1 ossl_ASN1_BIT_STRING_set1
#endif

#endif /* _OSSL_OPENSSL_MISSING_H_ */
