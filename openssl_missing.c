/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */

#if !defined(OPENSSL_NO_HMAC)
#include <string.h> /* memcpy() */
#include <openssl/hmac.h>

#if !defined(HAVE_HMAC_CTX_COPY)
int
HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in)
{
    if (!out || !in) {
	/* HMACerr(HMAC_CTX_COPY,HMAC_R_INPUT_NOT_INITIALIZED); */
	return 0;
    }
    memcpy(out, in, sizeof(HMAC_CTX));

    if (!EVP_MD_CTX_copy(&out->md_ctx, &in->md_ctx)) {
	return 0;
    }
    if (!EVP_MD_CTX_copy(&out->i_ctx, &in->i_ctx)) {
	return 0;
    }
    if (!EVP_MD_CTX_copy(&out->o_ctx, &in->o_ctx)) {
	return 0;
    }
    return 1;
}
#endif /* HAVE_HMAC_CTX_COPY */

#endif /* NO_HMAC */

#if !defined(HAVE_X509_STORE_SET_EX_DATA)
#include <openssl/x509_vfy.h>

int X509_STORE_set_ex_data(X509_STORE *str, int idx, void *data)
{
    return CRYPTO_set_ex_data(&str->ex_data,idx,data);
}
 
void *X509_STORE_get_ex_data(X509_STORE *str, int idx)
{
    return CRYPTO_get_ex_data(&str->ex_data,idx);
}
#endif /* HAVE_X509_STORE_SET_EX_DATA */
