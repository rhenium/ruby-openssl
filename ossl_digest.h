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
#if !defined(_OSSL_DIGEST_H_)
#define _OSSL_DIGEST_H_

extern VALUE mDigest;
extern VALUE cDigest;
extern VALUE eDigestError;

#define OSSLWrapDigest(klass, obj, ctx) do { \
	if (!ctx) { \
		rb_raise(rb_eRuntimeError, "Digest CTX wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(klass, 0, CRYPTO_free, ctx); \
} while (0)

#define OSSLGetDigest(obj, ctx) do { \
	OSSL_Check_Instance(obj, cDigest); \
	Data_Get_Struct(obj, EVP_MD_CTX, ctx); \
	if (!ctx) { \
		rb_raise(rb_eRuntimeError, "Digest CTX wasn't initialized!"); \
	} \
} while (0)

#define OSSLDigestValue(obj) OSSL_Check_Instance((obj), cDigest)

const EVP_MD *ossl_digest_get_EVP_MD(VALUE);
void Init_ossl_digest(void);

#endif /* _OSSL_DIGEST_H_ */

