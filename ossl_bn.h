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
#if !defined(_OSSL_BN_H_)
#define _OSSL_BN_H_

extern VALUE cBN;
extern VALUE eBNError;

#define OSSLWrapBN(obj, bn) do { \
	if (!bn) { \
		rb_raise(rb_eRuntimeError, "BN wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(cBN, 0, BN_clear_free, bn); \
} while (0)

#define OSSLGetBN(obj, bn) do { \
	OSSL_Check_Instance(obj, cBN); \
	Data_Get_Struct(obj, BIGNUM, bn); \
	if (!bn) { \
		rb_raise(rb_eRuntimeError, "BN wasn't initialized!"); \
	} \
} while (0)

#define OSSLBNValue(obj) OSSL_Check_Instance((obj), cBN)
#define OSSLBNValuePtr(obj) ossl_bn_get_BIGNUM((obj))

VALUE ossl_bn_new(BIGNUM *);
BIGNUM *ossl_bn_get_BIGNUM(VALUE);
void Init_ossl_bn(void);

#endif /* _OSS_BN_H_ */

