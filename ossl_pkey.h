/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_PKEY_H_)
#define _OSSL_PKEY_H_

extern VALUE mPKey;
extern VALUE cPKey;
extern VALUE ePKeyError;
extern ID id_private_q;

#define WrapPKey(klass, obj, pkey) do { \
	if (!pkey) { \
		rb_raise(rb_eRuntimeError, "PKEY wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(klass, 0, EVP_PKEY_free, pkey); \
} while (0)
#define GetPKey(obj, pkey) do {\
	Data_Get_Struct(obj, EVP_PKEY, pkey);\
	if (!pkey) { \
		rb_raise(rb_eRuntimeError, "PKEY wasn't initialized!");\
	} \
} while (0)
#define SafeGetPKey(obj, pkey) do { \
	OSSL_Check_Kind(obj, cPKey); \
	GetPKey(obj, pkey); \
} while (0)

VALUE ossl_pkey_new(EVP_PKEY *);
VALUE ossl_pkey_new_from_file(VALUE);
EVP_PKEY *ossl_pkey_get_EVP_PKEY(VALUE);
EVP_PKEY *ossl_pkey_get_private_EVP_PKEY(VALUE);
void Init_ossl_pkey(void);

/*
 * RSA
 */
extern VALUE cRSA;
extern VALUE eRSAError;

VALUE ossl_rsa_new(EVP_PKEY *);
void Init_ossl_rsa();

/*
 * DSA
 */
extern VALUE cDSA;
extern VALUE eDSAError;

VALUE ossl_dsa_new(EVP_PKEY *);
void Init_ossl_dsa();

/*
 * DH
 */
extern VALUE cDH;
extern VALUE eDHError;

VALUE ossl_dh_new(EVP_PKEY *);
void Init_ossl_dh();

#endif /* _OSSL_PKEY_H_ */

