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
EVP_PKEY *GetPKeyPtr(VALUE);
/*EVP_PKEY *DupPKeyPtr(VALUE);*/
EVP_PKEY *GetPrivPKeyPtr(VALUE);
EVP_PKEY *DupPrivPKeyPtr(VALUE);
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

#define OSSL_PKEY_BN(type,  name)					\
static VALUE ossl_##type##_get_##name##(VALUE self)			\
{									\
	EVP_PKEY *pkey;							\
	BIGNUM *bn;							\
									\
	GetPKey(self, pkey);						\
	bn = pkey->pkey.##type##->##name;				\
	if (bn == NULL)							\
		return Qnil;						\
	return ossl_bn_new(bn);						\
}									\
static VALUE ossl_##type##_set_##name##(VALUE self, VALUE bignum)	\
{									\
	EVP_PKEY *pkey;							\
	BIGNUM *bn, *newbn;						\
									\
	GetPKey(self, pkey);						\
	if (NIL_P(bignum)) {						\
		BN_clear_free(pkey->pkey.##type##->##name##);		\
		pkey->pkey.##type##->##name## = NULL;			\
		return Qnil;						\
	}								\
									\
	bn = GetBNPtr(bignum);						\
	if (pkey->pkey.##type##->##name## == NULL)			\
		pkey->pkey.##type##->##name## = BN_new();		\
	if (pkey->pkey.##type##->##name## == NULL)			\
		ossl_raise(eBNError, "");				\
	if (BN_copy(pkey->pkey.##type##->##name##, bn) == NULL)		\
		ossl_raise(eBNError, "");				\
	return bignum;							\
}

#define DEF_OSSL_PKEY_BN(class, type, name)				\
do {									\
	rb_define_method(class, #name, ossl_##type##_get_##name##, 0);	\
	rb_define_method(class, #name "=", ossl_##type##_set_##name##, 1);	\
} while (0)

#endif /* _OSSL_PKEY_H_ */

