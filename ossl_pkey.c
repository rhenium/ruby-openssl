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
#include "ossl.h"
#include "ossl_pkey.h"

#define GetPKey(obj, pkeyp) do {\
	Data_Get_Struct(obj, ossl_pkey, pkeyp);\
	if (!pkeyp->get_EVP_PKEY) rb_raise(ePKeyError, "not initialized!");\
} while (0)

/*
 * Classes
 */
ID id_private_q;
VALUE cPKey;
VALUE ePKeyError;

/*
 * Struct
 * see ossl_pkey.h
 */

/*
 * Public
 */
VALUE
ossl_pkey_new(EVP_PKEY *key)
{
	if (!key)
		rb_raise(ePKeyError, "Cannot make new key from NULL.");
	
	switch (key->type) {
#if !defined(OPENSSL_NO_RSA)
		case EVP_PKEY_RSA:
			return ossl_rsa_new(key->pkey.rsa);
#endif
#if !defined(OPENSSL_NO_DSA)
		case EVP_PKEY_DSA:
			return ossl_dsa_new(key->pkey.dsa);
#endif
#if !defined(OPENSSL_NO_DH)
		case EVP_PKEY_DH:
			return ossl_dh_new(key->pkey.dh);
#endif
	}
	
	rb_raise(ePKeyError, "unsupported key type");
	return Qnil;
}

VALUE
ossl_pkey_new_from_file(VALUE filename)
{
	FILE *fp = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE obj;

	filename = rb_str_to_str(filename);
	Check_SafeStr(filename);
	
	if ((fp = fopen(RSTRING(filename)->ptr, "r")) == NULL)
		rb_raise(ePKeyError, "%s", strerror(errno));

	/*
	 * MR:
	 * How about PublicKeys from file?
	 * pkey = PEM_read_PublicKey(fp, NULL, NULL, NULL);
	 * MISSING IN OPENSSL
	 */
	/*
	 * Will we handle user passwords?
	 */
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	
	if (!pkey)
		OSSL_Raise(ePKeyError, "");

	obj = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return obj;
}

EVP_PKEY *
ossl_pkey_get_EVP_PKEY(VALUE obj)
{
	ossl_pkey *pkeyp = NULL;
	
	OSSL_Check_Type(obj, cPKey);

	GetPKey(obj, pkeyp);

	return pkeyp->get_EVP_PKEY(obj);
}

/*
 * Private
 */
static VALUE
ossl_pkey_s_new(int argc, VALUE *argv, VALUE klass)
{
	if (klass == cPKey)
		rb_raise(rb_eNotImpError, "cannot do PKey::ANY.new - it is an abstract class");
	
	return Qnil;
}

/*
 * INIT
 */
void
Init_ossl_pkey(VALUE module)
{
	id_private_q = rb_intern("private?");
	
	ePKeyError = rb_define_class_under(module, "PKeyError", eOSSLError);

	cPKey = rb_define_class_under(module, "ANY", rb_cObject);
	rb_define_singleton_method(cPKey, "new", ossl_pkey_s_new, -1);
	
	/*
	 * INIT rsa, dsa
	 */
	Init_ossl_rsa(module, cPKey, ePKeyError);
	Init_ossl_dsa(module, cPKey, ePKeyError);
	Init_ossl_dh(module, cPKey, ePKeyError);
}

