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
#include "ossl.h"
#include "ossl_pkey.h"

#define GetPKey(obj, pkeyp) {\
	Data_Get_Struct(obj, ossl_pkey, pkeyp);\
	if (!pkeyp->get_EVP_PKEY) rb_raise(ePKeyError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cPKey;
VALUE ePKeyError;

/*
 * Struct
 * see ossl_pkey.h
 */

/*
 * Public
 */
VALUE ossl_pkey_new(EVP_PKEY *key)
{
	if (!key)
		rb_raise(ePKeyError, "Empty key!");
	
	switch (key->type) {
		case EVP_PKEY_RSA:
			return ossl_rsa_new(key->pkey.rsa);
		case EVP_PKEY_DSA:
			return ossl_dsa_new(key->pkey.dsa);
	}
	/*
	 * Make it or not?
	 * EVP_PKEY_free(new_key);
	 */
	rb_raise(ePKeyError, "unsupported key type");
	return Qnil;
}

EVP_PKEY *ossl_pkey_get_EVP_PKEY(VALUE obj)
{
	ossl_pkey *pkeyp = NULL;
	
	GetPKey(obj, pkeyp);

	return pkeyp->get_EVP_PKEY(obj);
}

/*
 * Private
 */
static VALUE ossl_pkey_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_pkey *pkeyp = NULL;
	VALUE obj;
	
	if (klass == cPKey)
		rb_raise(rb_eNotImpError, "cannot do PKey.new - PKey is an abstract class");
	
	return Qnil;
}

void Init_ossl_pkey(VALUE mPKey)
{
	ePKeyError = rb_define_class_under(mPKey, "Error", rb_eStandardError);

	cPKey = rb_define_class_under(mPKey, "ANY", rb_cObject);
	rb_define_singleton_method(cPKey, "new", ossl_pkey_s_new, -1);
	
	Init_ossl_rsa(mPKey, cPKey, ePKeyError);
	Init_ossl_dsa(mPKey, cPKey, ePKeyError);
	/*
	 * TODO:
	 * Init_ossl_dh(mPKey, cPKey, ePKeyError);
	 */
}

