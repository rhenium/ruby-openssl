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
VALUE
ossl_pkey_new(EVP_PKEY *key)
{
	if (!key)
		rb_raise(ePKeyError, "Empty key!");
	
	switch (key->type) {
		case EVP_PKEY_RSA:
			return ossl_rsa_new(key->pkey.rsa);
		case EVP_PKEY_DSA:
			return ossl_dsa_new(key->pkey.dsa);
	}
	
	rb_raise(ePKeyError, "unsupported key type");
	return Qnil;
}

VALUE
ossl_pkey_new_from_file(VALUE path)
{
	char *filename = NULL;
	FILE *fp = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE obj;

	filename = RSTRING(path)->ptr;
	if ((fp = fopen(filename, "r")) == NULL)
		rb_raise(ePKeyError, "%s", strerror(errno));
	/*
	 * Will we handle user passwords?
	 */
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!pkey)
		rb_raise(ePKeyError, "%s", ossl_error());

	obj = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return obj;
}

EVP_PKEY *
ossl_pkey_get_EVP_PKEY(VALUE obj)
{
	ossl_pkey *pkeyp = NULL;
	
	GetPKey(obj, pkeyp);

	return pkeyp->get_EVP_PKEY(obj);
}

/*
 * Private
 */
static VALUE
ossl_pkey_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_pkey *pkeyp = NULL;
	VALUE obj;
	
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
	ePKeyError = rb_define_class_under(module, "Error", rb_eStandardError);

	cPKey = rb_define_class_under(module, "ANY", rb_cObject);
	rb_define_singleton_method(cPKey, "new", ossl_pkey_s_new, -1);
	
	/*
	 * INIT rsa, dsa
	 */
	Init_ossl_rsa(module, cPKey, ePKeyError);
	Init_ossl_dsa(module, cPKey, ePKeyError);
	/*
	 * TODO:
	 * Init_ossl_dh(module, cPKey, ePKeyError);
	 */
}

