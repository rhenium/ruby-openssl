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

/*
 * Classes
 */
VALUE mPKey;
VALUE cPKey;
VALUE ePKeyError;
ID id_private_q;

/*
 * Public
 */
VALUE
ossl_pkey_new(EVP_PKEY *pkey)
{
	if (!pkey) {
		rb_raise(ePKeyError, "Cannot make new key from NULL.");
	}
	switch (EVP_PKEY_type(pkey->type)) {
#if !defined(OPENSSL_NO_RSA)
		case EVP_PKEY_RSA:
			return ossl_rsa_new(pkey);
#endif
#if !defined(OPENSSL_NO_DSA)
		case EVP_PKEY_DSA:
			return ossl_dsa_new(pkey);
#endif
#if !defined(OPENSSL_NO_DH)
		case EVP_PKEY_DH:
			return ossl_dh_new(pkey);
#endif
		default:
			rb_raise(ePKeyError, "unsupported key type");
	}
	return Qnil; /* not reached */
}

VALUE
ossl_pkey_new_from_file(VALUE filename)
{
	FILE *fp;
	EVP_PKEY *pkey;
	VALUE obj;

	SafeStringValue(filename);
	
	if (!(fp = fopen(StringValuePtr(filename), "r"))) {
		rb_raise(ePKeyError, "%s", strerror(errno));
	}
	/*
	 * Will we handle user passwords?
	 */
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	
	if (!pkey) {
		OSSL_Raise(ePKeyError, "");
	}
	obj = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return obj;
}

EVP_PKEY *
ossl_pkey_get_EVP_PKEY(VALUE obj)
{
	EVP_PKEY *pkey;
	
	SafeGetPKey(obj, pkey);

	obj = ossl_pkey_new(pkey);
	
	GetPKey(obj, pkey);
	DATA_PTR(obj) = NULL; /* Don't let GC to discard pkey! */
	
	return pkey;
}

/*
 * Private
 */
static VALUE
ossl_pkey_s_allocate(VALUE klass)
{
	EVP_PKEY *pkey;
	VALUE obj;

	if (!(pkey = EVP_PKEY_new())) {
		OSSL_Raise(ePKeyError, "");
	}
	WrapPKey(klass, obj, pkey);
	
	return obj;
}

static VALUE
ossl_pkey_initialize(VALUE self)
{
	if (rb_obj_is_instance_of(self, cPKey)) {
		rb_raise(rb_eNotImpError, "OpenSSL::PKey::PKey is an abstract class.");
	}
	return self;
}

static VALUE
ossl_pkey_to_der(VALUE self)
{
	EVP_PKEY *pkey = NULL;
	X509_PUBKEY *key = NULL;
	VALUE str;
	
	GetPKey(self, pkey);
	
	if (!(key = X509_PUBKEY_new())) {
		OSSL_Raise(ePKeyError, "");
	}
	if (!X509_PUBKEY_set(&key, pkey)) {
		X509_PUBKEY_free(key);
		OSSL_Raise(ePKeyError, "");
	}

	str = rb_str_new(key->public_key->data, key->public_key->length);
	X509_PUBKEY_free(key);

	return str;
}

/*
 * INIT
 */
void
Init_ossl_pkey()
{
	mPKey = rb_define_module_under(mOSSL, "PKey");
	
	ePKeyError = rb_define_class_under(mPKey, "PKeyError", eOSSLError);

	cPKey = rb_define_class_under(mPKey, "PKey", rb_cObject);
	
	rb_define_singleton_method(cPKey, "allocate", ossl_pkey_s_allocate, 0);
	rb_define_method(cPKey, "initialize", ossl_pkey_initialize, 0);

	rb_define_method(cPKey, "to_der", ossl_pkey_to_der, 0);
	
	id_private_q = rb_intern("private?");
	
	/*
	 * INIT rsa, dsa
	 */
	Init_ossl_rsa();
	Init_ossl_dsa();
	Init_ossl_dh();
}

