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
		ossl_raise(ePKeyError, "Cannot make new key from NULL.");
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
			ossl_raise(ePKeyError, "unsupported key type");
	}
	return Qnil; /* not reached */
}

VALUE
ossl_pkey_new_from_file(VALUE filename)
{
	FILE *fp;
	EVP_PKEY *pkey;

	SafeStringValue(filename);
	
	if (!(fp = fopen(RSTRING(filename)->ptr, "r"))) {
		ossl_raise(ePKeyError, "%s", strerror(errno));
	}
	/*
	 * Will we handle user passwords?
	 */
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	
	if (!pkey) {
		ossl_raise(ePKeyError, "");
	}
	return ossl_pkey_new(pkey);
}

EVP_PKEY *
GetPKeyPtr(VALUE obj)
{
	EVP_PKEY *pkey;
	
	SafeGetPKey(obj, pkey);

	return pkey;
}

EVP_PKEY *
GetPrivPKeyPtr(VALUE obj)
{
	EVP_PKEY *pkey;
	
	SafeGetPKey(obj, pkey);

	if (rb_funcall(obj, id_private_q, 0, NULL) != Qtrue) { /* returns Qtrue */
		ossl_raise(rb_eArgError, "Private key is needed.");
	}
	return pkey;
}

EVP_PKEY *
DupPrivPKeyPtr(VALUE obj)
{
	EVP_PKEY *pkey;
	
	SafeGetPKey(obj, pkey);

	if (rb_funcall(obj, id_private_q, 0, NULL) != Qtrue) { /* returns Qtrue */
		ossl_raise(rb_eArgError, "Private key is needed.");
	}
	CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);

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
		ossl_raise(ePKeyError, "");
	}
	WrapPKey(klass, obj, pkey);
	
	return obj;
}

static VALUE
ossl_pkey_initialize(VALUE self)
{
	if (rb_obj_is_instance_of(self, cPKey)) {
		ossl_raise(rb_eNotImpError, "OpenSSL::PKey::PKey is an abstract class.");
	}
	return self;
}

static VALUE
ossl_pkey_to_der(VALUE self)
{
	EVP_PKEY *pkey;
	X509_PUBKEY *key;
	VALUE str;
	
	GetPKey(self, pkey);
	
	if (!(key = X509_PUBKEY_new())) {
		ossl_raise(ePKeyError, "");
	}
	if (!X509_PUBKEY_set(&key, pkey)) {
		X509_PUBKEY_free(key);
		ossl_raise(ePKeyError, "");
	}
	str = rb_str_new(key->public_key->data, key->public_key->length);
	X509_PUBKEY_free(key);

	return str;
}

static VALUE
ossl_pkey_sign(VALUE self, VALUE digest, VALUE data)
{
	EVP_PKEY *pkey;
	EVP_MD_CTX ctx;
	char *buf;
	int buf_len;
	VALUE str;

	GetPKey(self, pkey);
	
	if (rb_funcall(self, id_private_q, 0, NULL) != Qtrue) {
		ossl_raise(rb_eArgError, "Private key is needed.");
	}
	EVP_SignInit(&ctx, GetDigestPtr(digest));
	
	StringValue(data);
	
	EVP_SignUpdate(&ctx, RSTRING(data)->ptr, RSTRING(data)->len);
	
	if (!(buf = OPENSSL_malloc(EVP_PKEY_size(pkey) + 16))) {
		ossl_raise(ePKeyError, "");
	}
	if (!EVP_SignFinal(&ctx, buf, &buf_len, pkey)) {
		OPENSSL_free(buf);
		ossl_raise(ePKeyError, "");
	}	
	str = rb_str_new(buf, buf_len);
	OPENSSL_free(buf);

	return str;
}

static VALUE
ossl_pkey_verify(VALUE self, VALUE digest, VALUE sig, VALUE data)
{
	EVP_PKEY *pkey;
	EVP_MD_CTX ctx;
	int result;

	GetPKey(self, pkey);

	EVP_VerifyInit(&ctx, GetDigestPtr(digest));
	
	StringValue(sig);
	StringValue(data);
	
	EVP_VerifyUpdate(&ctx, RSTRING(data)->ptr, RSTRING(data)->len);
	
	if ((result = EVP_VerifyFinal(&ctx, RSTRING(sig)->ptr, RSTRING(sig)->len, pkey)) < 0) {
		ossl_raise(ePKeyError, "");
	}
	if (result == 1) {
		return Qtrue;
	}
	return Qfalse;
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
	rb_define_method(cPKey, "sign", ossl_pkey_sign, 2);
	rb_define_method(cPKey, "verify", ossl_pkey_verify, 3);
	
	id_private_q = rb_intern("private?");
	
	/*
	 * INIT rsa, dsa
	 */
	Init_ossl_rsa();
	Init_ossl_dsa();
	Init_ossl_dh();
}

