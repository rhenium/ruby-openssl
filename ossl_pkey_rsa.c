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
#if !defined(OPENSSL_NO_RSA)

#include "ossl.h"

#define GetPKeyRSA(obj, pkey) do { \
	GetPKey(obj, pkey); \
	if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) { /* PARANOIA? */ \
		rb_raise(rb_eRuntimeError, "THIS IS NOT A RSA!") ; \
	} \
} while (0)

#define RSA_PRIVATE(rsa) ((rsa)->p && (rsa)->q)

/*
 * Classes
 */
VALUE cRSA;
VALUE eRSAError;

/*
 * Public
 */
static VALUE
rsa_instance(VALUE klass, RSA *rsa)
{
	EVP_PKEY *pkey;
	VALUE obj;
	
	if (!rsa) {
		return Qfalse;
	}
	if (!(pkey = EVP_PKEY_new())) {
		return Qfalse;
	}
	if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
		EVP_PKEY_free(pkey);
		return Qfalse;
	}
	WrapPKey(klass, obj, pkey);
	
	return obj;
}

VALUE
ossl_rsa_new(EVP_PKEY *pkey)
{
	VALUE obj;

	if (!pkey) {
		obj = rsa_instance(cRSA, RSA_new());
	} else {
		if (EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
			rb_raise(rb_eTypeError, "Not a RSA key!");
		}
		WrapPKey(cRSA, obj, pkey);
	}
	if (obj == Qfalse) {
		OSSL_Raise(eRSAError, "");
	}
	return obj;
}

/*
 * Private
 */
/*
 * CB for yielding when generating RSA data
 */
static void
ossl_rsa_generate_cb(int p, int n, void *arg)
{
	VALUE ary;

	ary = rb_ary_new2(2);
	rb_ary_store(ary, 0, INT2NUM(p));
	rb_ary_store(ary, 1, INT2NUM(n));
	
	rb_yield(ary);
}

static RSA *
rsa_generate(int size)
{
	void (*cb)(int, int, void *) = NULL;
	
	if (rb_block_given_p()) {
		cb = ossl_rsa_generate_cb;
	}

	return RSA_generate_key(size, RSA_F4, cb, NULL);
}

static VALUE
ossl_rsa_s_generate(VALUE klass, VALUE size)
{
	RSA *rsa = rsa_generate(FIX2INT(size)); /* err handled by rsa_instance */
	VALUE obj = rsa_instance(klass, rsa);

	if (obj == Qfalse) {
		RSA_free(rsa);
		OSSL_Raise(eRSAError, "");
	}
	return obj;
}

static VALUE
ossl_rsa_initialize(int argc, VALUE *argv, VALUE self)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	BIO *in;
	char *passwd = NULL;
	VALUE buffer, pass;
	
	GetPKey(self, pkey);
	
	rb_scan_args(argc, argv, "11", &buffer, &pass);

	if (FIXNUM_P(buffer)) {
		if (!(rsa = rsa_generate(FIX2INT(buffer)))) {
			OSSL_Raise(eRSAError, "");
		}
	} else {
		StringValue(buffer);

		if (!NIL_P(pass)) {
			passwd = StringValuePtr(pass);
		}
		if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, RSTRING(buffer)->len))) {
			OSSL_Raise(eRSAError, "");
		}
		if (!(rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL))) {
			BIO_reset(in);

			if (!(rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, passwd))) {
				BIO_free(in);
				OSSL_Raise(eRSAError, "Neither PUB key nor PRIV key:");
			}
		}
		BIO_free(in);
	}
	if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
		RSA_free(rsa);
		OSSL_Raise(eRSAError, "");
	}
	return self;
}

static VALUE
ossl_rsa_is_public(VALUE self)
{
	EVP_PKEY *pkey;

	GetPKeyRSA(self, pkey);
	
	/*
	 * SURPRISE! :-))
	 * Every key is public at the same time!
	 */
	return Qtrue;
}

static VALUE
ossl_rsa_is_private(VALUE self)
{
	EVP_PKEY *pkey;
	
	GetPKeyRSA(self, pkey);
	
	return (RSA_PRIVATE(pkey->pkey.rsa)) ? Qtrue : Qfalse;
}

static VALUE
ossl_rsa_export(int argc, VALUE *argv, VALUE self)
{
	EVP_PKEY *pkey;
	BIO *out;
	BUF_MEM *buf;
	const EVP_CIPHER *ciph = NULL;
	char *passwd = NULL;
	VALUE cipher, pass, str;

	GetPKeyRSA(self, pkey);

	rb_scan_args(argc, argv, "02", &cipher, &pass);

	if (!NIL_P(cipher)) {
		ciph = ossl_cipher_get_EVP_CIPHER(cipher);
		
		if (!NIL_P(pass)) {
			passwd = StringValuePtr(pass);
		}
	}
	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eRSAError, "");
	}
	if (RSA_PRIVATE(pkey->pkey.rsa)) {
		if (!PEM_write_bio_RSAPrivateKey(out, pkey->pkey.rsa, ciph, NULL, 0, NULL, passwd)) {
			BIO_free(out);
			OSSL_Raise(eRSAError, "");
		}
	} else {
		if (!PEM_write_bio_RSAPublicKey(out, pkey->pkey.rsa)) {
			BIO_free(out);
			OSSL_Raise(eRSAError, "");
		}
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE
ossl_rsa_public_encrypt(VALUE self, VALUE buffer)
{
	EVP_PKEY *pkey;
	char *buf;
	int buf_len;
	VALUE str;
	
	GetPKeyRSA(self, pkey);

	StringValue(buffer);
	
	if (!(buf = OPENSSL_malloc(RSA_size(pkey->pkey.rsa) + 16))) {
		OSSL_Raise(eRSAError, "");
	}
	if ((buf_len = RSA_public_encrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, buf, pkey->pkey.rsa, RSA_PKCS1_PADDING)) < 0) {
		OPENSSL_free(buf);
		OSSL_Raise(eRSAError, "");
	}
	str = rb_str_new(buf, buf_len);
	OPENSSL_free(buf);

	return str;
}

static VALUE
ossl_rsa_public_decrypt(VALUE self, VALUE buffer)
{
	EVP_PKEY *pkey;
	char *buf;
	int buf_len;
	VALUE str;

	GetPKeyRSA(self, pkey);

	StringValue(buffer);
	
	if (!(buf = OPENSSL_malloc(RSA_size(pkey->pkey.rsa) + 16))) {
		OSSL_Raise(eRSAError, "");
	}
	if ((buf_len = RSA_public_decrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, buf, pkey->pkey.rsa, RSA_PKCS1_PADDING)) < 0) {
		OPENSSL_free(buf);
		OSSL_Raise(eRSAError, "");
	}
	str = rb_str_new(buf, buf_len);
	OPENSSL_free(buf);

	return str;
}

static VALUE
ossl_rsa_private_encrypt(VALUE self, VALUE buffer)
{
	EVP_PKEY *pkey;
	char *buf;
	int buf_len;
	VALUE str;
	
	GetPKeyRSA(self, pkey);

	if (!RSA_PRIVATE(pkey->pkey.rsa)) {
		rb_raise(eRSAError, "PRIVATE key needed for this operation!");
	}
	
	StringValue(buffer);
	
	if (!(buf = OPENSSL_malloc(RSA_size(pkey->pkey.rsa) + 16))) {
		OSSL_Raise(eRSAError, "Memory alloc error");
	}
	if ((buf_len = RSA_private_encrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, buf, pkey->pkey.rsa, RSA_PKCS1_PADDING)) < 0) {
		OPENSSL_free(buf);
		OSSL_Raise(eRSAError, "");
	}
	str = rb_str_new(buf, buf_len);
	OPENSSL_free(buf);

	return str;
}

static VALUE
ossl_rsa_private_decrypt(VALUE self, VALUE buffer)
{
	EVP_PKEY *pkey;
	char *buf;
	int buf_len;
	VALUE str;

	GetPKeyRSA(self, pkey);

	if (!RSA_PRIVATE(pkey->pkey.rsa)) {
		rb_raise(eRSAError, "Private RSA key needed!");
	}

	StringValue(buffer);
	
	if (!(buf = OPENSSL_malloc(RSA_size(pkey->pkey.rsa) + 16))) {
		OSSL_Raise(eRSAError, "Memory alloc error");
	}
	if ((buf_len = RSA_private_decrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, buf, pkey->pkey.rsa, RSA_PKCS1_PADDING)) < 0) {
		OPENSSL_free(buf);
		OSSL_Raise(eRSAError, "");
	}
	str = rb_str_new(buf, buf_len);
	OPENSSL_free(buf);

	return str;
}

/*
 * Just sample
 * (it's not (maybe) wise to show private RSA values)
 * - if, then implement this via OpenSSL::BN
 *   
static VALUE
ossl_rsa_get_n(VALUE self)
{
	ossl_rsa *rsap = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE num;

	GetRSA(self, rsap);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eRSAError, "");
	}
	if (!BN_print(out, rsap->rsa->n)) {
		BIO_free(out);
		OSSL_Raise(eRSAError, "");
	}
	
	BIO_get_mem_ptr(out, &buf);
	num = rb_cstr2inum(buf->data, 16);
	BIO_free(out);

	return num;
}
 */

/*
 * Prints all parameters of key to buffer
 * INSECURE: PRIVATE INFORMATIONS CAN LEAK OUT!!!
 * Don't use :-)) (I's up to you)
 */
static VALUE
ossl_rsa_to_text(VALUE self)
{
	EVP_PKEY *pkey;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;

	GetPKeyRSA(self, pkey);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eRSAError, "");
	}
	if (!RSA_print(out, pkey->pkey.rsa, 0)) { //offset = 0
		BIO_free(out);
		OSSL_Raise(eRSAError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);

	return str;
}

/*
 * Makes new instance RSA PUBLIC_KEY from PRIVATE_KEY
 */
static VALUE
ossl_rsa_to_public_key(VALUE self)
{
	EVP_PKEY *pkey;
	RSA *rsa;
	VALUE obj;
	
	GetPKeyRSA(self, pkey);

	rsa = RSAPublicKey_dup(pkey->pkey.rsa); /* err check performed by rsa_instance */
	obj = rsa_instance(CLASS_OF(self), rsa);

	if (obj == Qfalse) {
		RSA_free(rsa);
		OSSL_Raise(eRSAError, "");
	}
	return obj;
}

/*
 * Better to implement is in Ruby space?
 * 
static VALUE
ossl_rsa_sign(VALUE self, VALUE digest, VALUE text)
{
	ossl_rsa *rsap = NULL;
	EVP_MD_CTX ctx;
	const EVP_MD *md = NULL;
	char *sign = NULL;
	int sign_len = 0;
	VALUE str;

	GetRSA(self, rsap);
	OSSL_Check_type(digest, cDigest);
	text = rb_String(text);

	if (!(sign = OPENSSL_malloc(RSA_size(rsap->rsa)+16))) {
		OSSL_Raise(eRSAError, "");
	}

	md = ossl_digest_get_EVP_MD(digest);
	EVP_SignInit(&ctx, md);
	EVP_SignUpdate(&ctx, RSTRING(text)->ptr, RSTRING(text)->len);
	if (!EVP_SignFinal(&ctx, sign, &sign_len, pkeyp->key)) {
		OPENSSL_free(sign);
		OSSL_Raise(eRSAError, "");
	}
	
	str = rb_str_new(sign, sign_len);
	OPENSSL_free(sign);

	return str;
}
	
static VALUE
ossl_rsa_verify(VALUE self, VALUE digest, VALUE text)
{
}
 */

/*
 * INIT
 */
void
Init_ossl_rsa()
{
	eRSAError = rb_define_class_under(mPKey, "RSAError", ePKeyError);

	cRSA = rb_define_class_under(mPKey, "RSA", cPKey);

	rb_define_singleton_method(cRSA, "generate", ossl_rsa_s_generate, 1);
	rb_define_method(cRSA, "initialize", ossl_rsa_initialize, -1);
	
	rb_define_method(cRSA, "public?", ossl_rsa_is_public, 0);
	rb_define_method(cRSA, "private?", ossl_rsa_is_private, 0);
	rb_define_method(cRSA, "to_text", ossl_rsa_to_text, 0);
	rb_define_method(cRSA, "export", ossl_rsa_export, -1);
	rb_define_alias(cRSA, "to_pem", "export");
	rb_define_method(cRSA, "public_key", ossl_rsa_to_public_key, 0);
	rb_define_method(cRSA, "public_encrypt", ossl_rsa_public_encrypt, 1);
	rb_define_method(cRSA, "public_decrypt", ossl_rsa_public_decrypt, 1);
	rb_define_method(cRSA, "private_encrypt", ossl_rsa_private_encrypt, 1);
	rb_define_method(cRSA, "private_decrypt", ossl_rsa_private_decrypt, 1);
	/*rb_define_method(cRSA, "n", ossl_rsa_get_n, 0);*/
/*
 * Implemented in Ruby space...
 * 
	rb_define_method(cRSA, "sign", ossl_rsa_sign, 2);
	rb_define_method(cRSA, "verify", ossl_rsa_verify, 3);
 */
}

#else /* defined NO_RSA */
#  warning >>> OpenSSL is compiled without RSA support <<<

void
Init_ossl_rsa()
{
	rb_warning("OpenSSL is compiled without RSA support");
}

#endif /* NO_RSA */

