/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"
#include "ossl_pkey.h"

#define MakeRSA(obj, rsap) {\
	obj = Data_Make_Struct(cRSA, ossl_rsa, 0, ossl_rsa_free, rsap);\
	rsap->pkey.get_EVP_PKEY = ossl_rsa_get_EVP_PKEY;\
}

#define GetRSA_unsafe(obj, rsap) Data_Get_Struct(obj, ossl_rsa, rsap)

#define GetRSA(obj, rsap) {\
	GetRSA_unsafe(obj, rsap);\
	if (!rsap->rsa) rb_raise(eRSAError, "not initialized!");\
}

#define RSA_PRIVATE(rsa) ((rsa)->p && (rsa)->q)

/*
 * Classes
 */
VALUE cRSA;
VALUE eRSAError;

/*
 * Struct
 */
typedef struct ossl_rsa_st {
	ossl_pkey pkey;
	RSA *rsa;
} ossl_rsa;

static void ossl_rsa_free(ossl_rsa *rsap)
{
	if (rsap) {
		if (rsap->rsa) RSA_free(rsap->rsa);
		rsap->rsa = NULL;
		free(rsap);
	}
}

/*
 * Public
 */
VALUE ossl_rsa_new_null()
{
	ossl_rsa *rsap = NULL;
	VALUE obj;
	
	MakeRSA(obj, rsap);
	
	if (!(rsap->rsa = RSA_new())) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	return obj;
}

VALUE ossl_rsa_new(RSA *rsa)
{
	ossl_rsa *rsap = NULL;
	VALUE obj;

	if (!rsa)
		return ossl_rsa_new_null();
	
	MakeRSA(obj, rsap);
	
	rsap->rsa = (RSA_PRIVATE(rsa)) ? RSAPrivateKey_dup(rsa) : RSAPublicKey_dup(rsa);
	if (!rsap->rsa) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	
	return obj;
}

RSA *ossl_rsa_get_RSA(VALUE obj)
{
	ossl_rsa *rsap = NULL;
	RSA *rsa = NULL;
	
	GetRSA(obj, rsap);

	rsa = (RSA_PRIVATE(rsap->rsa)) ? RSAPrivateKey_dup(rsap->rsa) : RSAPublicKey_dup(rsap->rsa);
	if (!rsa) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	
	return rsa;
}

EVP_PKEY *ossl_rsa_get_EVP_PKEY(VALUE obj)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;

	rsa = ossl_rsa_get_RSA(obj);

	if (!(pkey = EVP_PKEY_new())) {
		RSA_free(rsa);
		rb_raise(eRSAError, "%s", ossl_error());
	}

	if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
		RSA_free(rsa);
		rb_raise(eRSAError, "%s", ossl_error());
	}

	return pkey;
}

/*
 * Private
 */
static VALUE ossl_rsa_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_rsa *rsap = NULL;
	VALUE obj;
	
	MakeRSA(obj, rsap);

	rb_obj_call_init(obj, argc, argv);
	return obj;
}

/*
 * CB for yielding when generating RSA data
 */
static void ossl_rsa_generate_cb(int p, int n, void *arg)
{
	VALUE ary;

	ary = rb_ary_new2(2);
	rb_ary_store(ary, 0, INT2NUM(p));
	rb_ary_store(ary, 1, INT2NUM(n));
	
	rb_yield(ary);
}

static VALUE ossl_rsa_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_rsa *rsap = NULL;
	RSA *rsa = NULL;
	int type = 0;
	BIO *in = NULL;
	char *passwd = NULL;
	void (*cb)() = NULL;
	VALUE buffer, pass;
	
	GetRSA_unsafe(self, rsap);

	rb_scan_args(argc, argv, "02", &buffer, &pass);
	
	if (NIL_P(buffer)) {
		if (!(rsa = RSA_new())) {
			rb_raise(eRSAError, "%s", ossl_error());
		}
	} else switch (TYPE(buffer)) {
		case T_FIXNUM:
			if (rb_block_given_p())
				cb = ossl_rsa_generate_cb;
			if (!(rsa = RSA_generate_key(FIX2INT(buffer), RSA_F4, cb, NULL))) { /* arg to cb = NULL */
				rb_raise(eRSAError, "%s", ossl_error());
			}
			break;
		case T_STRING:
			Check_SafeStr(buffer);
			if (NIL_P(pass))
				passwd = NULL;
			else {
				pass = rb_str_to_str(pass);
				Check_SafeStr(pass);
				passwd = RSTRING(pass)->ptr;
			}
			if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, -1))) {
				rb_raise(eRSAError, "%s", ossl_error());
			}
			if (!(rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL))) {
				BIO_free(in);
				if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, -1))) {
					rb_raise(eRSAError, "%s", ossl_error());
				}
				if (!(rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, passwd))) {
					BIO_free(in);
					rb_raise(eRSAError, "%s", ossl_error());
				}
			}
			BIO_free(in);
			break;
		default:
			rb_raise(eRSAError, "unsupported argument (%s)", rb_class2name(CLASS_OF(buffer)));
	}
	rsap->rsa = rsa;
	
	return self;
}

static VALUE ossl_rsa_is_public(VALUE self)
{
	ossl_rsa *rsap = NULL;

	GetRSA(self, rsap);
	
	/*
	 * SURPRISE! :-))
	 * Every key is public at the same time!
	 */
	return Qtrue;
}

static VALUE ossl_rsa_is_private(VALUE self)
{
	ossl_rsa *rsap = NULL;
	
	GetRSA(self, rsap);
	
	return (RSA_PRIVATE(rsap->rsa)) ? Qtrue : Qfalse;
}

static VALUE ossl_rsa_export(int argc, VALUE *argv, VALUE self)
{
	ossl_rsa *rsap = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	const EVP_CIPHER *ciph = NULL;
	char *pass = NULL;
	VALUE cipher, password, str;

	GetRSA(self, rsap);

	rb_scan_args(argc, argv, "02", &cipher, &password);

	if (!NIL_P(cipher)) {
		OSSL_Check_Type(cipher, cCipher);
		ciph = ossl_cipher_get_EVP_CIPHER(cipher);
		
		if (!NIL_P(password)) {
			Check_SafeStr(password);
			pass = RSTRING(password)->ptr;
		}
	}
	if (!(out = BIO_new(BIO_s_mem()))) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	
	if (RSA_PRIVATE(rsap->rsa)) {
		if (!PEM_write_bio_RSAPrivateKey(out, rsap->rsa, ciph, NULL, 0, NULL, pass)) {
			rb_raise(eRSAError, "%s", ossl_error());
		}
	} else {
		if (!PEM_write_bio_RSAPublicKey(out, rsap->rsa)) {
			rb_raise(eRSAError, "%s", ossl_error());
		}
	}

	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE ossl_rsa_public_encrypt(VALUE self, VALUE buffer)
{
	ossl_rsa *rsap = NULL;
	char *enc_text = NULL;
	int len = 0, size = 0;
	VALUE enc;
	
	GetRSA(self, rsap);

	Check_Type(buffer, T_STRING);
	size = RSA_size(rsap->rsa);
	
	if (!(enc_text = malloc(size + 16))) {
		rb_raise(eRSAError, "Memory alloc error");
	}
	if ((len = RSA_public_encrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, enc_text, rsap->rsa, RSA_PKCS1_PADDING)) < 0) {
		free(enc_text);
		rb_raise(eRSAError, "%s", ossl_error());
	}
	enc = rb_str_new(enc_text, len);
	free(enc_text);

	return enc;
}

static VALUE ossl_rsa_public_decrypt(VALUE self, VALUE buffer)
{
	ossl_rsa *rsap = NULL;
	char *txt = NULL;
	int len = 0, size = 0;
	VALUE text;

	GetRSA(self, rsap);

	Check_Type(buffer, T_STRING);
	size = RSA_size(rsap->rsa);
	
	if (!(txt = malloc(size + 16))) {
		rb_raise(eRSAError, "Memory alloc error");
	}
	if ((len = RSA_public_decrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, txt, rsap->rsa, RSA_PKCS1_PADDING)) < 0) {
		free(txt);
		rb_raise(eRSAError, "%s", ossl_error());
	}
	text = rb_str_new(txt, len);
	free(txt);

	return text;
}

static VALUE ossl_rsa_private_encrypt(VALUE self, VALUE buffer)
{
	ossl_rsa *rsap = NULL;
	char *enc_text = NULL;
	int len = 0, size = 0;
	VALUE enc;
	
	GetRSA(self, rsap);

	if (!RSA_PRIVATE(rsap->rsa)) {
		rb_raise(eRSAError, "This key is PUBLIC only!");
	}
	Check_Type(buffer, T_STRING);
	
	size = RSA_size(rsap->rsa);
	
	if (!(enc_text = malloc(size + 16))) {
		rb_raise(eRSAError, "Memory alloc error");
	}
	if ((len = RSA_private_encrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, enc_text, rsap->rsa, RSA_PKCS1_PADDING)) < 0) {
		free(enc_text);
		rb_raise(eRSAError, "%s", ossl_error());
	}
	enc = rb_str_new(enc_text, len);
	free(enc_text);

	return enc;
}

static VALUE ossl_rsa_private_decrypt(VALUE self, VALUE buffer)
{
	ossl_rsa *rsap = NULL;
	char *txt = NULL;
	int len = 0, size = 0;
	VALUE text;

	GetRSA(self, rsap);

	if (!RSA_PRIVATE(rsap->rsa)) {
		rb_raise(eRSAError, "Private RSA key needed!");
	}
	Check_Type(buffer, T_STRING);
	
	size = RSA_size(rsap->rsa);

	if (!(txt = malloc(size + 16))) {
		rb_raise(eRSAError, "Memory alloc error");
	}
	if ((len = RSA_private_decrypt(RSTRING(buffer)->len, RSTRING(buffer)->ptr, txt, rsap->rsa, RSA_PKCS1_PADDING)) < 0) {
		free(txt);
		rb_raise(eRSAError, "%s", ossl_error());
	}
	text = rb_str_new(txt, len);
	free(txt);

	return text;
}

/*
 * Just sample
 * (it's not (maybe) wise to show private RSA values)
 */
static VALUE ossl_rsa_get_n(VALUE self)
{
	ossl_rsa *rsap = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE num;

	GetRSA(self, rsap);

	if (!(out = BIO_new(BIO_s_mem()))) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	if (!BN_print(out, rsap->rsa->n)) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	BIO_get_mem_ptr(out, &buf);
	
	num = rb_cstr2inum(buf->data, 16);
	BIO_free(out);

	return num;
}

static VALUE ossl_rsa_to_der(VALUE self)
{
	ossl_rsa *rsap = NULL;
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	X509_PUBKEY *key = NULL;
	VALUE str;
	
	GetRSA(self, rsap);

	rsa = (RSA_PRIVATE(rsap->rsa)) ? RSAPrivateKey_dup(rsap->rsa):RSAPublicKey_dup(rsap->rsa);
	if (!rsa) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	if (!(pkey = EVP_PKEY_new())) {
		RSA_free(rsa);
		rb_raise(eRSAError, "%s", ossl_error());
	}
	if (!EVP_PKEY_assign_RSA(pkey, rsap->rsa)) {
		RSA_free(rsa);
		EVP_PKEY_free(pkey);
		rb_raise(eRSAError, "%s", ossl_error());
	}	
	if (!(key = X509_PUBKEY_new())) {
		EVP_PKEY_free(pkey);
		rb_raise(eRSAError, "%s", ossl_error());
	}
	if (!X509_PUBKEY_set(&key, pkey)) {
		EVP_PKEY_free(pkey);
		X509_PUBKEY_free(key);
		rb_raise(eRSAError, "%s", ossl_error());
	}

	str = rb_str_new(key->public_key->data, key->public_key->length);
	/* EVP_PKEY_free(pkey) = this does X509_PUBKEY_free!! */
	X509_PUBKEY_free(key);

	return str;
}

/*
 * Prints all parameters of key to buffer
 * INSECURE: PRIVATE INFORMATIONS CAN LEAK OUT!!!
 * Don't use :-)) (I's up to you)
 */
static VALUE ossl_rsa_to_str(VALUE self)
{
	ossl_rsa *rsap = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetRSA(self, rsap);

	if (!(out = BIO_new(BIO_s_mem()))) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	if (!RSA_print(out, rsap->rsa, 0)) { //offset = 0
		rb_raise(eRSAError, "%s", ossl_error());
	}
	BIO_get_mem_ptr(out, &buf);
	
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);

	return str;
}

/*
 * Makes new instance RSA PUBLIC_KEY from PRIVATE_KEY
 */
static VALUE ossl_rsa_to_public_key(VALUE self)
{
	ossl_rsa *rsap1 = NULL, *rsap2 = NULL;
	VALUE obj;
	
	GetRSA(self, rsap1);

	MakeRSA(obj, rsap2);
	if (!(rsap2->rsa = RSAPublicKey_dup(rsap1->rsa))) {
		rb_raise(eRSAError, "%s", ossl_error());
	}
	
	return obj;
}

/*
 * Better to implement is in Ruby space?
 * 
static VALUE ossl_rsa_sign(VALUE self, VALUE digest, VALUE text)
{
	ossl_rsa *rsap = NULL;
	EVP_MD_CTX ctx;
	const EVP_MD *md = NULL;
	char *sign = NULL;
	int sign_len = 0;
	VALUE str;

	GetRSA(self, rsap);
	OSSL_Check_type(digest, cDigest);
	Check_SafeStr(text);

	if (!(sign = OPENSSL_malloc(RSA_size(rsap->rsa)+16))) {
		rb_raise(eRSAError, "%s", ossl_error());
	}

	md = ossl_digest_get_EVP_MD(digest);
	EVP_SignInit(&ctx, md);
	EVP_SignUpdate(&ctx, RSTRING(text)->ptr, RSTRING(text)->len);
	if (!EVP_SignFinal(&ctx, sign, &sign_len, pkeyp->key)) {
		OPENSSL_free(sign);
		rb_raise(ePKeyError, "%s", ossl_error());
	}
	
	str = rb_str_new(sign, sign_len);
	OPENSSL_free(sign);

	return str;
}
	
static VALUE ossl_rsa_verify(VALUE self, VALUE digest, VALUE text)
{
}
 */

void Init_ossl_rsa(VALUE mPKey, VALUE cPKey, VALUE ePKeyError)
{
	eRSAError = rb_define_class_under(mPKey, "RSAError", ePKeyError);

	cRSA = rb_define_class_under(mPKey, "RSA", cPKey);
	rb_define_singleton_method(cRSA, "new", ossl_rsa_s_new, -1);
	rb_define_method(cRSA, "initialize", ossl_rsa_initialize, -1);
	rb_define_method(cRSA, "public?", ossl_rsa_is_public, 0);
	rb_define_method(cRSA, "private?", ossl_rsa_is_private, 0);
	rb_define_method(cRSA, "to_str", ossl_rsa_to_str, 0);
	rb_define_method(cRSA, "export", ossl_rsa_export, -1);
	rb_define_alias(cRSA, "to_pem", "export");
	rb_define_method(cRSA, "public_key", ossl_rsa_to_public_key, 0);
	rb_define_method(cRSA, "public_encrypt", ossl_rsa_public_encrypt, 1);
	rb_define_method(cRSA, "public_decrypt", ossl_rsa_public_decrypt, 1);
	rb_define_method(cRSA, "private_encrypt", ossl_rsa_private_encrypt, 1);
	rb_define_method(cRSA, "private_decrypt", ossl_rsa_private_decrypt, 1);
	rb_define_method(cRSA, "n", ossl_rsa_get_n, 0);
	rb_define_method(cRSA, "to_der", ossl_rsa_to_der, 0);
/*
 * Rather in Ruby space?
 * 
	rb_define_method(cRSA, "sign", ossl_rsa_sign, 2);
	rb_define_method(cRSA, "verify", ossl_rsa_verify, 3);
 */
}

