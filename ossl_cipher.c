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

#define MakeCipher(obj, klass, ciphp) obj = Data_Make_Struct(klass, ossl_cipher, 0, ossl_cipher_free, ciphp)
#define GetCipher(obj, ciphp) do { \
	Data_Get_Struct(obj, ossl_cipher, ciphp); \
	if (!ciphp) { \
		ossl_raise(rb_eRuntimeError, "Cipher not inititalized!"); \
	} \
} while (0)
#define SafeGetCipher(obj, ciphp) do { \
	OSSL_Check_Kind(obj, cCipher); \
	GetCipher(obj, ciphp); \
	if (!ciphp->cipher) { \
		ossl_raise(rb_eRuntimeError, "Cipher not inititalized!"); \
	} \
} while (0)

/*
 * Classes
 */
VALUE mCipher;
VALUE cCipher;
VALUE eCipherError;

/*
 * Struct
 */
typedef struct ossl_cipher_st {
	int init; /* HACK - not to coredump when calling 'update' without previous en/decrypt */
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX ctx;
} ossl_cipher;

static void
ossl_cipher_free(ossl_cipher *ciphp)
{
	if (ciphp) {
		EVP_CIPHER_CTX_cleanup(&ciphp->ctx);
		ciphp->cipher = NULL;
		free(ciphp);
	}
}

/*
 * PUBLIC
 */
const EVP_CIPHER *
ossl_cipher_get_EVP_CIPHER(VALUE obj)
{
	ossl_cipher *ciphp;

	SafeGetCipher(obj, ciphp);

	return ciphp->cipher; /*EVP_CIPHER_CTX_cipher(ciphp->ctx);*/
}

/*
 * PRIVATE
 */
static VALUE
ossl_cipher_s_allocate(VALUE klass)
{
	ossl_cipher *ciphp;
	VALUE obj;

	MakeCipher(obj, klass, ciphp);
	
	ciphp->init = Qfalse;
	ciphp->cipher = NULL;

	return obj;
}

static VALUE
ossl_cipher_initialize(VALUE self, VALUE str)
{
	ossl_cipher *ciphp;
	char *c_name;

	GetCipher(self, ciphp);

	c_name = StringValuePtr(str);

	if (!(ciphp->cipher = EVP_get_cipherbyname(c_name))) {
		ossl_raise(rb_eRuntimeError, "Unsupported cipher algorithm (%s).", c_name);
	}
	return self;
}

static VALUE
ossl_cipher_encrypt(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp;
	unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
	VALUE pass, init_v;

	GetCipher(self, ciphp);
	
	rb_scan_args(argc, argv, "11", &pass, &init_v);
	
	StringValue(pass);

	if (NIL_P(init_v)) {
		/*
		 * TODO:
		 * random IV generation!
		 */ 
		memcpy(iv, "OpenSSL for Ruby rulez!", sizeof(iv));
		/*
		RAND_add(data,i,0); where from take data?
		if (RAND_pseudo_bytes(iv, 8) < 0) {
			ossl_raise(eCipherError, "");
		}
		 */
	} else {
		init_v = rb_obj_as_string(init_v);
		if (EVP_MAX_IV_LENGTH > RSTRING(init_v)->len) {
			memset(iv, 0, EVP_MAX_IV_LENGTH);
			memcpy(iv, RSTRING(init_v)->ptr, RSTRING(init_v)->len);
		} else {
			memcpy(iv, RSTRING(init_v)->ptr, sizeof(iv));
		}
	}
	EVP_CIPHER_CTX_init(&ciphp->ctx);

	EVP_BytesToKey(ciphp->cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_EncryptInit(&ciphp->ctx, ciphp->cipher, key, iv)) {
		ossl_raise(eCipherError, "");
	}
	ciphp->init = Qtrue;
	
	return self;
}

static VALUE
ossl_cipher_decrypt(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp;
	unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
	VALUE pass, init_v;
	
	GetCipher(self, ciphp);
	
	rb_scan_args(argc, argv, "11", &pass, &init_v);
	
	StringValue(pass);
	
	if (NIL_P(init_v)) {
		/*
		 * TODO:
		 * random IV generation!
		 */
		memcpy(iv, "OpenSSL for Ruby rulez!", EVP_MAX_IV_LENGTH);
	} else {
		init_v = rb_obj_as_string(init_v);
		if (EVP_MAX_IV_LENGTH > RSTRING(init_v)->len) {
			memset(iv, 0, EVP_MAX_IV_LENGTH);
			memcpy(iv, RSTRING(init_v)->ptr, RSTRING(init_v)->len);
		} else {
			memcpy(iv, RSTRING(init_v)->ptr, EVP_MAX_IV_LENGTH);
		}
	}
	EVP_CIPHER_CTX_init(&ciphp->ctx);

	/*if (!load_iv((unsigned char **)&header,&(ciphp->cipher->iv[0]),8)) return(0); * cipher = CIPHER_INFO */

	EVP_BytesToKey(ciphp->cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_DecryptInit(&ciphp->ctx, ciphp->cipher, key, iv)) {
		ossl_raise(eCipherError, "");
	}
	ciphp->init = Qtrue;
	
	return self;
}

static VALUE 
ossl_cipher_update(VALUE self, VALUE data)
{
	ossl_cipher *ciphp;
	char *in, *out;
	int in_len, out_len;
	VALUE str;

	GetCipher(self, ciphp);

	if (ciphp->init != Qtrue) {
		ossl_raise(eCipherError, "Don't call Cipher#update without preceding Cipher#(en|de)crypt.");
	}
	StringValue(data);
	in = RSTRING(data)->ptr;
	in_len = RSTRING(data)->len;
	
	if (!(out = OPENSSL_malloc(in_len + EVP_CIPHER_CTX_block_size(&ciphp->ctx)))) {
		ossl_raise(eCipherError, "");
	}
	if (!EVP_CipherUpdate(&ciphp->ctx, out, &out_len, in, in_len)) {
		OPENSSL_free(out);
		ossl_raise(eCipherError, "");
	}
	str = rb_str_new(out, out_len);
	OPENSSL_free(out);

	return str;
}

static VALUE 
ossl_cipher_final(VALUE self)
{
	ossl_cipher *ciphp;
	char *out;
	int out_len;
	VALUE str;

	GetCipher(self, ciphp);
	
	if (ciphp->init != Qtrue) {
		ossl_raise(eCipherError, "Don't call Cipher#final without preceding Cipher#(en|de)crypt.");
	}	
	if (!(out = OPENSSL_malloc(EVP_CIPHER_CTX_block_size(&ciphp->ctx)))) {
		ossl_raise(eCipherError, "");
	}
	if (!EVP_CipherFinal(&ciphp->ctx, out, &out_len)) {
		OPENSSL_free(out);
		ossl_raise(eCipherError, "");
	}
	if (!EVP_CIPHER_CTX_cleanup(&ciphp->ctx)) {
		OPENSSL_free(out);
		ossl_raise(eCipherError, "");
	}
	ciphp->init = Qfalse;

	str = rb_str_new(out, out_len);
	OPENSSL_free(out);
	
	return str;
}

static VALUE
ossl_cipher_name(VALUE self)
{
	ossl_cipher *ciphp;
	
	GetCipher(self, ciphp);

	return rb_str_new2(EVP_CIPHER_name(ciphp->cipher));
}

#define CIPHER_0ARG_INT(func)						\
	static VALUE							\
	ossl_cipher_##func(VALUE self)					\
	{								\
		ossl_cipher *ciphp;					\
									\
		GetCipher(self, ciphp);					\
									\
		return INT2NUM(EVP_CIPHER_##func(ciphp->cipher));	\
	}
CIPHER_0ARG_INT(key_length)
CIPHER_0ARG_INT(iv_length)

/*
 * INIT
 */
void 
Init_ossl_cipher(void)
{
	mCipher = rb_define_module_under(mOSSL, "Cipher");

	eCipherError = rb_define_class_under(mOSSL, "CipherError", eOSSLError);

	cCipher = rb_define_class_under(mCipher, "Cipher", rb_cObject);
	
	rb_define_singleton_method(cCipher, "allocate", ossl_cipher_s_allocate, 0);
	rb_define_method(cCipher, "initialize", ossl_cipher_initialize, 1);
	
	rb_define_method(cCipher, "encrypt", ossl_cipher_encrypt, -1);
	rb_define_method(cCipher, "decrypt", ossl_cipher_decrypt, -1);
	rb_define_method(cCipher, "update", ossl_cipher_update, 1);
	rb_define_alias(cCipher, "<<", "update");
	rb_define_method(cCipher, "final", ossl_cipher_final, 0);

	rb_define_method(cCipher, "name", ossl_cipher_name, 0);
	rb_define_method(cCipher, "key_len", ossl_cipher_key_length, 0);
/*
 * TODO
 * int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
 */
	rb_define_method(cCipher, "iv_len", ossl_cipher_iv_length, 0);

} /* Init_ossl_cipher */

