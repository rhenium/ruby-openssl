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
#define GetCipher(obj, ciphp) Data_Get_Struct(obj, ossl_cipher, ciphp)

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
	ossl_cipher *ciphp = NULL;

	OSSL_Check_Kind(obj, cCipher);
	
	GetCipher(obj, ciphp);

	return ciphp->cipher; /*EVP_CIPHER_CTX_cipher(ciphp->ctx);*/
}

/*
 * PRIVATE
 */
static VALUE
ossl_cipher_s_allocate(VALUE klass)
{
	ossl_cipher *ciphp = NULL;
	VALUE obj;

	MakeCipher(obj, klass, ciphp);
	
/*
 * NOT NEEDED IF STATIC
	if (!(ciphp->ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX)))) {
		OSSL_Raise(eCipherError, "");
	}
 */
	ciphp->init = Qfalse;
	ciphp->cipher = NULL;

	return obj;
}

static VALUE
ossl_cipher_initialize(VALUE self, VALUE str)
{
	ossl_cipher *ciphp = NULL;
	char *c_name = NULL;

	GetCipher(self, ciphp);

	c_name = StringValuePtr(str);

	if (!(ciphp->cipher = EVP_get_cipherbyname(c_name))) {
		rb_raise(rb_eRuntimeError, "Unsupported cipher algorithm (%s).", c_name);
	}
	
	return self;
}

static VALUE
ossl_cipher_encrypt(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
	VALUE pass, init_v;

	GetCipher(self, ciphp);
	
	rb_scan_args(argc, argv, "11", &pass, &init_v);
	
	pass = rb_String(pass);

	if (NIL_P(init_v)) {
		/*
		 * TODO:
		 * random IV generation!
		 */ 
		memcpy(iv, "OpenSSL for Ruby rulez!", sizeof(iv));
		/*
		RAND_add(data,i,0); where from take data?
		if (RAND_pseudo_bytes(iv, 8) < 0) {
			OSSL_Raise(eCipherError, "");
		}
		 */
	} else {
		init_v = rb_obj_as_string(init_v);
		if (EVP_MAX_IV_LENGTH > RSTRING(init_v)->len) {
			memset(iv, 0, EVP_MAX_IV_LENGTH);
			memcpy(iv, RSTRING(init_v)->ptr, RSTRING(init_v)->len);
		} else
			memcpy(iv, RSTRING(init_v)->ptr, sizeof(iv));
	}
	EVP_CIPHER_CTX_init(&ciphp->ctx);

	EVP_BytesToKey(ciphp->cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_EncryptInit(&ciphp->ctx, ciphp->cipher, key, iv)) {
		OSSL_Raise(eCipherError, "");
	}
	ciphp->init = Qtrue;
	
	return self;
}

static VALUE
ossl_cipher_decrypt(int argc, VALUE *argv, VALUE self)
{
	ossl_cipher *ciphp = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
	VALUE pass, init_v;
	
	GetCipher(self, ciphp);
	
	rb_scan_args(argc, argv, "11", &pass, &init_v);
	
	pass = rb_String(pass);
	
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
		} else
			memcpy(iv, RSTRING(init_v)->ptr, EVP_MAX_IV_LENGTH);
	}
	EVP_CIPHER_CTX_init(&ciphp->ctx);

	/*if (!load_iv((unsigned char **)&header,&(ciphp->cipher->iv[0]),8)) return(0); * cipher = CIPHER_INFO */

	EVP_BytesToKey(ciphp->cipher, EVP_md5(), iv, RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
	
	if (!EVP_DecryptInit(&ciphp->ctx, ciphp->cipher, key, iv)) {
		OSSL_Raise(eCipherError, "");
	}
	ciphp->init = Qtrue;
	
	return self;
}

static VALUE 
ossl_cipher_update(VALUE self, VALUE data)
{
	ossl_cipher *ciphp = NULL;
	char *in = NULL, *out = NULL;
	int in_len = 0, out_len = 0;
	VALUE str;

	GetCipher(self, ciphp);

	if (ciphp->init != Qtrue) {
		rb_raise(eCipherError, "Don't call 'update' without preceding 'en/decrypt'.");
	}
	
	data = rb_String(data);
	in = RSTRING(data)->ptr;
	in_len = RSTRING(data)->len;
	
	if (!(out = OPENSSL_malloc(in_len + EVP_CIPHER_CTX_block_size(&ciphp->ctx)))) {
		OSSL_Raise(eCipherError, "");
	}
	if (!EVP_CipherUpdate(&ciphp->ctx, out, &out_len, in, in_len)) {
		OPENSSL_free(out);
		OSSL_Raise(eCipherError, "");
	}
	str = rb_str_new(out, out_len);
	OPENSSL_free(out);

	return str;
}

static VALUE 
ossl_cipher_final(VALUE self)
{
	ossl_cipher *ciphp = NULL;

	char *out = NULL;
	int out_len = 0;
	VALUE str;

	GetCipher(self, ciphp);
	
	if (!(out = OPENSSL_malloc(EVP_CIPHER_CTX_block_size(&ciphp->ctx)))) {
		OSSL_Raise(eCipherError, "");
	}
	if (!EVP_CipherFinal(&ciphp->ctx, out, &out_len)) {
		OPENSSL_free(out);
		OSSL_Raise(eCipherError, "");
	}
	EVP_CIPHER_CTX_cleanup(&ciphp->ctx);
	str = rb_str_new(out, out_len);
	OPENSSL_free(out);
	ciphp->init = Qfalse;
	
	return str;
}

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
	rb_enable_super(cCipher, "initialize");
	
	rb_define_method(cCipher, "encrypt", ossl_cipher_encrypt, -1);
	rb_define_method(cCipher, "decrypt", ossl_cipher_decrypt, -1);
	rb_define_method(cCipher, "update", ossl_cipher_update, 1);
	rb_define_alias(cCipher, "<<", "update");
	rb_define_method(cCipher, "final", ossl_cipher_final, 0);

} /* Init_ossl_cipher */

