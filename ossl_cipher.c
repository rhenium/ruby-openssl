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
    EVP_CIPHER_CTX ctx;
} ossl_cipher;

static void
ossl_cipher_free(ossl_cipher *ciphp)
{
    if (ciphp) {
	EVP_CIPHER_CTX_cleanup(&ciphp->ctx);
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

    return EVP_CIPHER_CTX_cipher(&ciphp->ctx);
}

/*
 * PRIVATE
 */
static VALUE
ossl_cipher_alloc(VALUE klass)
{
    ossl_cipher *ciphp;
    VALUE obj;

    MakeCipher(obj, klass, ciphp);
	
    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_cipher_alloc)

static VALUE
ossl_cipher_initialize(VALUE self, VALUE str)
{
    ossl_cipher *ciphp;
    const EVP_CIPHER *cipher;
    char *name;

    GetCipher(self, ciphp);

    name = StringValuePtr(str);

    if (!(cipher = EVP_get_cipherbyname(name))) {
	ossl_raise(rb_eRuntimeError, "Unsupported cipher algorithm (%s).", name);
    }
    EVP_CIPHER_CTX_init(&ciphp->ctx);
    if (EVP_CipherInit(&ciphp->ctx, cipher, NULL, NULL, -1) != 1)
		ossl_raise(eCipherError, "");

    return self;
}
static VALUE
ossl_cipher_copy_object(VALUE self, VALUE other)
{
    ossl_cipher *ciphp1, *ciphp2;
	
    rb_check_frozen(self);
    if (self == other) return self;

    GetCipher(self, ciphp1);
    SafeGetCipher(other, ciphp2);

    return self;
}

static VALUE
ossl_cipher_reset(VALUE self)
{
	ossl_cipher *ciphp;

	GetCipher(self, ciphp);
	if (EVP_CipherInit(&ciphp->ctx, NULL, NULL, NULL, -1) != 1)
		ossl_raise(eCipherError, "");
		
	return self;
}

static VALUE
ossl_cipher_encrypt(int argc, VALUE *argv, VALUE self)
{
    ossl_cipher *ciphp;
    unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
    VALUE pass, init_v;

    GetCipher(self, ciphp);
	
    rb_scan_args(argc, argv, "02", &pass, &init_v);
	
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
    }
    else {
	init_v = rb_obj_as_string(init_v);
	if (EVP_MAX_IV_LENGTH > RSTRING(init_v)->len) {
	    memset(iv, 0, EVP_MAX_IV_LENGTH);
	    memcpy(iv, RSTRING(init_v)->ptr, RSTRING(init_v)->len);
	}
	else {
	    memcpy(iv, RSTRING(init_v)->ptr, sizeof(iv));
	}
    }

    if (EVP_CipherInit(&ciphp->ctx, NULL, NULL, NULL, 1) != 1) {
        ossl_raise(eCipherError, "");
    }

    if (!NIL_P(pass)) {
        StringValue(pass);

        EVP_BytesToKey(EVP_CIPHER_CTX_cipher(&ciphp->ctx), EVP_md5(), iv,
		   RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
        if (EVP_CipherInit(&ciphp->ctx, NULL, key, iv, -1) != 1) {
            ossl_raise(eCipherError, "");
        }
    }

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

    if (NIL_P(init_v)) {
	/*
	 * TODO:
	 * random IV generation!
	 */
	memcpy(iv, "OpenSSL for Ruby rulez!", EVP_MAX_IV_LENGTH);
    }
    else {
	init_v = rb_obj_as_string(init_v);
	if (EVP_MAX_IV_LENGTH > RSTRING(init_v)->len) {
	    memset(iv, 0, EVP_MAX_IV_LENGTH);
	    memcpy(iv, RSTRING(init_v)->ptr, RSTRING(init_v)->len);
	}
	else {
	    memcpy(iv, RSTRING(init_v)->ptr, EVP_MAX_IV_LENGTH);
	}
    }

    if (EVP_CipherInit(&ciphp->ctx, NULL, NULL, NULL, 0) != 1) {
        ossl_raise(eCipherError, "");
    }

    if (!NIL_P(pass)) {
        StringValue(pass);

        EVP_BytesToKey(EVP_CIPHER_CTX_cipher(&ciphp->ctx), EVP_md5(), iv,
		   RSTRING(pass)->ptr, RSTRING(pass)->len, 1, key, NULL);
        if (EVP_CipherInit(&ciphp->ctx, NULL, key, iv, -1) != 1) {
            ossl_raise(eCipherError, "");
        }
    }

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

    StringValue(data);
    in = RSTRING(data)->ptr;
    in_len = RSTRING(data)->len;
	
    if (!(out = OPENSSL_malloc(in_len+EVP_CIPHER_CTX_block_size(&ciphp->ctx)))){
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
	
    if (!(out = OPENSSL_malloc(EVP_CIPHER_CTX_block_size(&ciphp->ctx)))) {
	ossl_raise(eCipherError, "");
    }
    if (!EVP_CipherFinal(&ciphp->ctx, out, &out_len)) {
	OPENSSL_free(out);
	ossl_raise(eCipherError, "");
    }

    str = rb_str_new(out, out_len);
    OPENSSL_free(out);
	
    return str;
}

static VALUE
ossl_cipher_name(VALUE self)
{
    ossl_cipher *ciphp;

    GetCipher(self, ciphp);

    return rb_str_new2(EVP_CIPHER_name(EVP_CIPHER_CTX_cipher(&ciphp->ctx)));
}

static VALUE
ossl_cipher_set_key(VALUE self, VALUE key)
{
    ossl_cipher *ciphp;

    StringValue(key);
    GetCipher(self, ciphp);

    if (RSTRING(key)->len < EVP_CIPHER_CTX_key_length(&ciphp->ctx))
        ossl_raise(eCipherError, "key length too short");

    if (EVP_CipherInit(&ciphp->ctx, NULL, RSTRING(key)->ptr, NULL, -1) != 1)
        ossl_raise(eCipherError, "");

    return Qnil;
}

static VALUE
ossl_cipher_set_iv(VALUE self, VALUE iv)
{
    ossl_cipher *ciphp;

    StringValue(iv);
    GetCipher(self, ciphp);

    if (EVP_CipherInit(&ciphp->ctx, NULL, NULL, RSTRING(iv)->ptr, -1) != 1)
		ossl_raise(eCipherError, "");

    return Qnil;
}

#define CIPHER_0ARG_INT(func)					\
    static VALUE						\
    ossl_cipher_##func(VALUE self)				\
    {								\
	ossl_cipher *ciphp;					\
	GetCipher(self, ciphp);					\
	return INT2NUM(EVP_CIPHER_##func(EVP_CIPHER_CTX_cipher(&ciphp->ctx)));	\
    }
CIPHER_0ARG_INT(key_length)
CIPHER_0ARG_INT(iv_length)
CIPHER_0ARG_INT(block_size)

/*
 * INIT
 */
void 
Init_ossl_cipher(void)
{
    mCipher = rb_define_module_under(mOSSL, "Cipher");
    eCipherError = rb_define_class_under(mOSSL, "CipherError", eOSSLError);
    cCipher = rb_define_class_under(mCipher, "Cipher", rb_cObject);

    rb_define_alloc_func(cCipher, ossl_cipher_alloc);
    rb_define_method(cCipher, "initialize", ossl_cipher_initialize, 1);
    rb_define_method(cCipher, "copy_object", ossl_cipher_copy_object, 1);
    rb_define_method(cCipher, "reset", ossl_cipher_reset, 0);

    rb_define_method(cCipher, "encrypt", ossl_cipher_encrypt, -1);
    rb_define_method(cCipher, "decrypt", ossl_cipher_decrypt, -1);
    rb_define_method(cCipher, "update", ossl_cipher_update, 1);
    rb_define_alias(cCipher, "<<", "update");
    rb_define_method(cCipher, "final", ossl_cipher_final, 0);

    rb_define_method(cCipher, "name", ossl_cipher_name, 0);

    rb_define_method(cCipher, "key=", ossl_cipher_set_key, 1);
    rb_define_method(cCipher, "key_len", ossl_cipher_key_length, 0);
/*
 * TODO
 * int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
 */
    rb_define_method(cCipher, "iv=", ossl_cipher_set_iv, 1);
    rb_define_method(cCipher, "iv_len", ossl_cipher_iv_length, 0);

    rb_define_method(cCipher, "block_size", ossl_cipher_block_size, 0);

} /* Init_ossl_cipher */

