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
#if !defined(OPENSSL_NO_HMAC)

#include "ossl.h"

#define MakeHMAC(obj, ctx) \
    obj = Data_Make_Struct(cHMAC, HMAC_CTX, 0, CRYPTO_free, ctx)
#define GetHMAC(obj, ctx) do { \
    Data_Get_Struct(obj, HMAC_CTX, ctx); \
    if (!ctx) { \
	ossl_raise(rb_eRuntimeError, "HMAC wasn't initialized"); \
    } \
} while (0)
#define SafeGetHMAC(obj, ctx) do { \
    OSSL_Check_Kind(obj, cHMAC); \
    GetHMAC(obj, ctx); \
} while (0)

/*
 * Classes
 */
VALUE cHMAC;
VALUE eHMACError;

/*
 * Public
 */

/*
 * Private
 */
static VALUE
ossl_hmac_alloc(VALUE klass)
{
    HMAC_CTX *ctx;
    VALUE obj;

    MakeHMAC(obj, ctx);
	
    return obj;
}

static VALUE
ossl_hmac_initialize(VALUE self, VALUE key, VALUE digest)
{
    HMAC_CTX *ctx;

    GetHMAC(self, ctx);
    StringValue(key);
    HMAC_CTX_init(ctx);
    HMAC_Init(ctx, RSTRING(key)->ptr, RSTRING(key)->len, GetDigestPtr(digest));

    return self;
}

static VALUE
ossl_hmac_copy_object(VALUE self, VALUE other)
{
    HMAC_CTX *ctx1, *ctx2;
    
    rb_check_frozen(self);
    if (self == other) return self;

    GetHMAC(self, ctx1);
    SafeGetHMAC(other, ctx2);

    if (!HMAC_CTX_copy(ctx1, ctx2)) {
	ossl_raise(eHMACError, "");
    }
    return self;
}

static VALUE
ossl_hmac_update(VALUE self, VALUE data)
{
    HMAC_CTX *ctx;

    GetHMAC(self, ctx);
    StringValue(data);
    HMAC_Update(ctx, RSTRING(data)->ptr, RSTRING(data)->len);

    return self;
}

static void
hmac_final(HMAC_CTX *ctx, char **buf, int *buf_len)
{
    HMAC_CTX final;

    if (!HMAC_CTX_copy(&final, ctx)) {
	ossl_raise(eHMACError, "");
    }
    if (!(*buf = OPENSSL_malloc(HMAC_size(&final)))) {
	OSSL_Debug("Allocating %d mem", HMAC_size(&final));
	ossl_raise(eHMACError, "Cannot allocate memory for hmac");
    }
    HMAC_Final(&final, *buf, buf_len);
    HMAC_CTX_cleanup(&final);
}

static VALUE
ossl_hmac_digest(VALUE self)
{
    HMAC_CTX *ctx;
    char *buf;
    int buf_len;
    VALUE digest;
	
    GetHMAC(self, ctx);
    hmac_final(ctx, &buf, &buf_len);
    digest = rb_str_new(buf, buf_len);
    OPENSSL_free(buf);
    
    return digest;
}

static VALUE
ossl_hmac_hexdigest(VALUE self)
{
    HMAC_CTX *ctx;
    char *buf, *hexbuf;
    int buf_len;
    VALUE hexdigest;
	
    GetHMAC(self, ctx);
    hmac_final(ctx, &buf, &buf_len);
    if (string2hex(buf, buf_len, &hexbuf, NULL) != 2 * buf_len) {
	OPENSSL_free(buf);
	ossl_raise(eHMACError, "Memory alloc error");
    }
    hexdigest = rb_str_new(hexbuf, 2 * buf_len);
    OPENSSL_free(buf);
    OPENSSL_free(hexbuf);

    return hexdigest;
}

static VALUE
ossl_hmac_s_digest(VALUE klass, VALUE digest, VALUE key, VALUE data)
{
    char *buf;
    int buf_len;
	
    StringValue(key);
    StringValue(data);
    buf = HMAC(GetDigestPtr(digest), RSTRING(key)->ptr, RSTRING(key)->len,
	       RSTRING(data)->ptr, RSTRING(data)->len, NULL, &buf_len);

    return rb_str_new(buf, buf_len);
}

static VALUE
ossl_hmac_s_hexdigest(VALUE klass, VALUE digest, VALUE key, VALUE data)
{
    char *buf, *hexbuf;
    int buf_len;
    VALUE hexdigest;

    StringValue(key);
    StringValue(data);
	
    buf = HMAC(GetDigestPtr(digest), RSTRING(key)->ptr, RSTRING(key)->len,
	       RSTRING(data)->ptr, RSTRING(data)->len, NULL, &buf_len);
    if (string2hex(buf, buf_len, &hexbuf, NULL) != 2 * buf_len) {
	ossl_raise(eHMACError, "Cannot convert buf to hexbuf");
    }
    hexdigest = rb_str_new(hexbuf, 2 * buf_len);
    OPENSSL_free(hexbuf);
	
    return hexdigest;
}

/*
 * INIT
 */
void
Init_ossl_hmac()
{
    eHMACError = rb_define_class_under(mOSSL, "HMACError", eOSSLError);
	
    cHMAC = rb_define_class_under(mOSSL, "HMAC", rb_cObject);

    rb_define_alloc_func(cHMAC, ossl_hmac_alloc);
    rb_define_singleton_method(cHMAC, "digest", ossl_hmac_s_digest, 3);
    rb_define_singleton_method(cHMAC, "hexdigest", ossl_hmac_s_hexdigest, 3);
    
    rb_define_method(cHMAC, "initialize", ossl_hmac_initialize, 2);
    rb_define_method(cHMAC, "copy_object", ossl_hmac_copy_object, 1);

    rb_define_method(cHMAC, "update", ossl_hmac_update, 1);
    rb_define_alias(cHMAC, "<<", "update");
    rb_define_method(cHMAC, "digest", ossl_hmac_digest, 0);
    rb_define_method(cHMAC, "hexdigest", ossl_hmac_hexdigest, 0);
    rb_define_alias(cHMAC, "inspect", "hexdigest");
    rb_define_alias(cHMAC, "to_s", "hexdigest");
}

#else /* NO_HMAC */
#  warning >>> OpenSSL is compiled without HMAC support <<<
void
Init_ossl_hmac()
{
    rb_warning("HMAC will NOT be avaible: OpenSSL is compiled without HMAC.");
}
#endif /* NO_HMAC */
