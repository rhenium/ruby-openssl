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

#define WrapDigest(klass, obj, ctx) do { \
	if (!ctx) { \
		rb_raise(rb_eRuntimeError, "Digest CTX wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(klass, 0, CRYPTO_free, ctx); \
} while (0)
#define GetDigest(obj, ctx) do { \
	Data_Get_Struct(obj, EVP_MD_CTX, ctx); \
	if (!ctx) { \
		rb_raise(rb_eRuntimeError, "Digest CTX wasn't initialized!"); \
	} \
} while (0)
#define SafeGetDigest(obj, ctx) do { \
	OSSL_Check_Kind(obj, cDigest); \
	GetDigest(obj, ctx); \
} while (0)

/*
 * Classes
 */
VALUE mDigest;
VALUE cDigest;
VALUE eDigestError;

/*
 * Public
 */
const EVP_MD *
ossl_digest_get_EVP_MD(VALUE obj)
{
	EVP_MD_CTX *ctx;

	SafeGetDigest(obj, ctx);

	return EVP_MD_CTX_md(ctx); /*== ctx->digest*/
}

/*
 * Private
 */
static VALUE
ossl_digest_s_allocate(VALUE klass)
{
	EVP_MD_CTX *ctx;
	VALUE obj;

	if (!(ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX)))) {
		OSSL_Raise(eDigestError, "Cannot allocate memory for a digest's CTX");
	}
	WrapDigest(klass, obj, ctx);
	
	return obj;
}

static VALUE
ossl_digest_initialize(VALUE self, VALUE str)
{
	EVP_MD_CTX *ctx;
	const EVP_MD *md;
	char *md_name;
	
	GetDigest(self, ctx);
	
	md_name = StringValuePtr(str);
	
	if (!(md = EVP_get_digestbyname(md_name))) {
		rb_raise(rb_eRuntimeError, "Unsupported digest algorithm (%s).", md_name);
	}
	EVP_DigestInit(ctx, md);

	return self;
}

static VALUE
ossl_digest_update(VALUE self, VALUE data)
{
	EVP_MD_CTX *ctx;

	GetDigest(self, ctx);

	StringValue(data);

	EVP_DigestUpdate(ctx, RSTRING(data)->ptr, RSTRING(data)->len);

	return self;
}

static void
digest_final(EVP_MD_CTX *ctx, char **buf, int *buf_len)
{
	EVP_MD_CTX final;

	if (!EVP_MD_CTX_copy(&final, ctx)) {
		OSSL_Raise(eDigestError, "");
	}
	if (!(*buf = OPENSSL_malloc(EVP_MD_CTX_size(&final)))) {
		OSSL_Raise(eDigestError, "Cannot allocate mem for digest");
	}
	EVP_DigestFinal(&final, *buf, buf_len);
}

static VALUE
ossl_digest_digest(VALUE self)
{
	EVP_MD_CTX *ctx;
	char *buf;
	int buf_len;
	VALUE digest;
	
	GetDigest(self, ctx);
	
	digest_final(ctx, &buf, &buf_len);
	
	digest = rb_str_new(buf, buf_len);
	OPENSSL_free(buf);
	
	return digest;
}

static VALUE
ossl_digest_hexdigest(VALUE self)
{
	EVP_MD_CTX *ctx;
	char *buf, *hexbuf;
	int buf_len;
	VALUE hexdigest;
	
	GetDigest(self, ctx);
	
	digest_final(ctx, &buf, &buf_len);
	
	if (string2hex(buf, buf_len, &hexbuf, NULL) != 2 * buf_len) {
		OPENSSL_free(buf);
		OSSL_Raise(eDigestError, "Memory alloc error");
	}
	hexdigest = rb_str_new(hexbuf, 2 * buf_len);
	OPENSSL_free(buf);
	OPENSSL_free(hexbuf);

	return hexdigest;
}

static VALUE
ossl_digest_s_digest(VALUE klass, VALUE str, VALUE data)
{
	VALUE obj = rb_class_new_instance(1, &str, klass);

	ossl_digest_update(obj, data);

	return ossl_digest_digest(obj);
}

static VALUE
ossl_digest_s_hexdigest(VALUE klass, VALUE str, VALUE data)
{
	VALUE obj = rb_class_new_instance(1, &str, klass);

	ossl_digest_update(obj, data);

	return ossl_digest_hexdigest(obj);
}

static VALUE
ossl_digest_clone(VALUE self)
{
	EVP_MD_CTX *ctx, *other;
	VALUE obj;
	
	GetDigest(self, ctx);
	
	obj = rb_obj_alloc(CLASS_OF(self));
	
	GetDigest(obj, other);
	
	if (!EVP_MD_CTX_copy(other, ctx)) {
		OSSL_Raise(eDigestError, "");
	}
	
	return obj;
}

static VALUE
ossl_digest_equal(VALUE self, VALUE other)
{
	EVP_MD_CTX *ctx;
	VALUE str1, str2;

	GetDigest(self, ctx);
	
	if (CLASS_OF(other) == CLASS_OF(self)) {
		str2 = ossl_digest_digest(other);
	} else {
		StringValue(other);
		str2 = other;
	}

	if (RSTRING(str2)->len == EVP_MD_CTX_size(ctx)) {
		str1 = ossl_digest_digest(self);
	} else {
		str1 = ossl_digest_hexdigest(self);
	}

	if (RSTRING(str1)->len == RSTRING(str2)->len &&
			rb_str_cmp(str1, str2) == 0) {
		return Qtrue;
	}

	return Qfalse;
}

/*
 * INIT
 */
void
Init_ossl_digest()
{
	mDigest = rb_define_module_under(mOSSL, "Digest");
	
	eDigestError = rb_define_class_under(mDigest, "DigestError", eOSSLError);
	
	cDigest = rb_define_class_under(mDigest, "Digest", rb_cObject);
	
	rb_define_singleton_method(cDigest, "allocate", ossl_digest_s_allocate, 0);
	rb_define_singleton_method(cDigest, "digest", ossl_digest_s_digest, 2);
	rb_define_singleton_method(cDigest, "hexdigest", ossl_digest_s_hexdigest, 2);
	
	rb_define_method(cDigest, "initialize", ossl_digest_initialize, 1);

	rb_define_method(cDigest, "clone",  ossl_digest_clone, 0);

	rb_define_method(cDigest, "digest", ossl_digest_digest, 0);
	rb_define_method(cDigest, "hexdigest", ossl_digest_hexdigest, 0);
	rb_define_alias(cDigest, "inspect", "hexdigest");
	rb_define_alias(cDigest, "to_s", "hexdigest");
	
	rb_define_method(cDigest, "update", ossl_digest_update, 1);
	rb_define_alias(cDigest, "<<", "update");
	
	rb_define_method(cDigest, "==", ossl_digest_equal, 1);

} /* Init_ossl_digest */

