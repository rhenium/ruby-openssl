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

#define MakeDigest(klass, obj, digestp) {\
	obj = Data_Make_Struct(klass, ossl_digest, 0, ossl_digest_free, digestp);\
}
#define GetDigest(obj, digestp) Data_Get_Struct(obj, ossl_digest, digestp)

/*
 * Classes
 */
VALUE cDigest;
VALUE eDigestError;
VALUE cMD2, cMD4, cMD5, cMDC2, cRIPEMD160, cSHA, cSHA1, cDSS, cDSS1;

/*
 * Struct
 */
typedef struct ossl_digest_st {
	EVP_MD_CTX *md;
} ossl_digest;

static void
ossl_digest_free(ossl_digest *digestp)
{
	if (digestp) {
		if (digestp->md) OPENSSL_free(digestp->md);
		digestp->md = NULL;
		free(digestp);
	}
}

/*
 * PUBLIC
 */
int
ossl_digest_get_NID(VALUE obj)
{
	ossl_digest *digestp = NULL;
	
	OSSL_Check_Type(obj, cDigest);
	GetDigest(obj, digestp);

	return EVP_MD_CTX_type(digestp->md); /*== digestp->md->digest->type*/
}

const EVP_MD *
ossl_digest_get_EVP_MD(VALUE obj)
{
	ossl_digest *digestp = NULL;

	OSSL_Check_Type(obj, cDigest);
	GetDigest(obj, digestp);

	return EVP_MD_CTX_md(digestp->md); /*== digestp->md->digest*/
}

/*
 * PRIVATE
 */
static VALUE
ossl_digest_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_digest *digestp = NULL;
	VALUE obj;

	if (klass == cDigest)
		rb_raise(rb_eNotImpError, "cannot do Digest::ANY.new - it is an abstract class");

	MakeDigest(klass, obj, digestp);
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_digest_update(VALUE self, VALUE data)
{
	ossl_digest *digestp = NULL;

	GetDigest(self, digestp);

	data = rb_String(data);

	EVP_DigestUpdate(digestp->md, RSTRING(data)->ptr, RSTRING(data)->len);

	return self;
}

static VALUE
ossl_digest_digest(VALUE self)
{
	ossl_digest *digestp = NULL;
	char *digest_txt = NULL;
	int digest_len = 0;
	EVP_MD_CTX final;
	VALUE digest;
	
	GetDigest(self, digestp);
	
	if (!EVP_MD_CTX_copy(&final, digestp->md)) {
		OSSL_Raise(eDigestError, "");
	}
	if (!(digest_txt = OPENSSL_malloc(EVP_MD_CTX_size(&final)))) {
		OSSL_Raise(eDigestError, "Cannot allocate mem for digest");
	}
	EVP_DigestFinal(&final, digest_txt, &digest_len);

	digest = rb_str_new(digest_txt, digest_len);
	OPENSSL_free(digest_txt);
	
	return digest;
}

/*
 * RUBY attitude
 */
static VALUE
ossl_digest_hexdigest(VALUE self)
{
	ossl_digest *digestp = NULL;
	static const char hex[]="0123456789abcdef";
	char *digest_txt = NULL, *hexdigest_txt = NULL;
	int i,digest_len = 0;
	EVP_MD_CTX final;
	VALUE hexdigest;
	
	GetDigest(self, digestp);
	
	if (!EVP_MD_CTX_copy(&final, digestp->md)) {
		OSSL_Raise(eDigestError, "");
	}
	if (!(digest_txt = OPENSSL_malloc(EVP_MD_CTX_size(&final)))) {
		OSSL_Raise(eDigestError, "Cannot allocate memory for digest");
	}
	EVP_DigestFinal(&final, digest_txt, &digest_len);

	if (!(hexdigest_txt = OPENSSL_malloc(2*digest_len+1))) {
		OPENSSL_free(digest_txt);
		OSSL_Raise(eDigestError, "Memory alloc error");
	}
	for (i = 0; i < digest_len; i++) {
		hexdigest_txt[i + i] = hex[((unsigned char)digest_txt[i]) >> 4];
		hexdigest_txt[i + i + 1] = hex[digest_txt[i] & 0x0f];
	}
	hexdigest_txt[i + i] = '\0';
	hexdigest = rb_str_new(hexdigest_txt, 2*digest_len);
	OPENSSL_free(digest_txt);
	OPENSSL_free(hexdigest_txt);

	return hexdigest;
}

/*
 * OPENSSL attitude
 *
static VALUE
ossl_digest_hexdigest(VALUE self)
{
	ossl_digest *digestp = NULL;
	unsigned char *digest_txt = NULL, *hexdigest_txt = NULL;
	int i,digest_len = 0;
	EVP_MD_CTX final;
	VALUE hexdigest;
	
	GetDigest(self, digestp);
	
	if (!EVP_MD_CTX_copy(&final, digestp->md)) {
		OSSL_Raise(eDigestError, "");
	}

	if (!(digest_txt = OPENSSL_malloc(EVP_MD_CTX_size(&final)))) {
		OSSL_Raise(eDigestError, "Cannot allocate memory for digest");
	}
	EVP_DigestFinal(&final, digest_txt, &digest_len);

	hexdigest_txt = hex_to_string(digest_txt, digest_len);
	hexdigest = rb_str_new2(hexdigest_txt);
	OPENSSL_free(digest_txt);
	OPENSSL_free(hexdigest_txt);

	return hexdigest;
}
 */

/*
 * automation of digest initialization method
 */
#define DefDigestInit(dgst)									\
	static VALUE										\
	ossl_##dgst##_initialize(int argc, VALUE *argv, VALUE self)				\
	{											\
		ossl_digest *digestp = NULL;							\
		VALUE data;									\
												\
		GetDigest(self, digestp);							\
		if (!(digestp->md = OPENSSL_malloc(sizeof(EVP_MD_CTX)))) {			\
			OSSL_Raise(eDigestError, "Cannot allocate memory for a digest's CTX");	\
		}										\
		EVP_DigestInit(digestp->md, EVP_##dgst());					\
												\
		if (rb_scan_args(argc, argv, "01", &data) == 1) {				\
			data = rb_String(data);							\
			EVP_DigestUpdate(digestp->md, RSTRING(data)->ptr, RSTRING(data)->len);	\
		}										\
		return self;									\
	}

/*
 * Define digest initialize methods
 */
#if !defined(NO_MD2) && !defined(OPENSSL_NO_MD2)
	DefDigestInit(md2);
#endif
#if !defined(NO_MD4) && !defined(OPENSSL_NO_MD4)
	DefDigestInit(md4);
#endif
#if !defined(NO_MD5) && !defined(OPENSSL_NO_MD5)
	DefDigestInit(md5);
#endif
#if !defined(NO_SHA) && !defined(OPENSSL_NO_SHA)
	DefDigestInit(sha);
	DefDigestInit(sha1);
	DefDigestInit(dss);
	DefDigestInit(dss1);
#endif
#if !defined(NO_RIPEMD) && !defined(OPENSSL_NO_RIPEMD)
	DefDigestInit(ripemd160);
#endif
#if !defined(NO_MDC2) && !defined(OPENSSL_NO_MDC2)
	DefDigestInit(mdc2);
#endif

/*
 * INIT
 */
void
Init_ossl_digest(VALUE module)
{
	eDigestError = rb_define_class_under(module, "DigestError", rb_eStandardError);
	
	cDigest = rb_define_class_under(module, "ANY", rb_cObject);
	rb_define_singleton_method(cDigest, "new", ossl_digest_s_new, -1);
/*	rb_define_singleton_method(cDigest, "digest", ossl_digest_s_digest, 1);
	rb_define_singleton_method(cDigest, "hexdigest", ossl_digest_s_hexdigest, 1);
	rb_define_method(cDigest, "initialize", ossl_digest_init, -1);
	rb_define_method(cDigest, "clone",  ossl_digest_clone, 0);
 */
	rb_define_method(cDigest, "update", ossl_digest_update, 1);
	rb_define_alias(cDigest, "<<", "update");
	rb_define_method(cDigest, "digest", ossl_digest_digest, 0);
	rb_define_method(cDigest, "hexdigest", ossl_digest_hexdigest, 0);
	rb_define_alias(cDigest, "inspect", "hexdigest");
	rb_define_alias(cDigest, "to_s", "hexdigest");
	/*rb_define_method(cDigest, "==", ossl_digest_equal, 1);*/

/*
 * automation for classes creation and initialize method binding
 */
#define DefDigest(name, func) 									\
	c##name = rb_define_class_under(module, #name, cDigest);				\
	rb_define_method(c##name, "initialize", ossl_##func##_initialize, -1)

/*
 * create classes and bind initialize method
 */
#if !defined(NO_MD2) && !defined(OPENSSL_NO_MD2)
	DefDigest(MD2, md2);
#else
#	warning >>> OpenSSL is compiled without MD2 support <<<
	rb_warning("OpenSSL is compiled without MD2 support");
#endif /* NO_MD2 */
	
#if !defined(NO_MD4) && !defined(OPENSSL_NO_MD4)
	DefDigest(MD4, md4);
#else
#	warning >>> OpenSSL is compiled without MD4 support <<<
	rb_warning("OpenSSL is compiled without MD4 support");
#endif /* NO_MD4 */
	
#if !defined(NO_MD5) && !defined(OPENSSL_NO_MD5)
	DefDigest(MD5, md5);
#else
#	warning >>> OpenSSL is compiled without MD5 support <<<
	rb_warning("OpenSSL is compiled without MD5 support");
#endif /* NO_MD5 */
	
#if !defined(NO_SHA) && !defined(OPENSSL_NO_SHA)
	DefDigest(SHA, sha);
	DefDigest(SHA1, sha1);
	DefDigest(DSS, dss);
	DefDigest(DSS1, dss1);
#else
#	warning >>> OpenSSL is compiled without SHA, DSS support <<<
	rb_warning("OpenSSL is compiled without SHA, DSS support");
#endif /* NO_SHA */
	
#if !defined(NO_RIPEMD) && !defined(OPENSSL_NO_RIPEMD)
	DefDigest(RIPEMD160, ripemd160);
#else
#	warning >>> OpenSSL is compiled without RIPEMD160 support <<<
	rb_warning("OpenSSL is compiled without RIPEMD160 support");
#endif /* NO_RIPEMD */
	
#if !defined(NO_MDC2) && !defined(OPENSSL_NO_MDC2)
	DefDigest(MDC2, mdc2);
#else
#	warning >>> OpenSSL is compiled without MDC2 support <<<
	rb_warning("OpenSSL is compiled without MDC2 support");
#endif /* NO_MDC2 */
	
} /* Init_ */

