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
#if !defined(NO_HMAC) && !defined(OPENSSL_NO_HMAC)

#include "ossl.h"

#define MakeHMAC(obj, hmacp) {\
	obj = Data_Make_Struct(cHMAC, ossl_hmac, 0, ossl_hmac_free, hmacp);\
}
#define GetHMAC(obj, hmacp) Data_Get_Struct(obj, ossl_hmac, hmacp)

/*
 * Classes
 */
VALUE cHMAC;
VALUE eHMACError;

/*
 * Struct
 */
typedef struct ossl_hmac_st {
	HMAC_CTX *hmac;
} ossl_hmac;

static void
ossl_hmac_free(ossl_hmac *hmacp)
{
	if (hmacp) {
		if (hmacp->hmac) OPENSSL_free(hmacp->hmac);
		hmacp->hmac = NULL;
		free(hmacp);
	}
}

/*
 * PUBLIC
 */

/*
 * PRIVATE
 */
static VALUE
ossl_hmac_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_hmac *hmacp = NULL;
	VALUE obj;

	MakeHMAC(obj, hmacp);
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_hmac_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_hmac *hmacp = NULL;
	const EVP_MD *md = NULL;
	VALUE key, digest;

	GetHMAC(self, hmacp);

	rb_scan_args(argc, argv, "20", &key, &digest);

	Check_SafeStr(key);
	md = ossl_digest_get_EVP_MD(digest);

	if (!(hmacp->hmac = OPENSSL_malloc(sizeof(HMAC_CTX)))) {
		OSSL_Raise(eHMACError, "");
	}
	HMAC_Init(hmacp->hmac, RSTRING(key)->ptr, RSTRING(key)->len, md);

	return self;
}

static VALUE
ossl_hmac_update(VALUE self, VALUE data)
{
	ossl_hmac *hmacp = NULL;

	GetHMAC(self, hmacp);

	Check_SafeStr(data);

	HMAC_Update(hmacp->hmac, RSTRING(data)->ptr, RSTRING(data)->len);

	return self;
}

static VALUE
ossl_hmac_hmac(VALUE self)
{
	ossl_hmac *hmacp = NULL;
	char *buf = NULL;
	int buf_len = 0;
	HMAC_CTX final;
	VALUE str;
	
	GetHMAC(self, hmacp);
	
	if (!HMAC_CTX_copy(&final, hmacp->hmac)) {
		OSSL_Raise(eHMACError, "");
	}
	if (!(buf = OPENSSL_malloc(HMAC_size(&final)))) {
		OSSL_Raise(eHMACError, "Cannot allocate memory for hmac");
	}
	HMAC_Final(&final, buf, &buf_len);

	str = rb_str_new(buf, buf_len);
	OPENSSL_free(buf);
	
	return str;
}

static VALUE
ossl_hmac_hexhmac(VALUE self)
{
	ossl_hmac *hmacp = NULL;
	static const char hex[]="0123456789abcdef";
	char *buf = NULL, *hexbuf = NULL;
	int i,buf_len = 0;
	HMAC_CTX final;
	VALUE str;
	
	GetHMAC(self, hmacp);
	
	if (!HMAC_CTX_copy(&final, hmacp->hmac)) {
		OSSL_Raise(eHMACError, "Cannot copy HMAC CTX");
	}
	if (!(buf = OPENSSL_malloc(HMAC_size(&final)))) {
		OSSL_Raise(eHMACError, "Cannot allocate memory for hmac");
	}
	HMAC_Final(&final, buf, &buf_len);
	
	if (!(hexbuf = OPENSSL_malloc(2*buf_len+1))) {
		OPENSSL_free(buf);
		OSSL_Raise(eHMACError, "Memory alloc error");
	}
	for (i = 0; i < buf_len; i++) {
		hexbuf[i + i] = hex[((unsigned char)buf[i]) >> 4];
		hexbuf[i + i + 1] = hex[buf[i] & 0x0f];
	}
	hexbuf[i + i] = '\0';
	
	str = rb_str_new(hexbuf, 2*buf_len);

	OPENSSL_free(buf);
	OPENSSL_free(hexbuf);

	return str;
}

/*
 * INIT
 */
void
Init_hmac(VALUE module)
{
	eHMACError = rb_define_class_under(module, "HMACError", rb_eStandardError);
	
	cHMAC = rb_define_class_under(module, "HMAC", rb_cObject);
	rb_define_singleton_method(cHMAC, "new", ossl_hmac_s_new, -1);
	rb_define_method(cHMAC, "initialize", ossl_hmac_initialize, -1);
	rb_define_method(cHMAC, "update", ossl_hmac_update, 1);
	rb_define_alias(cHMAC, "<<", "update");
	rb_define_method(cHMAC, "hmac", ossl_hmac_hmac, 0);
	rb_define_method(cHMAC, "hexhmac", ossl_hmac_hexhmac, 0);
	rb_define_alias(cHMAC, "inspect", "hexhmac");
	rb_define_alias(cHMAC, "to_str", "hexhmac");
}

#else /* NO_HMAC */

void
Init_hmac(VALUE module)
{
	rb_warning("HMAC will NOT be avaible: OpenSSL is compiled without HMAC.");
}

#endif /* NO_HMAC */

