/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

#define MakeSPKI(obj, spkip) {\
	obj = Data_Make_Struct(cSPKI, ossl_spki, 0, ossl_spki_free, spkip);\
}
#define GetSPKI(obj, spkip) Data_Get_Struct(obj, ossl_spki, spkip)

/*
 * Classes
 */
VALUE cSPKI;
VALUE eSPKIError;

/*
 * Struct
 */
typedef struct ossl_spki_st {
	NETSCAPE_SPKI *spki;
} ossl_spki;

static void
ossl_spki_free(ossl_spki *spkip)
{
	if(spkip) {
		if(spkip->spki) NETSCAPE_SPKI_free(spkip->spki);
		spkip->spki = NULL;
		free(spkip);
	}
}

/*
 * Public functions
 */

/*
 * Private functions
 */
static VALUE
ossl_spki_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_spki *spkip = NULL;
	VALUE obj;
	
	MakeSPKI(obj, spkip);
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_spki_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_spki *spkip = NULL;
	NETSCAPE_SPKI *spki = NULL;
	VALUE buffer;
	
	GetSPKI(self, spkip);

	rb_scan_args(argc, argv, "01", &buffer);

	switch (TYPE(buffer)) {
		case T_NIL:
			spki = NETSCAPE_SPKI_new();
			break;
		case T_STRING:
			Check_SafeStr(buffer);
			spki = NETSCAPE_SPKI_b64_decode(RSTRING(buffer)->ptr, -1);
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported type");
	}
	if (!spki)
		rb_raise(eSPKIError, "%s", ossl_error());

	spkip->spki = spki;

	return self;
}

static VALUE
ossl_spki_to_pem(VALUE self)
{
	ossl_spki *spkip = NULL;
	char *data = NULL;
	VALUE str;
	
	GetSPKI(self, spkip);

	if (!(data = NETSCAPE_SPKI_b64_encode(spkip->spki))) {
		rb_raise(eSPKIError, "%s", ossl_error());
	}

	str = rb_str_new2(data);
	OPENSSL_free(data);

	return str;
}

static VALUE
ossl_spki_to_str(VALUE self)
{
	ossl_spki *spkip = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetSPKI(self, spkip);

	if (!(out = BIO_new(BIO_s_mem()))) {
		rb_raise(eSPKIError, "%s", ossl_error());
	}
	if (!NETSCAPE_SPKI_print(out, spkip->spki)) {
		BIO_free(out);
		rb_raise(eSPKIError, "%s", ossl_error());
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE
ossl_spki_get_public_key(VALUE self)
{
	ossl_spki *spkip = NULL;
	EVP_PKEY *pkey = NULL;

	GetSPKI(self, spkip);
	
	if (!(pkey = NETSCAPE_SPKI_get_pubkey(spkip->spki))) {
		rb_raise(eSPKIError, "%s", ossl_error());
	}

	return ossl_pkey_new(pkey);
}

static VALUE
ossl_spki_set_public_key(VALUE self, VALUE pubk)
{
	ossl_spki *spkip = NULL;
	EVP_PKEY *pkey = NULL;

	GetSPKI(self, spkip);
	OSSL_Check_Type(pubk, cPKey);
	
	pkey = ossl_pkey_get_EVP_PKEY(pubk);

	if (!NETSCAPE_SPKI_set_pubkey(spkip->spki, pkey)) {
		EVP_PKEY_free(pkey);
		rb_raise(eSPKIError, "%s", ossl_error());
	}

	return self;
}

static VALUE
ossl_spki_get_challenge(VALUE self)
{
	ossl_spki *spkip = NULL;
	VALUE str;

	GetSPKI(self, spkip);

	if (spkip->spki->spkac->challenge->length > 0)
		return rb_str_new(spkip->spki->spkac->challenge->data, spkip->spki->spkac->challenge->length);
	
	return rb_str_new2("");
}

static VALUE
ossl_spki_set_challenge(VALUE self, VALUE str)
{
	ossl_spki *spkip = NULL;

	GetSPKI(self, spkip);
	Check_SafeStr(str);

	if (!ASN1_STRING_set(spkip->spki->spkac->challenge, RSTRING(str)->ptr, RSTRING(str)->len)) {
		rb_raise(eSPKIError, "%s", ossl_error());
	}

	return str;
}

static VALUE
ossl_spki_sign(VALUE self, VALUE key, VALUE digest)
{
	ossl_spki *spkip = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetSPKI(self, spkip);
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(digest, cDigest);
	
	if (rb_funcall(key, rb_intern("private?"), 0, NULL) == Qfalse) {
		rb_raise(eSPKIError, "PRIVATE key needed to sign REQ!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	md = ossl_digest_get_EVP_MD(digest);

	if (!NETSCAPE_SPKI_sign(spkip->spki, pkey, md)) {
		EVP_PKEY_free(pkey);
		rb_raise(eSPKIError, "%s", ossl_error());
	}

	return self;
}

/*
 * Checks that cert signature is made with PRIVversion of this PUBLIC 'key'
 */
static VALUE
ossl_spki_verify(VALUE self, VALUE key)
{
	ossl_spki *spkip = NULL;
	EVP_PKEY *pkey = NULL;
	int i = 0;

	GetSPKI(self, spkip);
	OSSL_Check_Type(key, cPKey);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);

	i = NETSCAPE_SPKI_verify(spkip->spki, pkey);
	
	if (i < 0) {
		rb_raise(eSPKIError, "%s", ossl_error());
	} else if (i > 0)
		return Qtrue;

	return Qfalse;
}

/*
 * NETSCAPE_SPKI init
 */
void
Init_ossl_spki(VALUE module)
{
	eSPKIError = rb_define_class_under(module, "SPKIError", rb_eStandardError);
	
	cSPKI = rb_define_class_under(module, "SPKI", rb_cObject);
	rb_define_singleton_method(cSPKI, "new", ossl_spki_s_new, -1);
	rb_define_method(cSPKI, "initialize", ossl_spki_initialize, -1);
	rb_define_method(cSPKI, "to_pem", ossl_spki_to_pem, 0);
	rb_define_method(cSPKI, "to_str", ossl_spki_to_str, 0);
	rb_define_method(cSPKI, "public_key", ossl_spki_get_public_key, 0);
	rb_define_method(cSPKI, "public_key=", ossl_spki_set_public_key, 1);
	rb_define_method(cSPKI, "sign", ossl_spki_sign, 2);
	rb_define_method(cSPKI, "verify", ossl_spki_verify, 1);
	rb_define_method(cSPKI, "challenge", ossl_spki_get_challenge, 0);
	rb_define_method(cSPKI, "challenge=", ossl_spki_set_challenge, 1);
}

