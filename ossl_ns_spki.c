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

#define WrapSPKI(obj, spkip) obj = Data_Wrap_Struct(cSPKI, 0, NETSCAPE_SPKI_free, spki)
#define GetSPKI(obj, spki) Data_Get_Struct(obj, NETSCAPE_SPKI, spki)

/*
 * Classes
 */
VALUE cSPKI;
VALUE eSPKIError;

/*
 * Public functions
 */

/*
 * Private functions
 */
static VALUE
ossl_spki_s_new(int argc, VALUE *argv, VALUE klass)
{
	NETSCAPE_SPKI *spki = NULL;
	VALUE obj;
	
	if (!(spki = NETSCAPE_SPKI_new())) {
		OSSL_Raise(eSPKIError, "");
	}
	
	WrapSPKI(obj, spki);
	
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_spki_initialize(int argc, VALUE *argv, VALUE self)
{
	NETSCAPE_SPKI *spki = NULL;
	VALUE buffer;
	
	if (argc == 0)
		return self;
	
	buffer = rb_String(argv[0]);
	
	if (!(spki = NETSCAPE_SPKI_b64_decode(RSTRING(buffer)->ptr, -1))) {
		OSSL_Raise(eSPKIError, "");
	}

	NETSCAPE_SPKI_free(DATA_PTR(self));
	DATA_PTR(self) = spki;

	return self;
}

static VALUE
ossl_spki_to_pem(VALUE self)
{
	NETSCAPE_SPKI *spki = NULL;
	char *data = NULL;
	VALUE str;
	
	GetSPKI(self, spki);

	if (!(data = NETSCAPE_SPKI_b64_encode(spki))) {
		OSSL_Raise(eSPKIError, "");
	}

	str = rb_str_new2(data);
	OPENSSL_free(data);

	return str;
}

static VALUE
ossl_spki_to_text(VALUE self)
{
	NETSCAPE_SPKI *spki = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetSPKI(self, spki);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eSPKIError, "");
	}
	if (!NETSCAPE_SPKI_print(out, spki)) {
		BIO_free(out);
		OSSL_Raise(eSPKIError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE
ossl_spki_get_public_key(VALUE self)
{
	NETSCAPE_SPKI *spki = NULL;
	EVP_PKEY *pkey = NULL;

	GetSPKI(self, spki);
	
	if (!(pkey = NETSCAPE_SPKI_get_pubkey(spki))) {
		OSSL_Raise(eSPKIError, "");
	}

	return ossl_pkey_new(pkey);
}

static VALUE
ossl_spki_set_public_key(VALUE self, VALUE pubk)
{
	NETSCAPE_SPKI *spki = NULL;
	EVP_PKEY *pkey = NULL;

	GetSPKI(self, spki);
	
	pkey = ossl_pkey_get_EVP_PKEY(pubk);

	if (!NETSCAPE_SPKI_set_pubkey(spki, pkey)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eSPKIError, "");
	}

	return pubk;
}

static VALUE
ossl_spki_get_challenge(VALUE self)
{
	NETSCAPE_SPKI *spki = NULL;

	GetSPKI(self, spki);

	if (spki->spkac->challenge->length > 0)
		return rb_str_new(spki->spkac->challenge->data, spki->spkac->challenge->length);
	
	return rb_str_new2("");
}

static VALUE
ossl_spki_set_challenge(VALUE self, VALUE str)
{
	NETSCAPE_SPKI *spki = NULL;

	GetSPKI(self, spki);
	
	str = rb_String(str);

	if (!ASN1_STRING_set(spki->spkac->challenge, RSTRING(str)->ptr, RSTRING(str)->len)) {
		OSSL_Raise(eSPKIError, "");
	}

	return str;
}

static VALUE
ossl_spki_sign(VALUE self, VALUE key, VALUE digest)
{
	NETSCAPE_SPKI *spki = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetSPKI(self, spki);
	
	md = ossl_digest_get_EVP_MD(digest);
	
	if (rb_funcall(key, id_private_q, 0, NULL) == Qfalse) {
		rb_raise(eSPKIError, "PRIVATE key needed to sign REQ!");
	}
	pkey = ossl_pkey_get_EVP_PKEY(key);

	if (!NETSCAPE_SPKI_sign(spki, pkey, md)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eSPKIError, "");
	}

	return self;
}

/*
 * Checks that cert signature is made with PRIVversion of this PUBLIC 'key'
 */
static VALUE
ossl_spki_verify(VALUE self, VALUE key)
{
	NETSCAPE_SPKI *spki = NULL;
	EVP_PKEY *pkey = NULL;
	int result = 0;

	GetSPKI(self, spki);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);

	result = NETSCAPE_SPKI_verify(spki, pkey);
	EVP_PKEY_free(pkey);
	
	if (result < 0) {
		OSSL_Raise(eSPKIError, "");
	} else if (result > 0)
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
	rb_define_alias(cSPKI, "to_s", "to_pem");
	rb_define_method(cSPKI, "to_text", ossl_spki_to_text, 0);
	rb_define_method(cSPKI, "public_key", ossl_spki_get_public_key, 0);
	rb_define_method(cSPKI, "public_key=", ossl_spki_set_public_key, 1);
	rb_define_method(cSPKI, "sign", ossl_spki_sign, 2);
	rb_define_method(cSPKI, "verify", ossl_spki_verify, 1);
	rb_define_method(cSPKI, "challenge", ossl_spki_get_challenge, 0);
	rb_define_method(cSPKI, "challenge=", ossl_spki_set_challenge, 1);
}

