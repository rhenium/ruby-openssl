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
#if !defined(NO_DH) && !defined(OPENSSL_NO_DH)

#include "ossl.h"
#include "ossl_pkey.h"

#define MakeDH(obj, dhp) {\
	obj = Data_Make_Struct(cDH, ossl_dh, 0, ossl_dh_free, dhp);\
	dhp->pkey.get_EVP_PKEY = ossl_dh_get_EVP_PKEY;\
}

#define GetDH(obj, dhp) {\
	Data_Get_Struct(obj, ossl_dh, dhp);\
	if (!dhp->dh) rb_raise(eDHError, "not initialized!");\
}

#define DH_PRIVATE(dh) ((dh)->priv_key)

/*
 * Classes
 */
VALUE cDH;
VALUE eDHError;

/*
 * Struct
 */
typedef struct ossl_dh_st {
	ossl_pkey pkey;
	DH *dh;
} ossl_dh;

static void
ossl_dh_free(ossl_dh *dhp)
{
	if (dhp) {
		if (dhp->dh) DH_free(dhp->dh);
		dhp->dh = NULL;
		free(dhp);
	}
}

/*
 * Public
 */
VALUE
ossl_dh_new(DH *dh)
{
	ossl_dh *dhp = NULL;
	DH *new = NULL;
	VALUE obj;

	if (!dh)
		new = DH_new();
	else new = DHparams_dup(dh);

	if (!new)
		OSSL_Raise(eDHError, "");
	
	MakeDH(obj, dhp);
	dhp->dh = new;

	return obj;
}

DH *
ossl_dh_get_DH(VALUE obj)
{
	ossl_dh *dhp = NULL;
	DH *dh = NULL;
	
	OSSL_Check_Type(obj, cDH);
	GetDH(obj, dhp);

	dh = DHparams_dup(dhp->dh);
	
	if (!dh)
		OSSL_Raise(eDHError, "");
	
	return dh;
}

EVP_PKEY *
ossl_dh_get_EVP_PKEY(VALUE obj)
{
	DH *dh = NULL;
	EVP_PKEY *pkey = NULL;

	dh = ossl_dh_get_DH(obj);

	if (!(pkey = EVP_PKEY_new())) {
		DH_free(dh);
		OSSL_Raise(eDHError, "");
	}

	if (!EVP_PKEY_assign_DH(pkey, dh)) { /* NO DUP - don't free! */
		DH_free(dh);
		EVP_PKEY_free(pkey);
		OSSL_Raise(eDHError, "");
	}

	return pkey;
}

/*
 * Private
 */
static VALUE
ossl_dh_s_new_from_pem(VALUE klass, VALUE buffer)
{
	ossl_dh *dhp = NULL;
	DH *dh = NULL;
	BIO *in = NULL;
	VALUE obj;
	
	Check_Type(buffer, T_STRING);
	
	if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, RSTRING(buffer)->len)))
		OSSL_Raise(eDHError, "");

	if (!(dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL))) {
		BIO_free(in);
		OSSL_Raise(eDHError, "");
	}
	BIO_free(in);
	
	MakeDH(obj, dhp);
	dhp->dh = dh;
	
	return obj;
}

/*
 * CB for yielding when generating DH params
 */
static void MS_CALLBACK
ossl_dh_generate_cb(int p, int n, void *arg)
{
	VALUE ary;

	ary = rb_ary_new2(2);
	rb_ary_store(ary, 0, INT2NUM(p));
	rb_ary_store(ary, 1, INT2NUM(n));
	
	rb_yield(ary);
}

static VALUE
ossl_dh_s_generate(VALUE klass, VALUE size, VALUE gen)
{
	ossl_dh *dhp = NULL;
	DH *dh = NULL;
	void (*cb)(int, int, void *) = NULL;
	VALUE obj;
	
	Check_Type(size, T_FIXNUM);
	
	if (rb_block_given_p())
		cb = ossl_dh_generate_cb;

	if (!(dh = DH_generate_parameters(FIX2INT(size), FIX2INT(gen), cb, NULL))) { /* arg to cb = NULL */
		OSSL_Raise(eDHError, "");
	}
	if (!DH_generate_key(dh)) {
		DH_free(dh);
		OSSL_Raise(eDHError, "");
	}
	
	MakeDH(obj, dhp);
	dhp->dh = dh;
	
	return obj;
}

static VALUE
ossl_dh_is_public(VALUE self)
{
	ossl_dh *dhp = NULL;

	GetDH(self, dhp);
	
	/*
	 * Do we need to check dhp->dh->public_pkey?
	 * return Qtrue;
	 */
	return (dhp->dh->pub_key) ? Qtrue : Qfalse;
}

static VALUE
ossl_dh_is_private(VALUE self)
{
	ossl_dh *dhp = NULL;
	
	GetDH(self, dhp);
	
	return (DH_PRIVATE(dhp->dh)) ? Qtrue : Qfalse;
}

static VALUE
ossl_dh_export(VALUE self)
{
	ossl_dh *dhp = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetDH(self, dhp);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eDHError, "");
	}
	
	if (!PEM_write_bio_DHparams(out, dhp->dh)) {
		BIO_free(out);
		OSSL_Raise(eDHError, "");
	}

	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

/*
 * Prints all parameters of key to buffer
 * INSECURE: PRIVATE INFORMATIONS CAN LEAK OUT!!!
 * Don't use :-)) (I's up to you)
 */
static VALUE
ossl_dh_to_str(VALUE self)
{
	ossl_dh *dhp = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetDH(self, dhp);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eDHError, "");
	}
	if (!DHparams_print(out, dhp->dh)) {
		BIO_free(out);
		OSSL_Raise(eDHError, "");
	}
	
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);

	return str;
}

/*
 * Makes new instance DH PUBLIC_KEY from PRIVATE_KEY
 */
static VALUE
ossl_dh_to_public_key(VALUE self)
{
	ossl_dh *dhp1 = NULL, *dhp2 = NULL;
	VALUE obj;
	
	GetDH(self, dhp1);

	MakeDH(obj, dhp2);
	
	if (!(dhp2->dh = DHparams_dup(dhp1->dh))) {
		OSSL_Raise(eDHError, "");
	}

	return obj;
}

/*
 * INIT
 */
void
Init_ossl_dh(VALUE mPKey, VALUE cPKey, VALUE ePKeyError)
{
	eDHError = rb_define_class_under(mPKey, "DHError", ePKeyError);

	cDH = rb_define_class_under(mPKey, "DH", cPKey);
	
	rb_define_singleton_method(cDH, "new_from_pem", ossl_dh_s_new_from_pem, 1);
	rb_define_singleton_method(cDH, "generate", ossl_dh_s_generate, 2);
	rb_define_alias(CLASS_OF(cDH), "new_from_fixnum", "generate");

	rb_define_method(cDH, "public?", ossl_dh_is_public, 0);
	rb_define_method(cDH, "private?", ossl_dh_is_private, 0);
	rb_define_method(cDH, "to_str", ossl_dh_to_str, 0);
	rb_define_method(cDH, "export", ossl_dh_export, 0);
	rb_define_alias(cDH, "to_pem", "export");
	rb_define_method(cDH, "public_key", ossl_dh_to_public_key, 0);
}

#else /* defined NO_DH */
#	warning >>> OpenSSL is compiled without DH support <<<

void
Init_ossl_dh(VALUE mPKey, VALUE cPKey, VALUE ePKeyError)
{
	rb_warning("OpenSSL is compiled without DH support");
}

#endif /* NO_DH */

