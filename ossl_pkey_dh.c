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
#if !defined(OPENSSL_NO_DH)

#include "ossl.h"

#define GetPKeyDH(obj, pkey) do { \
    GetPKey(obj, pkey); \
    if (EVP_PKEY_type(pkey->type) != EVP_PKEY_DH) { /* PARANOIA? */ \
	ossl_raise(rb_eRuntimeError, "THIS IS NOT A DH!") ; \
    } \
} while (0)

#define DH_PRIVATE(dh) ((dh)->priv_key)

/*
 * Classes
 */
VALUE cDH;
VALUE eDHError;

/*
 * Public
 */
static VALUE
dh_instance(VALUE klass, DH *dh)
{
    EVP_PKEY *pkey;
    VALUE obj;
	
    if (!dh) {
	return Qfalse;
    }
    if (!(pkey = EVP_PKEY_new())) {
	return Qfalse;
    }
    if (!EVP_PKEY_assign_DH(pkey, dh)) {
	EVP_PKEY_free(pkey);
	return Qfalse;
    }
    WrapPKey(klass, obj, pkey);

    return obj;
}

VALUE
ossl_dh_new(EVP_PKEY *pkey)
{
    VALUE obj;

    if (!pkey) {
	obj = dh_instance(cDH, DH_new());
    } else {
	if (EVP_PKEY_type(pkey->type) != EVP_PKEY_DH) {
	    ossl_raise(rb_eTypeError, "Not a DH key!");
	}
	WrapPKey(cDH, obj, pkey);
    }
    if (obj == Qfalse) {
	ossl_raise(eDHError, "");
    }

    return obj;
}

/*
 * Private
 */
/*
 * CB for yielding when generating DH params
 */
static void
ossl_dh_generate_cb(int p, int n, void *arg)
{
    VALUE ary;

    ary = rb_ary_new2(2);
    rb_ary_store(ary, 0, INT2NUM(p));
    rb_ary_store(ary, 1, INT2NUM(n));

    rb_yield(ary);
}

static DH *
dh_generate(int size, int gen)
{
    DH *dh;
    void (*cb)(int, int, void *) = NULL;

    if (rb_block_given_p()) {
	cb = ossl_dh_generate_cb;
    }
    /* arg to cb = NULL */
    if (!(dh = DH_generate_parameters(size, gen, cb, NULL))) {
	return 0;
    }
    if (!DH_generate_key(dh)) {
	DH_free(dh);
	return 0;
    }

    return dh;
}

static VALUE
ossl_dh_s_generate(int argc, VALUE *argv, VALUE klass)
{
    DH *dh ;
    int g = 2;
    VALUE size, gen, obj;
	
    if (rb_scan_args(argc, argv, "11", &size, &gen) == 2) {
	g = FIX2INT(gen);
    }
    dh = dh_generate(FIX2INT(size), g);
    obj = dh_instance(klass, dh);
    if (obj == Qfalse) {
	DH_free(dh);
	ossl_raise(eDHError, "");
    }

    return obj;
}

static VALUE
ossl_dh_initialize(int argc, VALUE *argv, VALUE self)
{
    EVP_PKEY *pkey;
    DH *dh;
    int g = 2;
    BIO *in;
    VALUE buffer, gen;

    GetPKeyDH(self, pkey);
    rb_scan_args(argc, argv, "11", &buffer, &gen);
    if (FIXNUM_P(buffer)) {
	if (!NIL_P(gen)) {
	    g = FIX2INT(gen);
	}
	if (!(dh = dh_generate(FIX2INT(buffer), g))) {
	    ossl_raise(eDHError, "");
	}
    } else {
	StringValue(buffer);
	in = BIO_new_mem_buf(RSTRING(buffer)->ptr, RSTRING(buffer)->len);
	if (!in){
	    ossl_raise(eDHError, "");
	}
	if (!(dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL))) {
	    BIO_free(in);
	    ossl_raise(eDHError, "");
	}
	BIO_free(in);
    }
    if (!EVP_PKEY_assign_DH(pkey, dh)) {
	DH_free(dh);
	ossl_raise(eRSAError, "");
    }
    return self;
}

static VALUE
ossl_dh_is_public(VALUE self)
{
    EVP_PKEY *pkey;

    GetPKeyDH(self, pkey);
    /*
     * Do we need to check dhp->dh->public_pkey?
     * return Qtrue;
     */
    return (pkey->pkey.dh->pub_key) ? Qtrue : Qfalse;
}

static VALUE
ossl_dh_is_private(VALUE self)
{
    EVP_PKEY *pkey;

    GetPKeyDH(self, pkey);
	
    return (DH_PRIVATE(pkey->pkey.dh)) ? Qtrue : Qfalse;
}

static VALUE
ossl_dh_export(VALUE self)
{
    EVP_PKEY *pkey;
    BIO *out;
    BUF_MEM *buf;
    VALUE str;

    GetPKeyDH(self, pkey);
    if (!(out = BIO_new(BIO_s_mem()))) {
	ossl_raise(eDHError, "");
    }
    if (!PEM_write_bio_DHparams(out, pkey->pkey.dh)) {
	BIO_free(out);
	ossl_raise(eDHError, "");
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
ossl_dh_to_text(VALUE self)
{
    EVP_PKEY *pkey;
    BIO *out;
    BUF_MEM *buf;
    VALUE str;

    GetPKeyDH(self, pkey);
    if (!(out = BIO_new(BIO_s_mem()))) {
	ossl_raise(eDHError, "");
    }
    if (!DHparams_print(out, pkey->pkey.dh)) {
	BIO_free(out);
	ossl_raise(eDHError, "");
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
    EVP_PKEY *pkey;
    DH *dh;
    VALUE obj;
	
    GetPKeyDH(self, pkey);
    dh = DHparams_dup(pkey->pkey.dh); /* err check perfomed by dh_instance */
    obj = dh_instance(CLASS_OF(self), dh);
    if (obj == Qfalse) {
	DH_free(dh);
	ossl_raise(eDHError, "");
    }

    return obj;
}

/*
 * INIT
 */
void
Init_ossl_dh()
{
    eDHError = rb_define_class_under(mPKey, "DHError", ePKeyError);

    cDH = rb_define_class_under(mPKey, "DH", cPKey);
	
    rb_define_singleton_method(cDH, "generate", ossl_dh_s_generate, -1);
    rb_define_method(cDH, "initialize", ossl_dh_initialize, -1);

    rb_define_method(cDH, "public?", ossl_dh_is_public, 0);
    rb_define_method(cDH, "private?", ossl_dh_is_private, 0);
    rb_define_method(cDH, "to_text", ossl_dh_to_text, 0);
    rb_define_method(cDH, "export", ossl_dh_export, 0);
    rb_define_alias(cDH, "to_pem", "export");
    rb_define_alias(cDH, "to_s", "export");
    rb_define_method(cDH, "public_key", ossl_dh_to_public_key, 0);
}

#else /* defined NO_DH */
#   warning >>> OpenSSL is compiled without DH support <<<

void
Init_ossl_dh()
{
    rb_warning("OpenSSL is compiled without DH support");
}
#endif /* NO_DH */

