/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

#define MakeX509CRL(obj, crlp) {\
	obj = Data_Make_Struct(cX509CRL, ossl_x509crl, 0, ossl_x509crl_free, crlp);\
}
#define GetX509CRL_unsafe(obj, crlp) Data_Get_Struct(obj, ossl_x509crl, crlp)
#define GetX509CRL(obj, crlp) {\
	GetX509CRL_unsafe(obj, crlp);\
	if (!crlp->crl) rb_raise(eX509CRLError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cX509CRL;
VALUE eX509CRLError;

/*
 * Struct
 */
typedef struct ossl_x509crl_st {
	X509_CRL *crl;
} ossl_x509crl;

static void 
ossl_x509crl_free(ossl_x509crl *crlp)
{
	if (crlp) {
		if (crlp->crl) X509_CRL_free(crlp->crl);
		crlp->crl = NULL;
		free(crlp);
	}
}

/*
 * PUBLIC
 */
X509_CRL *
ossl_x509crl_get_X509_CRL(VALUE obj)
{
	ossl_x509crl *crlp = NULL;
	X509_CRL *crl = NULL;
	
	OSSL_Check_Type(obj, cX509CRL);
	
	GetX509CRL(obj, crlp);

	if (!(crl = X509_CRL_dup(crlp->crl))) {
		OSSL_Raise(eX509CRLError, "");
	}

	return crl;
}

/*
 * PRIVATE
 */
static VALUE 
ossl_x509crl_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_x509crl *crlp = NULL;
	VALUE obj;

	MakeX509CRL(obj, crlp);

	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE 
ossl_x509crl_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_x509crl *crlp = NULL;
	X509_CRL *crl = NULL;
	BIO *in = NULL;
	VALUE buffer;
	
	GetX509CRL_unsafe(self, crlp);
	
	rb_scan_args(argc, argv, "01", &buffer);

	switch (TYPE(buffer)) {
		case T_NIL:
			crl = X509_CRL_new();
			break;
		case T_STRING:
			if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, -1))) {
				OSSL_Raise(eX509CRLError, "");
			}
			crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
			BIO_free(in);
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported type");
	}
	if (!crl)
		OSSL_Raise(eX509CRLError, "");

	crlp->crl = crl;

	return self;
}

static VALUE 
ossl_x509crl_get_version(VALUE self)
{
	ossl_x509crl *crlp = NULL;
	long ver = 0;

	GetX509CRL(self, crlp);

	ver = ASN1_INTEGER_get(crlp->crl->crl->version);

	return INT2NUM(ver);
}

static VALUE 
ossl_x509crl_set_version(VALUE self, VALUE version)
{
	ossl_x509crl *crlp = NULL;
	ASN1_INTEGER *asn1int = NULL;
	
	GetX509CRL(self, crlp);

	if (!(asn1int = ASN1_INTEGER_new())) {
		OSSL_Raise(eX509CRLError, "");
	}
	if (!ASN1_INTEGER_set(asn1int, NUM2LONG(version))) {
		OSSL_Raise(eX509CRLError, "");
	}
	
	ASN1_INTEGER_free(crlp->crl->crl->version);
	crlp->crl->crl->version = asn1int;

	return version;
}

static VALUE 
ossl_x509crl_get_issuer(VALUE self)
{
	ossl_x509crl *crlp = NULL;
	
	GetX509CRL(self, crlp);
	
	return ossl_x509name_new(crlp->crl->crl->issuer);
}

static VALUE 
ossl_x509crl_set_issuer(VALUE self, VALUE issuer)
{
	ossl_x509crl *crlp = NULL;
	X509_NAME *name = NULL;
	
	GetX509CRL(self, crlp);

	OSSL_Check_Type(issuer, cX509Name);
	name = ossl_x509name_get_X509_NAME(issuer);
	
	if (!X509_NAME_set(&(crlp->crl->crl->issuer), name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		OSSL_Raise(eX509CRLError, "");
	}
	X509_NAME_free(name);
	
	return issuer;
}

static VALUE 
ossl_x509crl_get_last_update(VALUE self)
{
	ossl_x509crl *crlp = NULL;

	GetX509CRL(self, crlp);

	return asn1time_to_time(crlp->crl->crl->lastUpdate);
}

static VALUE 
ossl_x509crl_set_last_update(VALUE self, VALUE time)
{
	ossl_x509crl *crlp = NULL;
	VALUE sec;
	
	GetX509CRL(self, crlp);

	OSSL_Check_Type(time, rb_cTime);
	sec = rb_funcall(time, rb_intern("to_i"), 0, NULL);
	
	if (!FIXNUM_P(sec))
		rb_raise(eX509CRLError, "wierd time");

	if (!ASN1_UTCTIME_set(crlp->crl->crl->lastUpdate, FIX2INT(sec))) {
		OSSL_Raise(eX509CRLError, "");
	}

	return time;
}

static VALUE 
ossl_x509crl_get_next_update(VALUE self)
{
	ossl_x509crl *crlp = NULL;

	GetX509CRL(self, crlp);

	return asn1time_to_time(crlp->crl->crl->nextUpdate);
}

static VALUE 
ossl_x509crl_set_next_update(VALUE self, VALUE time)
{
	ossl_x509crl *crlp = NULL;
	VALUE sec;

	GetX509CRL(self, crlp);

	OSSL_Check_Type(time, rb_cTime);
	sec = rb_funcall(time, rb_intern("to_i"), 0, NULL);
	
	if (!FIXNUM_P(sec))
		rb_raise(eX509CRLError, "wierd time");

	if (!ASN1_UTCTIME_set(crlp->crl->crl->nextUpdate, FIX2INT(sec))) {
		OSSL_Raise(eX509CRLError, "");
	}

	return time;
}

static VALUE 
ossl_x509crl_get_revoked(VALUE self)
{
	ossl_x509crl *crlp = NULL;
	int i, num = 0;
	X509_REVOKED *rev = NULL;
	VALUE ary, revoked;

	GetX509CRL(self, crlp);

	num = sk_X509_CRL_num(crlp->crl->crl->revoked);

	if (num < 0)
		return rb_ary_new();

	ary = rb_ary_new2(num);

	for(i=0; i<num; i++) {
		rev = (X509_REVOKED *)sk_X509_CRL_value(crlp->crl->crl->revoked, i); /* NO DUP - don't free! */
		revoked = ossl_x509revoked_new(rev);
		rb_ary_push(ary, revoked);
	}

	return ary;
}

static VALUE 
ossl_x509crl_set_revoked(VALUE self, VALUE ary)
{
	ossl_x509crl *crlp = NULL;
	X509_REVOKED *rev = NULL;
	int i;

	GetX509CRL(self, crlp);

	Check_Type(ary, T_ARRAY);
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary members should be X509 Revoked */
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Revoked);
	}
	
	sk_X509_REVOKED_pop_free(crlp->crl->crl->revoked, X509_REVOKED_free);
	crlp->crl->crl->revoked = NULL;
	M_ASN1_New(crlp->crl->crl->revoked, sk_X509_REVOKED_new_null);
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		rev = ossl_x509revoked_get_X509_REVOKED(RARRAY(ary)->ptr[i]);

		if (!sk_X509_CRL_push(crlp->crl->crl->revoked, rev)) { /* NO DUP - don't free! */
			OSSL_Raise(eX509CRLError, "");
		}
	}
	sk_X509_REVOKED_sort(crlp->crl->crl->revoked);
	
	return ary;
}

static VALUE 
ossl_x509crl_add_revoked(VALUE self, VALUE revoked)
{
	ossl_x509crl *crlp = NULL;
	X509_REVOKED *rev = NULL;

	GetX509CRL(self, crlp);

	OSSL_Check_Type(revoked, cX509Revoked);
	rev = ossl_x509revoked_get_X509_REVOKED(revoked);

	if (!sk_X509_CRL_push(crlp->crl->crl->revoked, rev)) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CRLError, "");
	}
	sk_X509_REVOKED_sort(crlp->crl->crl->revoked);
	
	return revoked;
}

static VALUE 
ossl_x509crl_sign(VALUE self, VALUE key, VALUE digest)
{
	ossl_x509crl *crlp = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetX509CRL(self, crlp);

	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(digest, cDigest);
	
	if (rb_funcall(key, rb_intern("private?"), 0, NULL) == Qfalse) {
		rb_raise(eX509CRLError, "PRIVATE key needed to sign CRL!");
	}
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	md = ossl_digest_get_EVP_MD(digest);
	
	if (!X509_CRL_sign(crlp->crl, pkey, md)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509CRLError, "");
	}
	EVP_PKEY_free(pkey);

	return self;
}

static VALUE 
ossl_x509crl_verify(VALUE self, VALUE key)
{
	ossl_x509crl *crlp = NULL;
	EVP_PKEY *pkey = NULL;
	int result = 0;

	GetX509CRL(self, crlp);

	OSSL_Check_Type(key, cPKey);
	pkey = ossl_pkey_get_EVP_PKEY(key);

	result = X509_CRL_verify(crlp->crl, pkey);
	EVP_PKEY_free(pkey);

	if (result == 1) return Qtrue;
	return Qfalse;
}

static VALUE 
ossl_x509crl_to_pem(VALUE self)
{
	ossl_x509crl *crlp = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetX509CRL(self, crlp);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CRLError, "");
	}
	if (!PEM_write_bio_X509_CRL(out, crlp->crl)) {
		BIO_free(out);
		OSSL_Raise(eX509CRLError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE 
ossl_x509crl_to_str(VALUE self)
{
	ossl_x509crl *crlp = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetX509CRL(self, crlp);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CRLError, "");
	}
	if (!X509_CRL_print(out, crlp->crl)) {
		BIO_free(out);
		OSSL_Raise(eX509CRLError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

/*
 * Gets X509v3 extensions as array of X509Ext objects
 */
static VALUE 
ossl_x509crl_get_extensions(VALUE self)
{
	ossl_x509crl *crlp = NULL;
	int count = 0, i;
	X509_EXTENSION *ext = NULL;
	VALUE ary;

	GetX509CRL(self, crlp);

	count = X509_CRL_get_ext_count(crlp->crl);

	if (count > 0) 
		ary = rb_ary_new2(count);
	else
		return rb_ary_new();

	for (i=0; i<count; i++) {
		ext = X509_CRL_get_ext(crlp->crl, i); /* NO DUP - don't free! */
		rb_ary_push(ary, ossl_x509ext_new(ext));
	}
	
	return ary;
}

/*
 * Sets X509_EXTENSIONs
 */
static VALUE 
ossl_x509crl_set_extensions(VALUE self, VALUE ary)
{
	ossl_x509crl *crlp = NULL;
	X509_EXTENSION *ext = NULL;
	int i = 0;
	
	GetX509CRL(self, crlp);

	Check_Type(ary, T_ARRAY);
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary members should be X509 Extensions */
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Extension);
	}

	sk_X509_EXTENSION_pop_free(crlp->crl->crl->extensions, X509_EXTENSION_free);
	crlp->crl->crl->extensions = NULL;

	for (i=0; i<RARRAY(ary)->len; i++) {
		ext = ossl_x509ext_get_X509_EXTENSION(RARRAY(ary)->ptr[i]);

		if(!X509_CRL_add_ext(crlp->crl, ext, -1)) { /* DUPs ext - FREE it */
			X509_EXTENSION_free(ext);
			OSSL_Raise(eX509CRLError, "");
		}
		X509_EXTENSION_free(ext);
	}

	return ary;
}

static VALUE 
ossl_x509crl_add_extension(VALUE self, VALUE extension)
{
	ossl_x509crl *crlp = NULL;
	X509_EXTENSION *ext = NULL;

	GetX509CRL(self, crlp);

	OSSL_Check_Type(extension, cX509Extension);
	ext = ossl_x509ext_get_X509_EXTENSION(extension);
	
	if(!X509_CRL_add_ext(crlp->crl, ext, -1)) { /* DUPs ext - FREE it */
		X509_EXTENSION_free(ext);
		OSSL_Raise(eX509CRLError, "");
	}
	X509_EXTENSION_free(ext);

	return extension;
}

/*
 * INIT
 */
void 
Init_ossl_x509crl(VALUE module)
{
	eX509CRLError = rb_define_class_under(module, "CRLError", rb_eStandardError);

	cX509CRL = rb_define_class_under(module, "CRL", rb_cObject);
	rb_define_singleton_method(cX509CRL, "new", ossl_x509crl_s_new, -1);
	rb_define_method(cX509CRL, "initialize", ossl_x509crl_initialize, -1);
	rb_define_method(cX509CRL, "version", ossl_x509crl_get_version, 0);
	rb_define_method(cX509CRL, "version=", ossl_x509crl_set_version, 1);
	rb_define_method(cX509CRL, "issuer", ossl_x509crl_get_issuer, 0);
	rb_define_method(cX509CRL, "issuer=", ossl_x509crl_set_issuer, 1);
	rb_define_method(cX509CRL, "last_update", ossl_x509crl_get_last_update, 0);
	rb_define_method(cX509CRL, "last_update=", ossl_x509crl_set_last_update, 1);
	rb_define_method(cX509CRL, "next_update", ossl_x509crl_get_next_update, 0);
	rb_define_method(cX509CRL, "next_update=", ossl_x509crl_set_next_update, 1);
	rb_define_method(cX509CRL, "revoked", ossl_x509crl_get_revoked, 0);
	rb_define_method(cX509CRL, "revoked=", ossl_x509crl_set_revoked, 1);
	rb_define_method(cX509CRL, "add_revoked", ossl_x509crl_add_revoked, 1);
	rb_define_method(cX509CRL, "sign", ossl_x509crl_sign, 1);
	rb_define_method(cX509CRL, "verify", ossl_x509crl_verify, 1);
	rb_define_method(cX509CRL, "to_pem", ossl_x509crl_to_pem, 0);
	rb_define_method(cX509CRL, "to_str", ossl_x509crl_to_str, 0);
	rb_define_method(cX509CRL, "extensions", ossl_x509crl_get_extensions, 0);
	rb_define_method(cX509CRL, "extensions=", ossl_x509crl_set_extensions, 1);
	rb_define_method(cX509CRL, "add_extension", ossl_x509crl_add_extension, 1);
}

