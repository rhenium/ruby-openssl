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

#define WrapX509CRL(obj, crl) obj = Data_Wrap_Struct(cX509CRL, 0, X509_CRL_free, crl)
#define GetX509CRL(obj, crl) Data_Get_Struct(obj, X509_CRL, crl)

/*
 * Classes
 */
VALUE cX509CRL;
VALUE eX509CRLError;

/*
 * PUBLIC
 */
X509_CRL *
ossl_x509crl_get_X509_CRL(VALUE obj)
{
	X509_CRL *crl = NULL, *new;
	
	OSSL_Check_Type(obj, cX509CRL);
	
	GetX509CRL(obj, crl);

	if (!(new = X509_CRL_dup(crl))) {
		OSSL_Raise(eX509CRLError, "");
	}

	return new;
}

/*
 * PRIVATE
 */
static VALUE 
ossl_x509crl_s_new(int argc, VALUE *argv, VALUE klass)
{
	X509_CRL *crl = NULL;
	VALUE obj;

	if (!(crl = X509_CRL_new())) {
		OSSL_Raise(eX509CRLError, "");
	}
	
	WrapX509CRL(obj, crl);
	
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE 
ossl_x509crl_initialize(int argc, VALUE *argv, VALUE self)
{
	BIO *in = NULL;
	VALUE buffer;
	
	if (argc == 0)
		return self;
	
	buffer = rb_String(argv[0]);
	
	if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, -1))) {
		OSSL_Raise(eX509CRLError, "");
	}
	if (!PEM_read_bio_X509_CRL(in, (X509_CRL **)&DATA_PTR(self), NULL, NULL)) {
		BIO_free(in);
		OSSL_Raise(eX509CRLError, "");
	}
	BIO_free(in);
	
	return self;
}

static VALUE 
ossl_x509crl_get_version(VALUE self)
{
	X509_CRL *crl = NULL;
	long ver = 0;

	GetX509CRL(self, crl);

	ver = ASN1_INTEGER_get(crl->crl->version);

	return INT2NUM(ver);
}

static VALUE 
ossl_x509crl_set_version(VALUE self, VALUE version)
{
	X509_CRL *crl = NULL;
	ASN1_INTEGER *asn1int = NULL;
	long ver = 0;
	
	GetX509CRL(self, crl);

	if ((ver = NUM2LONG(version)) < 0) {
		rb_raise(eX509CRLError, "version must be >= 0!");
	}
	if (!(asn1int = ASN1_INTEGER_new())) {
		OSSL_Raise(eX509CRLError, "");
	}
	if (!ASN1_INTEGER_set(asn1int, ver)) {
		OSSL_Raise(eX509CRLError, "");
	}
	
	ASN1_INTEGER_free(crl->crl->version);
	crl->crl->version = asn1int;

	return version;
}

static VALUE 
ossl_x509crl_get_issuer(VALUE self)
{
	X509_CRL *crl = NULL;
	
	GetX509CRL(self, crl);
	
	return ossl_x509name_new(crl->crl->issuer);
}

static VALUE 
ossl_x509crl_set_issuer(VALUE self, VALUE issuer)
{
	X509_CRL *crl = NULL;
	X509_NAME *name = NULL;
	
	GetX509CRL(self, crl);

	OSSL_Check_Type(issuer, cX509Name);
	name = ossl_x509name_get_X509_NAME(issuer);
	
	if (!X509_NAME_set(&(crl->crl->issuer), name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		OSSL_Raise(eX509CRLError, "");
	}
	X509_NAME_free(name);
	
	return issuer;
}

static VALUE 
ossl_x509crl_get_last_update(VALUE self)
{
	X509_CRL *crl = NULL;

	GetX509CRL(self, crl);

	return asn1time_to_time(crl->crl->lastUpdate);
}

static VALUE 
ossl_x509crl_set_last_update(VALUE self, VALUE time)
{
	X509_CRL *crl = NULL;
	time_t sec;
	
	GetX509CRL(self, crl);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(crl->crl->lastUpdate, sec)) {
		OSSL_Raise(eX509CRLError, "");
	}

	return time;
}

static VALUE 
ossl_x509crl_get_next_update(VALUE self)
{
	X509_CRL *crl = NULL;

	GetX509CRL(self, crl);

	return asn1time_to_time(crl->crl->nextUpdate);
}

static VALUE 
ossl_x509crl_set_next_update(VALUE self, VALUE time)
{
	X509_CRL *crl = NULL;
	time_t sec;

	GetX509CRL(self, crl);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(crl->crl->nextUpdate, sec)) {
		OSSL_Raise(eX509CRLError, "");
	}

	return time;
}

static VALUE 
ossl_x509crl_get_revoked(VALUE self)
{
	X509_CRL *crl = NULL;
	int i, num = 0;
	X509_REVOKED *rev = NULL;
	VALUE ary, revoked;

	GetX509CRL(self, crl);

	num = sk_X509_CRL_num(crl->crl->revoked);

	if (num < 0)
		return rb_ary_new();

	ary = rb_ary_new2(num);

	for(i=0; i<num; i++) {
		rev = (X509_REVOKED *)sk_X509_CRL_value(crl->crl->revoked, i); /* NO DUP - don't free! */
		revoked = ossl_x509revoked_new(rev);
		rb_ary_push(ary, revoked);
	}

	return ary;
}

static VALUE 
ossl_x509crl_set_revoked(VALUE self, VALUE ary)
{
	X509_CRL *crl = NULL;
	X509_REVOKED *rev = NULL;
	int i;

	GetX509CRL(self, crl);

	Check_Type(ary, T_ARRAY);
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary members should be X509 Revoked */
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Revoked);
	}
	
	sk_X509_REVOKED_pop_free(crl->crl->revoked, X509_REVOKED_free);
	crl->crl->revoked = NULL;
	M_ASN1_New(crl->crl->revoked, sk_X509_REVOKED_new_null);
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		rev = ossl_x509revoked_get_X509_REVOKED(RARRAY(ary)->ptr[i]);

		if (!sk_X509_CRL_push(crl->crl->revoked, rev)) { /* NO DUP - don't free! */
			OSSL_Raise(eX509CRLError, "");
		}
	}
	sk_X509_REVOKED_sort(crl->crl->revoked);
	
	return ary;
}

static VALUE 
ossl_x509crl_add_revoked(VALUE self, VALUE revoked)
{
	X509_CRL *crl = NULL;
	X509_REVOKED *rev = NULL;

	GetX509CRL(self, crl);

	OSSL_Check_Type(revoked, cX509Revoked);
	rev = ossl_x509revoked_get_X509_REVOKED(revoked);

	if (!sk_X509_CRL_push(crl->crl->revoked, rev)) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CRLError, "");
	}
	sk_X509_REVOKED_sort(crl->crl->revoked);
	
	return revoked;
}

static VALUE 
ossl_x509crl_sign(VALUE self, VALUE key, VALUE digest)
{
	X509_CRL *crl = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetX509CRL(self, crl);

	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(digest, cDigest);
	
	if (rb_funcall(key, id_private_q, 0, NULL) == Qfalse) {
		rb_raise(eX509CRLError, "PRIVATE key needed to sign CRL!");
	}
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	md = ossl_digest_get_EVP_MD(digest);
	
	if (!X509_CRL_sign(crl, pkey, md)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509CRLError, "");
	}
	EVP_PKEY_free(pkey);

	return self;
}

static VALUE 
ossl_x509crl_verify(VALUE self, VALUE key)
{
	X509_CRL *crl = NULL;
	EVP_PKEY *pkey = NULL;
	int result = 0;

	GetX509CRL(self, crl);

	OSSL_Check_Type(key, cPKey);
	pkey = ossl_pkey_get_EVP_PKEY(key);

	result = X509_CRL_verify(crl, pkey);
	EVP_PKEY_free(pkey);

	if (result == 1) return Qtrue;
	return Qfalse;
}

static VALUE 
ossl_x509crl_to_pem(VALUE self)
{
	X509_CRL *crl = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetX509CRL(self, crl);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CRLError, "");
	}
	if (!PEM_write_bio_X509_CRL(out, crl)) {
		BIO_free(out);
		OSSL_Raise(eX509CRLError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE 
ossl_x509crl_to_text(VALUE self)
{
	X509_CRL *crl = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;

	GetX509CRL(self, crl);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CRLError, "");
	}
	if (!X509_CRL_print(out, crl)) {
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
	X509_CRL *crl = NULL;
	int count = 0, i;
	X509_EXTENSION *ext = NULL;
	VALUE ary;

	GetX509CRL(self, crl);

	count = X509_CRL_get_ext_count(crl);

	if (count > 0) 
		ary = rb_ary_new2(count);
	else
		return rb_ary_new();

	for (i=0; i<count; i++) {
		ext = X509_CRL_get_ext(crl, i); /* NO DUP - don't free! */
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
	X509_CRL *crl = NULL;
	X509_EXTENSION *ext = NULL;
	int i = 0;
	
	GetX509CRL(self, crl);

	Check_Type(ary, T_ARRAY);
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary members should be X509 Extensions */
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Extension);
	}

	sk_X509_EXTENSION_pop_free(crl->crl->extensions, X509_EXTENSION_free);
	crl->crl->extensions = NULL;

	for (i=0; i<RARRAY(ary)->len; i++) {
		ext = ossl_x509ext_get_X509_EXTENSION(RARRAY(ary)->ptr[i]);

		if(!X509_CRL_add_ext(crl, ext, -1)) { /* DUPs ext - FREE it */
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
	X509_CRL *crl = NULL;
	X509_EXTENSION *ext = NULL;

	GetX509CRL(self, crl);

	OSSL_Check_Type(extension, cX509Extension);
	ext = ossl_x509ext_get_X509_EXTENSION(extension);
	
	if (!X509_CRL_add_ext(crl, ext, -1)) { /* DUPs ext - FREE it */
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
	rb_define_alias(cX509CRL, "to_s", "to_pem");
	rb_define_method(cX509CRL, "to_text", ossl_x509crl_to_text, 0);
	rb_define_method(cX509CRL, "extensions", ossl_x509crl_get_extensions, 0);
	rb_define_method(cX509CRL, "extensions=", ossl_x509crl_set_extensions, 1);
	rb_define_method(cX509CRL, "add_extension", ossl_x509crl_add_extension, 1);
}

