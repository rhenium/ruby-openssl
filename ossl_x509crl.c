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

#define WrapX509CRL(klass, obj, crl) do { \
	if (!crl) { \
		ossl_raise(rb_eRuntimeError, "CRL wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(klass, 0, X509_CRL_free, crl); \
} while (0)
#define GetX509CRL(obj, crl) do { \
	Data_Get_Struct(obj, X509_CRL, crl); \
	if (!crl) { \
		ossl_raise(rb_eRuntimeError, "CRL wasn't initialized!"); \
	} \
} while (0)
#define SafeGetX509CRL(obj, crl) do { \
	OSSL_Check_Kind(obj, cX509CRL); \
	GetX509CRL(obj, crl); \
} while (0)

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
	X509_CRL *crl, *new;
	
	SafeGetX509CRL(obj, crl);

	if (!(new = X509_CRL_dup(crl))) {
		ossl_raise(eX509CRLError, "");
	}
	return new;
}

/*
 * PRIVATE
 */
static VALUE 
ossl_x509crl_s_allocate(VALUE klass)
{
	X509_CRL *crl;
	VALUE obj;

	if (!(crl = X509_CRL_new())) {
		ossl_raise(eX509CRLError, "");
	}
	WrapX509CRL(klass, obj, crl);
	
	return obj;
}

static VALUE 
ossl_x509crl_initialize(int argc, VALUE *argv, VALUE self)
{
	BIO *in;
	VALUE buffer;

	if (rb_scan_args(argc, argv, "01", &buffer) == 0) {
		return self;
	}	
	if (!(in = BIO_new_mem_buf(StringValuePtr(buffer), -1))) {
		ossl_raise(eX509CRLError, "");
	}
	/*
	 * TODO:
	 * Check if we should free CRL
	X509_CRL_free(DATA_PTR(self));
	 */
	if (!PEM_read_bio_X509_CRL(in, (X509_CRL **)&DATA_PTR(self), NULL, NULL)) {
		BIO_free(in);
		ossl_raise(eX509CRLError, "");
	}
	BIO_free(in);
	
	return self;
}

static VALUE 
ossl_x509crl_get_version(VALUE self)
{
	X509_CRL *crl;
	long ver;

	GetX509CRL(self, crl);

	ver = ASN1_INTEGER_get(crl->crl->version);

	return LONG2NUM(ver);
}

static VALUE 
ossl_x509crl_set_version(VALUE self, VALUE version)
{
	X509_CRL *crl;
	ASN1_INTEGER *asn1int;
	long ver;
	
	GetX509CRL(self, crl);

	if ((ver = NUM2LONG(version)) < 0) {
		ossl_raise(eX509CRLError, "version must be >= 0!");
	}
	if (!(asn1int = ASN1_INTEGER_new())) {
		ossl_raise(eX509CRLError, "");
	}
	if (!ASN1_INTEGER_set(asn1int, ver)) {
		ossl_raise(eX509CRLError, "");
	}
	ASN1_INTEGER_free(crl->crl->version);
	crl->crl->version = asn1int;

	return version;
}

static VALUE 
ossl_x509crl_get_issuer(VALUE self)
{
	X509_CRL *crl;
	
	GetX509CRL(self, crl);
	
	return ossl_x509name_new(X509_CRL_get_issuer(crl)); /* NO DUP - don't free */
}

static VALUE 
ossl_x509crl_set_issuer(VALUE self, VALUE issuer)
{
	X509_CRL *crl;
	
	GetX509CRL(self, crl);

	if (!X509_CRL_set_issuer_name(crl, GetX509NamePtr(issuer))) { /* DUPs name */
		ossl_raise(eX509CRLError, "");
	}
	return issuer;
}

static VALUE 
ossl_x509crl_get_last_update(VALUE self)
{
	X509_CRL *crl;

	GetX509CRL(self, crl);

	return asn1time_to_time(crl->crl->lastUpdate);
}

static VALUE 
ossl_x509crl_set_last_update(VALUE self, VALUE time)
{
	X509_CRL *crl;
	time_t sec;
	
	GetX509CRL(self, crl);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(crl->crl->lastUpdate, sec)) {
		ossl_raise(eX509CRLError, "");
	}
	return time;
}

static VALUE 
ossl_x509crl_get_next_update(VALUE self)
{
	X509_CRL *crl;

	GetX509CRL(self, crl);

	return asn1time_to_time(crl->crl->nextUpdate);
}

static VALUE 
ossl_x509crl_set_next_update(VALUE self, VALUE time)
{
	X509_CRL *crl;
	time_t sec;

	GetX509CRL(self, crl);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(crl->crl->nextUpdate, sec)) {
		ossl_raise(eX509CRLError, "");
	}
	return time;
}

static VALUE 
ossl_x509crl_get_revoked(VALUE self)
{
	X509_CRL *crl;
	int i, num;
	X509_REVOKED *rev;
	VALUE ary, revoked;

	GetX509CRL(self, crl);

	num = sk_X509_CRL_num(crl->crl->revoked);

	if (num < 0) {
		rb_warning("num < 0???");
		return rb_ary_new();
	}
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
	X509_CRL *crl;
	X509_REVOKED *rev;
	int i;

	GetX509CRL(self, crl);

	Check_Type(ary, T_ARRAY);
	
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary members should be X509 Revoked */
		OSSL_Check_Kind(RARRAY(ary)->ptr[i], cX509Rev);
	}
	
	sk_X509_REVOKED_pop_free(crl->crl->revoked, X509_REVOKED_free);
	crl->crl->revoked = NULL;
	M_ASN1_New(crl->crl->revoked, sk_X509_REVOKED_new_null);
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		rev = ossl_x509revoked_get_X509_REVOKED(RARRAY(ary)->ptr[i]);

		if (!sk_X509_CRL_push(crl->crl->revoked, rev)) { /* NO DUP - don't free! */
			ossl_raise(eX509CRLError, "");
		}
	}
	sk_X509_REVOKED_sort(crl->crl->revoked);
	
	return ary;
}

static VALUE 
ossl_x509crl_add_revoked(VALUE self, VALUE revoked)
{
	X509_CRL *crl;
	X509_REVOKED *rev;

	GetX509CRL(self, crl);

	rev = ossl_x509revoked_get_X509_REVOKED(revoked);

	if (!sk_X509_CRL_push(crl->crl->revoked, rev)) { /* NO DUP - don't free! */
		ossl_raise(eX509CRLError, "");
	}
	sk_X509_REVOKED_sort(crl->crl->revoked);
	
	return revoked;
}

static VALUE 
ossl_x509crl_sign(VALUE self, VALUE key, VALUE digest)
{
	X509_CRL *crl;
	EVP_PKEY *pkey;
	const EVP_MD *md;

	GetX509CRL(self, crl);

	pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
	md = GetDigestPtr(digest);
	
	if (!X509_CRL_sign(crl, pkey, md)) {
		ossl_raise(eX509CRLError, "");
	}
	return self;
}

static VALUE 
ossl_x509crl_verify(VALUE self, VALUE key)
{
	X509_CRL *crl;
	int ret;

	GetX509CRL(self, crl);

	if ((ret = X509_CRL_verify(crl, GetPKeyPtr(key))) < 0) {
		ossl_raise(eX509CRLError, "");
	}
	if (ret == 1) {
		return Qtrue;
	}
	return Qfalse;
}

static VALUE 
ossl_x509crl_to_pem(VALUE self)
{
	X509_CRL *crl;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;

	GetX509CRL(self, crl);

	if (!(out = BIO_new(BIO_s_mem()))) {
		ossl_raise(eX509CRLError, "");
	}
	if (!PEM_write_bio_X509_CRL(out, crl)) {
		BIO_free(out);
		ossl_raise(eX509CRLError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE 
ossl_x509crl_to_text(VALUE self)
{
	X509_CRL *crl;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;

	GetX509CRL(self, crl);

	if (!(out = BIO_new(BIO_s_mem()))) {
		ossl_raise(eX509CRLError, "");
	}
	if (!X509_CRL_print(out, crl)) {
		BIO_free(out);
		ossl_raise(eX509CRLError, "");
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
	X509_CRL *crl;
	int count, i;
	X509_EXTENSION *ext;
	VALUE ary;

	GetX509CRL(self, crl);

	count = X509_CRL_get_ext_count(crl);

	if (count < 0) {
		rb_warning("count < 0???");
		return rb_ary_new();
	}
	ary = rb_ary_new2(count);

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
	X509_CRL *crl;
	X509_EXTENSION *ext;
	int i;
	
	GetX509CRL(self, crl);

	Check_Type(ary, T_ARRAY);
	
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary members should be X509 Extensions */
		OSSL_Check_Kind(RARRAY(ary)->ptr[i], cX509Ext);
	}
	
	sk_X509_EXTENSION_pop_free(crl->crl->extensions, X509_EXTENSION_free);
	crl->crl->extensions = NULL;

	for (i=0; i<RARRAY(ary)->len; i++) {
		ext = ossl_x509ext_get_X509_EXTENSION(RARRAY(ary)->ptr[i]);

		if(!X509_CRL_add_ext(crl, ext, -1)) { /* DUPs ext - FREE it */
			X509_EXTENSION_free(ext);
			ossl_raise(eX509CRLError, "");
		}
		X509_EXTENSION_free(ext);
	}
	return ary;
}

static VALUE 
ossl_x509crl_add_extension(VALUE self, VALUE extension)
{
	X509_CRL *crl;
	X509_EXTENSION *ext;

	GetX509CRL(self, crl);

	ext = ossl_x509ext_get_X509_EXTENSION(extension);
	
	if (!X509_CRL_add_ext(crl, ext, -1)) { /* DUPs ext - FREE it */
		X509_EXTENSION_free(ext);
		ossl_raise(eX509CRLError, "");
	}
	X509_EXTENSION_free(ext);

	return extension;
}

/*
 * INIT
 */
void 
Init_ossl_x509crl()
{
	eX509CRLError = rb_define_class_under(mX509, "CRLError", eOSSLError);

	cX509CRL = rb_define_class_under(mX509, "CRL", rb_cObject);
	
	rb_define_singleton_method(cX509CRL, "allocate", ossl_x509crl_s_allocate, 0);
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

