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

#define WrapX509(klass, obj, x509) do { \
	if (!x509) { \
		ossl_raise(rb_eRuntimeError, "CERT wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(klass, 0, X509_free, x509); \
} while (0)
#define GetX509(obj, x509) do { \
	Data_Get_Struct(obj, X509, x509); \
	if (!x509) { \
		ossl_raise(rb_eRuntimeError, "CERT wasn't initialized!"); \
	} \
} while (0)
#define SafeGetX509(obj, x509) do { \
	OSSL_Check_Kind(obj, cX509Cert); \
	GetX509(obj, x509); \
} while (0)

/*
 * Classes
 */
VALUE cX509Cert;
VALUE eX509CertError;

/*
 * Public
 */
VALUE
ossl_x509_new(X509 *x509)
{
	X509 *new;
	VALUE obj;

	if (!x509) {
		new = X509_new();
	} else {
		new = X509_dup(x509);
	}
	if (!new) {
		ossl_raise(eX509CertError, "");
	}
	WrapX509(cX509Cert, obj, new);
	
	return obj;
}

VALUE 
ossl_x509_new_from_file(VALUE filename)
{
	X509 *x509;
	FILE *fp;
	VALUE obj;

	SafeStringValue(filename);
	
	if (!(fp = fopen(StringValuePtr(filename), "r")))
		ossl_raise(eX509CertError, "%s", strerror(errno));

	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!x509) {
		ossl_raise(eX509CertError, "");
	}
	WrapX509(cX509Cert, obj, x509);

	return obj;
}

X509 *
GetX509CertPtr(VALUE obj)
{
	X509 *x509;
	SafeGetX509(obj, x509);
	return x509;
}

X509 *
DupX509CertPtr(VALUE obj)
{
	X509 *x509;
	SafeGetX509(obj, x509);
	CRYPTO_add(&x509->references,1,CRYPTO_LOCK_X509);
	return x509;
}

/*
 * Private
 */
static VALUE 
ossl_x509_s_allocate(VALUE klass)
{
	X509 *x509;
	VALUE obj;

	if (!(x509 = X509_new())) {
		ossl_raise(eX509CertError, "");
	}
	WrapX509(klass, obj, x509);

	return obj;
}

static VALUE 
ossl_x509_initialize(int argc, VALUE *argv, VALUE self)
{
	BIO *in;
	VALUE buffer;

	if (rb_scan_args(argc, argv, "01", &buffer) == 0) {
		return self;
	}
	StringValue(buffer);
	
	if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, RSTRING(buffer)->len))) {
		ossl_raise(eX509CertError, "");
	}
	/*
	 * TODO:
	 * Check if we could free old X509
	X509_free(DATA_PTR(self));
	 */
	if (!PEM_read_bio_X509(in, (X509 **)&DATA_PTR(self), NULL, NULL)) {
		BIO_free(in);
		ossl_raise(eX509CertError, "");
	}
	BIO_free(in);
	
	return self;
}

static VALUE 
ossl_x509_to_der(VALUE self)
{
	X509 *x509;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;
	
	GetX509(self, x509);

	if (!(out = BIO_new(BIO_s_mem()))) {
		ossl_raise(eX509CertError, "");
	}
	if (!i2d_X509_bio(out, x509)) {
		BIO_free(out);
		ossl_raise(eX509CertError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE 
ossl_x509_to_pem(VALUE self)
{
	X509 *x509;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;
	
	GetX509(self, x509);

	if (!(out = BIO_new(BIO_s_mem()))) {
		ossl_raise(eX509CertError, "");
	}
	if (!PEM_write_bio_X509(out, x509)) {
		BIO_free(out);
		ossl_raise(eX509CertError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE
ossl_x509_to_text(VALUE self)
{
	X509 *x509;
	BIO *out;
	BUF_MEM *buf;
	VALUE str;
	
	GetX509(self, x509);

	if (!(out = BIO_new(BIO_s_mem()))) {
		ossl_raise(eX509CertError, "");
	}
	if (!X509_print(out, x509)) {
		BIO_free(out);
		ossl_raise(eX509CertError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

/*
 * Makes from X509 X509_REQuest
 *
static VALUE 
ossl_x509_to_req(VALUE self)
{
	X509 *x509;
	X509_REQ *req;
	
	GetX509(self, x509);
	
	if (!(req = X509_to_X509_REQ(x509, NULL, EVP_md5()))) {
		ossl_raise(eX509CertError, "");
	}
	return ossl_x509req_new(req);
}
 */

static VALUE 
ossl_x509_get_version(VALUE self)
{
	X509 *x509;
	long ver;

	GetX509(self, x509);
	
	ver = X509_get_version(x509);

	return LONG2FIX(ver);
}

static VALUE 
ossl_x509_set_version(VALUE self, VALUE version)
{
	X509 *x509;
	long ver;

	GetX509(self, x509);

	if ((ver = FIX2LONG(version)) < 0) {
		ossl_raise(eX509CertError, "version must be >= 0!");
	}
	if (!X509_set_version(x509, ver)) {
		ossl_raise(eX509CertError, "");
	}
	return version;
}

static VALUE 
ossl_x509_get_serial(VALUE self)
{
	X509 *x509;
	ASN1_INTEGER *asn1int;
	long serial;

	GetX509(self, x509);
	
	if (!(asn1int = X509_get_serialNumber(x509))) { /* NO DUP - don't free */
		ossl_raise(eX509CertError, "");
	}
	serial = ASN1_INTEGER_get(asn1int);

	return LONG2FIX(serial);
}

static VALUE 
ossl_x509_set_serial(VALUE self, VALUE serial)
{
	X509 *x509;
	ASN1_INTEGER *asn1int;

	GetX509(self, x509);
	
	if (!(asn1int = ASN1_INTEGER_new())) {
		ossl_raise(eX509CertError, "");
	}
	if (!ASN1_INTEGER_set(asn1int, FIX2LONG(serial))) {
		ASN1_INTEGER_free(asn1int);
		ossl_raise(eX509CertError, "");
	}
	if (!X509_set_serialNumber(x509, asn1int)) { /* DUPs asn1int - FREE it */
		ASN1_INTEGER_free(asn1int);
		ossl_raise(eX509CertError, "");
	}
	ASN1_INTEGER_free(asn1int);
	
	return serial;
}

static VALUE 
ossl_x509_get_subject(VALUE self)
{
	X509 *x509;
	X509_NAME *name;
	
	GetX509(self, x509);

	if (!(name = X509_get_subject_name(x509))) { /* NO DUP - don't free! */
		ossl_raise(eX509CertError, "");
	}
	return ossl_x509name_new(name);
}

static VALUE 
ossl_x509_set_subject(VALUE self, VALUE subject)
{
	X509 *x509;
	X509_NAME *name;
	
	GetX509(self, x509);

	name = ossl_x509name_get_X509_NAME(subject);

	if (!X509_set_subject_name(x509, name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		ossl_raise(eX509CertError, "");
	}
	X509_NAME_free(name);

	return subject;
}

static VALUE 
ossl_x509_get_issuer(VALUE self)
{
	X509 *x509;
	X509_NAME *name;
	
	GetX509(self, x509);
	
	if(!(name = X509_get_issuer_name(x509))) { /* NO DUP - don't free! */
		ossl_raise(eX509CertError, "");
	}
	return ossl_x509name_new(name);
}

static VALUE 
ossl_x509_set_issuer(VALUE self, VALUE issuer)
{
	X509 *x509;
	X509_NAME *name;
	
	GetX509(self, x509);

	name = ossl_x509name_get_X509_NAME(issuer);
	
	if (!X509_set_issuer_name(x509, name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		ossl_raise(eX509CertError, "");
	}
	X509_NAME_free(name);

	return issuer;
}

static VALUE 
ossl_x509_get_not_before(VALUE self)
{
	X509 *x509;
	ASN1_UTCTIME *asn1time;

	GetX509(self, x509);

	if (!(asn1time = X509_get_notBefore(x509))) { /* NO DUP - don't free! */
		ossl_raise(eX509CertError, "");
	}
	return asn1time_to_time(asn1time);
}

static VALUE 
ossl_x509_set_not_before(VALUE self, VALUE time)
{
	X509 *x509;
	time_t sec;
	
	GetX509(self, x509);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(X509_get_notBefore(x509), sec)) {
		ossl_raise(eX509CertError, "");
	}
	return time;
}

static VALUE 
ossl_x509_get_not_after(VALUE self)
{
	X509 *x509;
	ASN1_UTCTIME *asn1time;

	GetX509(self, x509);

	if (!(asn1time = X509_get_notAfter(x509))) { /* NO DUP - don't free! */
		ossl_raise(eX509CertError, "");
	}
	return asn1time_to_time(asn1time);
}

static VALUE 
ossl_x509_set_not_after(VALUE self, VALUE time)
{
	X509 *x509;
	time_t sec;
	
	GetX509(self, x509);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(X509_get_notAfter(x509), sec)) {
		ossl_raise(eX509CertError, "");
	}
	return time;
}

static VALUE 
ossl_x509_get_public_key(VALUE self)
{
	X509 *x509;
	EVP_PKEY *pkey;

	GetX509(self, x509);
	
	if (!(pkey = X509_get_pubkey(x509))) { /* adds an reference */
		ossl_raise(eX509CertError, "");
	}
	return ossl_pkey_new(pkey); /* NO DUP - OK */
}

static VALUE 
ossl_x509_set_public_key(VALUE self, VALUE key)
{
	X509 *x509;

	GetX509(self, x509);
	
	if (!X509_set_pubkey(x509, GetPKeyPtr(key))) { /* DUPs pkey */
		ossl_raise(eX509CertError, "");
	}
	return key;
}

static VALUE 
ossl_x509_sign(VALUE self, VALUE key, VALUE digest)
{
	X509 *x509;
	EVP_PKEY *pkey;
	const EVP_MD *md;

	GetX509(self, x509);
	
	pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
	md = GetDigestPtr(digest);
	
	if (!X509_sign(x509, pkey, md)) {
		ossl_raise(eX509CertError, "");
	}
	return self;
}

/*
 * Checks that cert signature is made with PRIVversion of this PUBLIC 'key'
 */
static VALUE 
ossl_x509_verify(VALUE self, VALUE key)
{
	X509 *x509;
	EVP_PKEY *pkey;
	int i;

	GetX509(self, x509);
	
	pkey = GetPKeyPtr(key); /* NO NEED TO DUP */
	
	if ((i = X509_verify(x509, pkey)) < 0) {
		ossl_raise(eX509CertError, "");
	} 
	if (i > 0) {
		return Qtrue;
	}
	return Qfalse;
}

/*
 * Checks if 'key' is PRIV key for this cert
 */
static VALUE 
ossl_x509_check_private_key(VALUE self, VALUE key)
{
	X509 *x509;
	EVP_PKEY *pkey;
	
	GetX509(self, x509);
	
	/* not needed private key, but should be */
	pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
	
	if (!X509_check_private_key(x509, pkey)) {
		rb_warning("Check private key:%s", OSSL_ErrMsg());
		return Qfalse;
	}
	return Qtrue;
}

/*
 * Gets X509v3 extensions as array of X509Ext objects
 */
static VALUE 
ossl_x509_get_extensions(VALUE self)
{
	X509 *x509;
	int count, i;
	X509_EXTENSION *ext;
	VALUE ary;

	GetX509(self, x509);

	count = X509_get_ext_count(x509);

	if (count < 0) {
		return rb_ary_new();
	}
	ary = rb_ary_new2(count);
	
	for (i=0; i<count; i++) {
		ext = X509_get_ext(x509, i); /* NO DUP - don't free! */
		rb_ary_push(ary, ossl_x509ext_new(ext));
	}
	return ary;
}

/*
 * Sets X509_EXTENSIONs
 */
static VALUE 
ossl_x509_set_extensions(VALUE self, VALUE ary)
{
	X509 *x509;
	X509_EXTENSION *ext;
	int i;
	
	GetX509(self, x509);

	Check_Type(ary, T_ARRAY);
	
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary's members should be X509Extension */
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Ext);
	}

	sk_X509_EXTENSION_pop_free(x509->cert_info->extensions, X509_EXTENSION_free);
	x509->cert_info->extensions = NULL;
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		ext = ossl_x509ext_get_X509_EXTENSION(RARRAY(ary)->ptr[i]);
		
		if (!X509_add_ext(x509, ext, -1)) { /* DUPs ext - FREE it */
			X509_EXTENSION_free(ext);
			ossl_raise(eX509CertError, "");
		}
		X509_EXTENSION_free(ext);
	}
	return ary;
}

static VALUE 
ossl_x509_add_extension(VALUE self, VALUE extension)
{
	X509 *x509;
	X509_EXTENSION *ext;
	
	GetX509(self, x509);

	ext = ossl_x509ext_get_X509_EXTENSION(extension);
	
	if (!X509_add_ext(x509, ext, -1)) { /* DUPs ext - FREE it */
		X509_EXTENSION_free(ext);
		ossl_raise(eX509CertError, "");
	}
	X509_EXTENSION_free(ext);

	return extension;
}

/*
 * INIT
 */
void 
Init_ossl_x509cert()
{
	eX509CertError = rb_define_class_under(mX509, "CertificateError", eOSSLError);
	
	cX509Cert = rb_define_class_under(mX509, "Certificate", rb_cObject);
	
	rb_define_singleton_method(cX509Cert, "allocate", ossl_x509_s_allocate, 0);
	rb_define_method(cX509Cert, "initialize", ossl_x509_initialize, -1);
	
	rb_define_method(cX509Cert, "to_der", ossl_x509_to_der, 0);
	rb_define_method(cX509Cert, "to_pem", ossl_x509_to_pem, 0);
	rb_define_alias(cX509Cert, "to_s", "to_pem");
	rb_define_method(cX509Cert, "to_text", ossl_x509_to_text, 0);
	rb_define_method(cX509Cert, "version", ossl_x509_get_version, 0);
	rb_define_method(cX509Cert, "version=", ossl_x509_set_version, 1);
	rb_define_method(cX509Cert, "serial", ossl_x509_get_serial, 0);
	rb_define_method(cX509Cert, "serial=", ossl_x509_set_serial, 1);
	rb_define_method(cX509Cert, "subject", ossl_x509_get_subject, 0);
	rb_define_method(cX509Cert, "subject=", ossl_x509_set_subject, 1);
	rb_define_method(cX509Cert, "issuer", ossl_x509_get_issuer, 0);
	rb_define_method(cX509Cert, "issuer=", ossl_x509_set_issuer, 1);
	rb_define_method(cX509Cert, "not_before", ossl_x509_get_not_before, 0);
	rb_define_method(cX509Cert, "not_before=", ossl_x509_set_not_before, 1);
	rb_define_method(cX509Cert, "not_after", ossl_x509_get_not_after, 0);
	rb_define_method(cX509Cert, "not_after=", ossl_x509_set_not_after, 1);
	rb_define_method(cX509Cert, "public_key", ossl_x509_get_public_key, 0);
	rb_define_method(cX509Cert, "public_key=", ossl_x509_set_public_key, 1);
	rb_define_method(cX509Cert, "sign", ossl_x509_sign, 2);
	rb_define_method(cX509Cert, "verify", ossl_x509_verify, 1);
	rb_define_method(cX509Cert, "check_private_key", ossl_x509_check_private_key, 1);
	rb_define_method(cX509Cert, "extensions", ossl_x509_get_extensions, 0);
	rb_define_method(cX509Cert, "extensions=", ossl_x509_set_extensions, 1);
	rb_define_method(cX509Cert, "add_extension", ossl_x509_add_extension, 1);
}

