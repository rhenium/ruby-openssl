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

#define WrapX509(obj, x509) obj = Data_Wrap_Struct(cX509Certificate, 0, X509_free, x509)
#define GetX509(obj, x509) Data_Get_Struct(obj, X509, x509)

/*
 * Classes
 */
VALUE cX509Certificate;
VALUE eX509CertificateError;

/*
 * Public
 */
VALUE
ossl_x509_new(X509 *x509)
{
	X509 *new = NULL;
	VALUE obj;

	if (!x509)
		new = X509_new();
	else new = X509_dup(x509);

	if (!new)
		OSSL_Raise(eX509CertificateError, "");

	WrapX509(obj, new);
	
	return obj;
}

VALUE 
ossl_x509_new_from_file(VALUE filename)
{
	X509 *x509 = NULL;
	char *path;
	FILE *fp;
	VALUE obj;

	filename = rb_str_to_str(filename);
	Check_SafeStr(filename);
	
	path = RSTRING(filename)->ptr;
	
	if (!(fp = fopen(path, "r")))
		rb_raise(eX509CertificateError, "%s", strerror(errno));

	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!x509)
		OSSL_Raise(eX509CertificateError, "");
	
	WrapX509(obj, x509);

	return obj;
}

X509 *
ossl_x509_get_X509(VALUE obj)
{
	X509 *x509 = NULL, *new;
	
	OSSL_Check_Type(obj, cX509Certificate);	
	
	GetX509(obj, x509);
	
	if (!(new = X509_dup(x509))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	return new;
}

/*
 * Private
 */
static VALUE 
ossl_x509_s_new(int argc, VALUE *argv, VALUE klass)
{
	VALUE obj;
	
	obj = ossl_x509_new(NULL);
	
	rb_obj_call_init(obj, argc, argv);
	
	return obj;
}

static VALUE 
ossl_x509_initialize(int argc, VALUE *argv, VALUE self)
{
	BIO *in = NULL;
	VALUE buffer;

	if (argc == 0)
		return self;
	
	buffer = rb_String(argv[0]);
	
	if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, RSTRING(buffer)->len))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!PEM_read_bio_X509(in, (X509 **)&DATA_PTR(self), NULL, NULL)) {
		BIO_free(in);
		OSSL_Raise(eX509CertificateError, "");
	}
	BIO_free(in);
	
	return self;
}

static VALUE 
ossl_x509_to_der(VALUE self)
{
	X509 *x509 = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509(self, x509);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!i2d_X509_bio(out, x509)) {
		BIO_free(out);
		OSSL_Raise(eX509CertificateError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE 
ossl_x509_to_pem(VALUE self)
{
	X509 *x509 = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509(self, x509);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!PEM_write_bio_X509(out, x509)) {
		BIO_free(out);
		OSSL_Raise(eX509CertificateError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE
ossl_x509_to_text(VALUE self)
{
	X509 *x509 = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509(self, x509);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!X509_print(out, x509)) {
		BIO_free(out);
		OSSL_Raise(eX509CertificateError, "");
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
	X509 *x509 = NULL;
	X509_REQ *req = NULL;
	
	GetX509(self, x509);
	
	if (!(req = X509_to_X509_REQ(x509, NULL, EVP_md5()))) {
		OSSL_Raise(eX509CertificateError, "");
	}

	return ossl_x509req_new(req);
}
 */

static VALUE 
ossl_x509_get_version(VALUE self)
{
	X509 *x509 = NULL;
	long ver = 0;

	GetX509(self, x509);
	
	ver = X509_get_version(x509);

	return INT2NUM(ver);
}

static VALUE 
ossl_x509_set_version(VALUE self, VALUE version)
{
	X509 *x509 = NULL;
	long ver = 0;

	GetX509(self, x509);

	if ((ver = FIX2LONG(version)) < 0) {
		rb_raise(eX509CertificateError, "version must be >= 0!");
	}
	if (!X509_set_version(x509, ver)) {
		OSSL_Raise(eX509CertificateError, "");
	}

	return version;
}

static VALUE 
ossl_x509_get_serial(VALUE self)
{
	X509 *x509 = NULL;
	ASN1_INTEGER *asn1int = NULL;
	long serial = 0;

	GetX509(self, x509);
	
	if (!(asn1int = X509_get_serialNumber(x509))) { /* NO DUP - don't free */
		OSSL_Raise(eX509CertificateError, "");
	}
	serial = ASN1_INTEGER_get(asn1int);

	return INT2NUM(serial);
}

static VALUE 
ossl_x509_set_serial(VALUE self, VALUE serial)
{
	X509 *x509 = NULL;
	ASN1_INTEGER *asn1int = NULL;

	GetX509(self, x509);
	
	if (!(asn1int = ASN1_INTEGER_new())) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!ASN1_INTEGER_set(asn1int, FIX2LONG(serial))) {
		ASN1_INTEGER_free(asn1int);
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!X509_set_serialNumber(x509, asn1int)) { /* DUPs asn1int - FREE it */
		ASN1_INTEGER_free(asn1int);
		OSSL_Raise(eX509CertificateError, "");
	}
	ASN1_INTEGER_free(asn1int);
	
	return serial;
}

static VALUE 
ossl_x509_get_subject(VALUE self)
{
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509);

	if (!(name = X509_get_subject_name(x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}

	return ossl_x509name_new(name);
}

static VALUE 
ossl_x509_set_subject(VALUE self, VALUE subject)
{
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509);

	name = ossl_x509name_get_X509_NAME(subject);

	if (!X509_set_subject_name(x509, name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		OSSL_Raise(eX509CertificateError, "");
	}
	X509_NAME_free(name);

	return subject;
}

static VALUE 
ossl_x509_get_issuer(VALUE self)
{
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509);
	
	if(!(name = X509_get_issuer_name(x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}
	
	return ossl_x509name_new(name);
}

static VALUE 
ossl_x509_set_issuer(VALUE self, VALUE issuer)
{
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509);

	name = ossl_x509name_get_X509_NAME(issuer);
	
	if (!X509_set_issuer_name(x509, name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		OSSL_Raise(eX509CertificateError, "");
	}
	X509_NAME_free(name);

	return issuer;
}

static VALUE 
ossl_x509_get_not_before(VALUE self)
{
	X509 *x509 = NULL;
	ASN1_UTCTIME *asn1time = NULL;

	GetX509(self, x509);

	if (!(asn1time = X509_get_notBefore(x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}

	return asn1time_to_time(asn1time);
}

static VALUE 
ossl_x509_set_not_before(VALUE self, VALUE time)
{
	X509 *x509 = NULL;
	time_t sec;
	
	GetX509(self, x509);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(X509_get_notBefore(x509), sec)) {
		OSSL_Raise(eX509CertificateError, "");
	}
	return time;
}

static VALUE 
ossl_x509_get_not_after(VALUE self)
{
	X509 *x509 = NULL;
	ASN1_UTCTIME *asn1time = NULL;

	GetX509(self, x509);

	if (!(asn1time = X509_get_notAfter(x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}

	return asn1time_to_time(asn1time);
}

static VALUE 
ossl_x509_set_not_after(VALUE self, VALUE time)
{
	X509 *x509 = NULL;
	time_t sec;
	
	GetX509(self, x509);

	sec = time_to_time_t(time);
	
	if (!ASN1_UTCTIME_set(X509_get_notAfter(x509), sec)) {
		OSSL_Raise(eX509CertificateError, "");
	}
	return time;
}

static VALUE 
ossl_x509_get_public_key(VALUE self)
{
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE pub_key;

	GetX509(self, x509);
	
	if (!(pkey = X509_get_pubkey(x509))) { /* adds an reference - safe to FREE */
		OSSL_Raise(eX509CertificateError, "");
	}
	pub_key = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return pub_key;
}

static VALUE 
ossl_x509_set_public_key(VALUE self, VALUE pubk)
{
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;

	GetX509(self, x509);
	
	pkey = ossl_pkey_get_EVP_PKEY(pubk);
	
	if (!X509_set_pubkey(x509, pkey)) { /* DUPs pkey - FREE it */
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509CertificateError, "");
	}
	EVP_PKEY_free(pkey);

	return self;
}

static VALUE 
ossl_x509_sign(VALUE self, VALUE key, VALUE digest)
{
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetX509(self, x509);
	
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(digest, cDigest);
	
	if (rb_funcall(key, rb_intern("private?"), 0, NULL) == Qfalse) {
		rb_raise(eX509CertificateError, "PRIVATE key needed to sign X509 Certificate!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	md = ossl_digest_get_EVP_MD(digest);
	
	if (!X509_sign(x509, pkey, md)) {
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509CertificateError, "");
	}
	EVP_PKEY_free(pkey);

	return self;
}

/*
 * Checks that cert signature is made with PRIVversion of this PUBLIC 'key'
 */
static VALUE 
ossl_x509_verify(VALUE self, VALUE key)
{
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	int i = 0;

	GetX509(self, x509);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	
	i = X509_verify(x509, pkey);
	EVP_PKEY_free(pkey);

	if (i < 0) {
		OSSL_Raise(eX509CertificateError, "");
	} else if (i > 0)
		return Qtrue;

	return Qfalse;
}

/*
 * Checks is 'key' is PRIV key for this cert
 */
static VALUE 
ossl_x509_check_private_key(VALUE self, VALUE key)
{
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE result;
	
	GetX509(self, x509);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	
	if (!X509_check_private_key(x509, pkey)) {
		OSSL_Warning("Check private key:");
		result = Qfalse;
	} else
		result = Qtrue;
	
	EVP_PKEY_free(pkey);

	return result;
}

/*
 * Gets X509v3 extensions as array of X509Ext objects
 */
static VALUE 
ossl_x509_get_extensions(VALUE self)
{
	X509 *x509 = NULL;
	int count = 0, i;
	X509_EXTENSION *ext = NULL;
	VALUE ary;

	GetX509(self, x509);

	count = X509_get_ext_count(x509);

	if (count > 0)
		ary = rb_ary_new2(count);
	else
		return rb_ary_new();

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
	X509 *x509 = NULL;
	X509_EXTENSION *ext = NULL;
	int i = 0;
	
	GetX509(self, x509);

	Check_Type(ary, T_ARRAY);
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary's members should be X509Extension */
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Extension);
	}

	sk_X509_EXTENSION_pop_free(x509->cert_info->extensions, X509_EXTENSION_free);
	x509->cert_info->extensions = NULL;
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		ext = ossl_x509ext_get_X509_EXTENSION(RARRAY(ary)->ptr[i]);
		
		if (!X509_add_ext(x509, ext, -1)) { /* DUPs ext - FREE it */
			X509_EXTENSION_free(ext);
			OSSL_Raise(eX509CertificateError, "");
		}
		X509_EXTENSION_free(ext);
	}

	return ary;
}

static VALUE 
ossl_x509_add_extension(VALUE self, VALUE extension)
{
	X509 *x509 = NULL;
	X509_EXTENSION *ext = NULL;
	
	GetX509(self, x509);

	ext = ossl_x509ext_get_X509_EXTENSION(extension);
	
	if (!X509_add_ext(x509, ext, -1)) { /* DUPs ext - FREE it */
		X509_EXTENSION_free(ext);
		OSSL_Raise(eX509CertificateError, "");
	}
	X509_EXTENSION_free(ext);

	return extension;
}

/*
 * INIT
 */
void 
Init_ossl_x509(VALUE module)
{
	eX509CertificateError = rb_define_class_under(module, "CertificateError", rb_eStandardError);
	
	cX509Certificate = rb_define_class_under(module, "Certificate", rb_cObject);
	rb_define_singleton_method(cX509Certificate, "new", ossl_x509_s_new, -1);
	rb_define_method(cX509Certificate, "initialize", ossl_x509_initialize, -1);
	rb_define_method(cX509Certificate, "to_der", ossl_x509_to_der, 0);
	rb_define_method(cX509Certificate, "to_pem", ossl_x509_to_pem, 0);
	rb_define_alias(cX509Certificate, "to_s", "to_pem");
	rb_define_method(cX509Certificate, "to_text", ossl_x509_to_text, 0);
	rb_define_method(cX509Certificate, "version", ossl_x509_get_version, 0);
	rb_define_method(cX509Certificate, "version=", ossl_x509_set_version, 1);
	rb_define_method(cX509Certificate, "serial", ossl_x509_get_serial, 0);
	rb_define_method(cX509Certificate, "serial=", ossl_x509_set_serial, 1);
	rb_define_method(cX509Certificate, "subject", ossl_x509_get_subject, 0);
	rb_define_method(cX509Certificate, "subject=", ossl_x509_set_subject, 1);
	rb_define_method(cX509Certificate, "issuer", ossl_x509_get_issuer, 0);
	rb_define_method(cX509Certificate, "issuer=", ossl_x509_set_issuer, 1);
	rb_define_method(cX509Certificate, "not_before", ossl_x509_get_not_before, 0);
	rb_define_method(cX509Certificate, "not_before=", ossl_x509_set_not_before, 1);
	rb_define_method(cX509Certificate, "not_after", ossl_x509_get_not_after, 0);
	rb_define_method(cX509Certificate, "not_after=", ossl_x509_set_not_after, 1);
	rb_define_method(cX509Certificate, "public_key", ossl_x509_get_public_key, 0);
	rb_define_method(cX509Certificate, "public_key=", ossl_x509_set_public_key, 1);
	rb_define_method(cX509Certificate, "sign", ossl_x509_sign, 2);
	rb_define_method(cX509Certificate, "verify", ossl_x509_verify, 1);
	rb_define_method(cX509Certificate, "check_private_key", ossl_x509_check_private_key, 1);
	rb_define_method(cX509Certificate, "extensions", ossl_x509_get_extensions, 0);
	rb_define_method(cX509Certificate, "extensions=", ossl_x509_set_extensions, 1);
	rb_define_method(cX509Certificate, "add_extension", ossl_x509_add_extension, 1);
}

