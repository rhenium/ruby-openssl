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

#define MakeX509(obj, x509p) {\
	obj = Data_Make_Struct(cX509Certificate, ossl_x509, 0, ossl_x509_free, x509p);\
}
#define GetX509_unsafe(obj, x509p) Data_Get_Struct(obj, ossl_x509, x509p)
#define GetX509(obj, x509p) {\
	GetX509_unsafe(obj, x509p);\
	if (!x509p->x509) rb_raise(eX509CertificateError, "not initialized!");\
}

/*
 * Classes
 */
VALUE cX509Certificate;
VALUE eX509CertificateError;

/*
 * Struct
 */
typedef struct ossl_x509_st {
	X509 *x509;
} ossl_x509;

static void 
ossl_x509_free(ossl_x509 *x509p)
{
	if (x509p) {
		if(x509p->x509) X509_free(x509p->x509);
		x509p->x509 = NULL;
		free(x509p);
	}
}

/*
 * public functions
 */
VALUE
ossl_x509_new(X509 *x509)
{
	ossl_x509 *x509p = NULL;
	X509 *new = NULL;
	VALUE obj;

	if (!x509)
		new = X509_new();
	else new = X509_dup(x509);

	if (!new)
		OSSL_Raise(eX509CertificateError, "");

	MakeX509(obj, x509p);
	x509p->x509 = new;
	
	return obj;
}

VALUE 
ossl_x509_new_from_file(VALUE filename)
{
	char *path;
	FILE *fp;
	X509 *cert;
	ossl_x509 *x509p = NULL;
	VALUE obj;

	Check_SafeStr(filename);
	path = RSTRING(filename)->ptr;
	
	if ((fp = fopen(path, "r")) == NULL)
		rb_raise(eX509CertificateError, "%s", strerror(errno));

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!cert)
		OSSL_Raise(eX509CertificateError, "");
	
	MakeX509(obj, x509p);
	x509p->x509 = cert;

	return obj;
}

X509 *
ossl_x509_get_X509(VALUE obj)
{
	ossl_x509 *x509p = NULL;
	X509 *x509 = NULL;
	
	OSSL_Check_Type(obj, cX509Certificate);	
	GetX509(obj, x509p);
	
	if (!(x509 = X509_dup(x509p->x509))) {
		OSSL_Raise(eX509CertificateError, "");
	}

	return x509;
}

/*
 * private functions
 */
static VALUE 
ossl_x509_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_x509 *x509p = NULL;
	VALUE obj;
	
	MakeX509(obj, x509p);
	
	rb_obj_call_init(obj, argc, argv);
	
	return obj;
}

static VALUE 
ossl_x509_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_x509 *x509p = NULL;
	X509 *x509 = NULL;
	BIO *in = NULL;
	VALUE buffer;
	
	GetX509_unsafe(self, x509p);

	rb_scan_args(argc, argv, "01", &buffer);

	switch (TYPE(buffer)) {
		case T_NIL:
			x509 = X509_new();
			break;
			
		case T_STRING:
			Check_SafeStr(buffer);
			if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, RSTRING(buffer)->len))) {
				OSSL_Raise(eX509CertificateError, "");
			}
			x509 = PEM_read_bio_X509(in, NULL, NULL, NULL);
			BIO_free(in);
			break;
			
		default:
			rb_raise(rb_eTypeError, "unsupported type");
	}
	
	if (!x509)
		OSSL_Raise(eX509CertificateError, "");
	
	x509p->x509 = x509;

	return self;
}

static VALUE 
ossl_x509_to_der(VALUE self)
{
	ossl_x509 *x509p = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509(self, x509p);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!i2d_X509_bio(out, x509p->x509)) {
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
	ossl_x509 *x509p = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509(self, x509p);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!PEM_write_bio_X509(out, x509p->x509)) {
		BIO_free(out);
		OSSL_Raise(eX509CertificateError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE
ossl_x509_to_str(VALUE self)
{
	ossl_x509 *x509p = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509(self, x509p);

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!X509_print(out, x509p->x509)) {
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
	ossl_x509 *x509p = NULL;
	X509_REQ *req = NULL;
	
	GetX509(self, x509p);
	
	if (!(req = X509_to_X509_REQ(x509p->x509, NULL, EVP_md5()))) {
		OSSL_Raise(eX509CertificateError, "");
	}

	return ossl_x509req_new(req);
}
 */

static VALUE 
ossl_x509_get_version(VALUE self)
{
	ossl_x509 *x509p = NULL;
	long version = 0;

	GetX509(self, x509p);
	
	version = X509_get_version(x509p->x509);

	return INT2NUM(version+1);
}

static VALUE 
ossl_x509_set_version(VALUE self, VALUE version)
{
	ossl_x509 *x509p = NULL;
	long ver = 0;

	GetX509(self, x509p);

	if ((ver = FIX2LONG(version)) <= 0) {
		rb_raise(eX509CertificateError, "version must be > 0!");
	}
	if (!X509_set_version(x509p->x509, ver-1)) {
		OSSL_Raise(eX509CertificateError, "");
	}

	return version;
}

static VALUE 
ossl_x509_get_serial(VALUE self)
{
	ossl_x509 *x509p = NULL;
	ASN1_INTEGER *asn1int = NULL;
	long serial = 0;

	GetX509(self, x509p);
	
	if (!(asn1int = X509_get_serialNumber(x509p->x509))) { /* NO DUP - don't free */
		OSSL_Raise(eX509CertificateError, "");
	}
	serial = ASN1_INTEGER_get(asn1int);

	return INT2NUM(serial);
}

static VALUE 
ossl_x509_set_serial(VALUE self, VALUE serial)
{
	ossl_x509 *x509p = NULL;
	ASN1_INTEGER *asn1int = NULL;

	GetX509(self, x509p);
	
	if (!(asn1int = ASN1_INTEGER_new())) {
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!ASN1_INTEGER_set(asn1int, FIX2LONG(serial))) {
		ASN1_INTEGER_free(asn1int);
		OSSL_Raise(eX509CertificateError, "");
	}
	if (!X509_set_serialNumber(x509p->x509, asn1int)) { /* DUPs asn1int - FREE it */
		ASN1_INTEGER_free(asn1int);
		OSSL_Raise(eX509CertificateError, "");
	}
	ASN1_INTEGER_free(asn1int);
	
	return serial;
}

static VALUE 
ossl_x509_get_subject(VALUE self)
{
	ossl_x509 *x509p = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509p);

	if (!(name = X509_get_subject_name(x509p->x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}

	return ossl_x509name_new(name);
}

static VALUE 
ossl_x509_set_subject(VALUE self, VALUE subject)
{
	ossl_x509 *x509p = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509p);

	OSSL_Check_Type(subject, cX509Name);
	name = ossl_x509name_get_X509_NAME(subject);

	if (!X509_set_subject_name(x509p->x509, name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		OSSL_Raise(eX509CertificateError, "");
	}
	X509_NAME_free(name);

	return subject;
}

static VALUE 
ossl_x509_get_issuer(VALUE self)
{
	ossl_x509 *x509p = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509p);
	
	if(!(name = X509_get_issuer_name(x509p->x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}
	
	return ossl_x509name_new(name);
}

static VALUE 
ossl_x509_set_issuer(VALUE self, VALUE issuer)
{
	ossl_x509 *x509p = NULL;
	X509_NAME *name = NULL;
	
	GetX509(self, x509p);

	OSSL_Check_Type(issuer, cX509Name);
	name = ossl_x509name_get_X509_NAME(issuer);
	
	if (!X509_set_issuer_name(x509p->x509, name)) { /* DUPs name - FREE it */
		X509_NAME_free(name);
		OSSL_Raise(eX509CertificateError, "");
	}
	X509_NAME_free(name);

	return issuer;
}

static VALUE 
ossl_x509_get_not_before(VALUE self)
{
	ossl_x509 *x509p = NULL;
	ASN1_UTCTIME *asn1time = NULL;

	GetX509(self, x509p);

	if (!(asn1time = X509_get_notBefore(x509p->x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}

	return asn1time_to_time(asn1time);
}

static VALUE 
ossl_x509_set_not_before(VALUE self, VALUE time)
{
	ossl_x509 *x509p = NULL;
	int intsec = -1;
	VALUE sec;
	
	GetX509(self, x509p);

	OSSL_Check_Type(time, rb_cTime);
	sec = rb_funcall(time, rb_intern("to_i"), 0, NULL);
	
	if (!FIXNUM_P(sec)) {
		rb_raise(eX509CertificateError, "wierd time");
	}
	if ((intsec = FIX2INT(sec)) < 0) {
		rb_raise(eX509CertificateError, "time < 0???");
	}
	if (!ASN1_UTCTIME_set(X509_get_notBefore(x509p->x509), intsec)) {
		OSSL_Raise(eX509CertificateError, "");
	}
	return time;
}

static VALUE 
ossl_x509_get_not_after(VALUE self)
{
	ossl_x509 *x509p = NULL;
	ASN1_UTCTIME *asn1time = NULL;

	GetX509(self, x509p);

	if (!(asn1time = X509_get_notAfter(x509p->x509))) { /* NO DUP - don't free! */
		OSSL_Raise(eX509CertificateError, "");
	}

	return asn1time_to_time(asn1time);
}

static VALUE 
ossl_x509_set_not_after(VALUE self, VALUE time)
{
	ossl_x509 *x509p = NULL;
	int intsec = -1;
	VALUE sec;
	
	GetX509(self, x509p);

	OSSL_Check_Type(time, rb_cTime);
	sec = rb_funcall(time, rb_intern("to_i"), 0, NULL);
	
	if (!FIXNUM_P(sec)) {
		rb_raise(eX509CertificateError, "wierd time");
	}
	if ((intsec = FIX2INT(sec)) < 0) {
		rb_raise(eX509CertificateError, "time < 0??");
	}
	if (!ASN1_UTCTIME_set(X509_get_notAfter(x509p->x509), FIX2INT(sec))) {
		OSSL_Raise(eX509CertificateError, "");
	}
	return time;
}

static VALUE 
ossl_x509_get_public_key(VALUE self)
{
	ossl_x509 *x509p = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE pub_key;

	GetX509(self, x509p);
	
	if (!(pkey = X509_get_pubkey(x509p->x509))) { /* adds an reference - safe to FREE */
		OSSL_Raise(eX509CertificateError, "");
	}
	pub_key = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return pub_key;
}

static VALUE 
ossl_x509_set_public_key(VALUE self, VALUE pubk)
{
	ossl_x509 *x509p = NULL;
	EVP_PKEY *pkey = NULL;

	GetX509(self, x509p);
	OSSL_Check_Type(pubk, cPKey);
	
	pkey = ossl_pkey_get_EVP_PKEY(pubk);
	
	if (!X509_set_pubkey(x509p->x509, pkey)) { /* DUPs pkey - FREE it */
		EVP_PKEY_free(pkey);
		OSSL_Raise(eX509CertificateError, "");
	}
	EVP_PKEY_free(pkey);

	return self;
}

static VALUE 
ossl_x509_sign(VALUE self, VALUE key, VALUE digest)
{
	ossl_x509 *x509p = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetX509(self, x509p);
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(digest, cDigest);
	
	if (rb_funcall(key, rb_intern("private?"), 0, NULL) == Qfalse) {
		rb_raise(eX509CertificateError, "PRIVATE key needed to sign X509 Certificate!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	md = ossl_digest_get_EVP_MD(digest);
	
	if (!X509_sign(x509p->x509, pkey, md)) {
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
	ossl_x509 *x509p = NULL;
	EVP_PKEY *pkey = NULL;
	int i = 0;

	GetX509(self, x509p);
	OSSL_Check_Type(key, cPKey);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	i = X509_verify(x509p->x509, pkey);
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
	ossl_x509 *x509p = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE result;
	
	GetX509(self, x509p);
	OSSL_Check_Type(key, cPKey);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	
	if (!X509_check_private_key(x509p->x509, pkey)) {
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
	ossl_x509 *x509p = NULL;
	int count = 0, i;
	X509_EXTENSION *ext = NULL;
	VALUE ary;

	GetX509(self, x509p);

	count = X509_get_ext_count(x509p->x509);

	if (count > 0)
		ary = rb_ary_new2(count);
	else
		return rb_ary_new();

	for (i=0; i<count; i++) {
		ext = X509_get_ext(x509p->x509, i); /* NO DUP - don't free! */
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
	ossl_x509 *x509p = NULL;
	X509_EXTENSION *ext = NULL;
	int i = 0;
	
	GetX509(self, x509p);

	Check_Type(ary, T_ARRAY);
	for (i=0; i<RARRAY(ary)->len; i++) { /* All ary's members should be X509Extension */
		OSSL_Check_Type(RARRAY(ary)->ptr[i], cX509Extension);
	}

	sk_X509_EXTENSION_pop_free(x509p->x509->cert_info->extensions, X509_EXTENSION_free);
	x509p->x509->cert_info->extensions = NULL;
	
	for (i=0; i<RARRAY(ary)->len; i++) {
		ext = ossl_x509ext_get_X509_EXTENSION(RARRAY(ary)->ptr[i]);
		
		if (!X509_add_ext(x509p->x509, ext, -1)) { /* DUPs ext - FREE it */
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
	ossl_x509 *x509p = NULL;
	X509_EXTENSION *ext = NULL;
	
	GetX509(self, x509p);

	OSSL_Check_Type(extension, cX509Extension);
	ext = ossl_x509ext_get_X509_EXTENSION(extension);
	
	if (!X509_add_ext(x509p->x509, ext, -1)) { /* DUPs ext - FREE it */
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
	rb_define_method(cX509Certificate, "to_str", ossl_x509_to_str, 0);
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

