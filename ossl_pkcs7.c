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

#define MakePKCS7(obj, pkcs7p) {\
	obj = Data_Make_Struct(cPKCS7, ossl_pkcs7, 0, ossl_pkcs7_free, pkcs7p);\
}
#define GetPKCS7_unsafe(obj, pkcs7p) Data_Get_Struct(obj, ossl_pkcs7, pkcs7p)
#define GetPKCS7(obj, pkcs7p) {\
	GetPKCS7_unsafe(obj, pkcs7p);\
	if (!pkcs7p->pkcs7) rb_raise(ePKCS7Error, "not initialized!");\
}

#define MakePKCS7si(obj, p7sip) {\
	obj = Data_Make_Struct(cPKCS7SignerInfo, ossl_pkcs7si, 0, ossl_pkcs7si_free, p7sip);\
}
#define GetPKCS7si_unsafe(obj, p7sip) Data_Get_Struct(obj, ossl_pkcs7si, p7sip)
#define GetPKCS7si(obj, p7sip) {\
	GetPKCS7si_unsafe(obj, p7sip);\
	if (!p7sip->signer) rb_raise(ePKCS7Error, "not initialized!");\
}

#define DefPKCS7Const(x) rb_define_const(mPKCS7, #x, INT2FIX(##x))

/*
 * Constants
 */
#define SIGNED NID_pkcs7_signed
#define ENVELOPED NID_pkcs7_enveloped
#define SIGNED_ENVELOPED NID_pkcs7_signedAndEnveloped
/*
 * #define DIGEST NID_digest
 * #define ENCRYPTED NID_encrypted
 */

/* 
 * Classes
 */
VALUE cPKCS7;
VALUE cPKCS7SignerInfo;
VALUE ePKCS7Error;

/*
 * Struct
 */
typedef struct ossl_pkcs7_st {
	PKCS7 *pkcs7;
} ossl_pkcs7;

typedef struct ossl_pkcs7si_st {
	PKCS7_SIGNER_INFO *signer;
} ossl_pkcs7si;

static void
ossl_pkcs7_free(ossl_pkcs7 *pkcs7p)
{
	if (pkcs7p) {
		if (pkcs7p->pkcs7) {
			PKCS7_free(pkcs7p->pkcs7);
		}
		free(pkcs7p);
	}
}

static void
ossl_pkcs7si_free(ossl_pkcs7si *p7sip)
{
	if (p7sip) {
		if (p7sip->signer) {
			PKCS7_SIGNER_INFO_free(p7sip->signer);
		}
		free(p7sip);
	}
}

/*
 * Public
 */
VALUE
ossl_pkcs7si_new_null(void)
{
	ossl_pkcs7si *p7sip = NULL;
	VALUE obj;
	
	MakePKCS7si(obj, p7sip);

	if (!(p7sip->signer = PKCS7_SIGNER_INFO_new())) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	return obj;
}

VALUE
ossl_pkcs7si_new(PKCS7_SIGNER_INFO *si)
{
	ossl_pkcs7si *p7sip = NULL;
	VALUE obj;

	if (!si)
		return ossl_pkcs7si_new_null();

	MakePKCS7si(obj, p7sip);

	if (!(p7sip->signer = PKCS7_SIGNER_INFO_dup(si))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	return obj;
}

PKCS7_SIGNER_INFO *
ossl_pkcs7si_get_PKCS7_SIGNER_INFO(VALUE obj)
{
	ossl_pkcs7si *p7sip = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	
	GetPKCS7si(obj, p7sip);

	if (!(si = PKCS7_SIGNER_INFO_dup(p7sip->signer))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	return si;
}

/*
 * Private
 */
/*
 * WORKS WELL, but we can implement this in Ruby space
static VALUE ossl_pkcs7_s_sign(VALUE klass, VALUE key, VALUE cert, VALUE data)
{
	ossl_pkcs7 *p7p = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	PKCS7 *p7 = NULL;
	VALUE obj;
	
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(cert, X509Certificate);
	Check_Type(data, T_STRING);

	Check_SafeStr(data);
	if (rb_funcall(key, rb_intern("private?"), 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "private key needed!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	x509 = ossl_x509_get_X509(cert);

	if (!(bio = BIO_new_mem_buf(RSTRING(data)->ptr, -1))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	if (!(p7 = PKCS7_sign(x509, pkey, NULL, bio, 0))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	BIO_free(bio);
	
	MakePKCS7(obj, p7p);
	p7p->pkcs7 = p7;

	return obj;
}
 */

static VALUE
ossl_pkcs7_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_pkcs7 *pkcs7p = NULL;
	VALUE obj;

	MakePKCS7(obj, pkcs7p);
	
	rb_obj_call_init(obj, argc, argv);
	return obj;
}

static VALUE
ossl_pkcs7_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_pkcs7 *p7p = NULL;
	BIO *in = NULL;
	PKCS7 *p7 = NULL;
	VALUE arg1;
	
	GetPKCS7_unsafe(self, p7p);

	rb_scan_args(argc, argv, "10", &arg1);
	
	switch (TYPE(arg1)) {
		case T_FIXNUM:
			if (!(p7 = PKCS7_new())) {
				rb_raise(ePKCS7Error, "%s", ossl_error());
			}
			if(!PKCS7_set_type(p7, FIX2INT(arg1))) {
				/*PKCS7_free(p7);*/
				rb_raise(ePKCS7Error, "%s", ossl_error());
			}
			break;
		case T_STRING:
			Check_SafeStr(arg1);
			if (!(in = BIO_new_mem_buf(RSTRING(arg1)->ptr, -1))) {
				rb_raise(ePKCS7Error, "%s", ossl_error());
			}
			if (!(p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL))) {
				rb_raise(ePKCS7Error, "%s", ossl_error());
			}
			BIO_free(in);
			break;
		default:
			rb_raise(ePKCS7Error, "unsupported param (%s)", rb_class2name(CLASS_OF(arg1)));
	}
	p7p->pkcs7 = p7;

	return self;
}

/*
 * 
static VALUE ossl_pkcs7_set_type(VALUE self, VALUE type)
{
	PKCS7_set_type(p7, NID);
}
 */

static VALUE
ossl_pkcs7_set_cipher(VALUE self, VALUE cipher)
{
	ossl_pkcs7 *p7p = NULL;

	GetPKCS7(self, p7p);

	OSSL_Check_Type(cipher, cCipher);
	
	if (!PKCS7_set_cipher(p7p->pkcs7, ossl_cipher_get_EVP_CIPHER(cipher))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	return cipher;
}

static VALUE
ossl_pkcs7_add_signer(VALUE self, VALUE signer, VALUE pkey)
{
	ossl_pkcs7 *p7p = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	EVP_PKEY *key = NULL;
	
	GetPKCS7(self, p7p);

	OSSL_Check_Type(pkey, cPKey);
	OSSL_Check_Type(signer, cPKCS7SignerInfo);

	if (rb_funcall(pkey, rb_intern("private?"), 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "private key needed!");
	}
	si = ossl_pkcs7si_get_PKCS7_SIGNER_INFO(signer);
	key = ossl_pkey_get_EVP_PKEY(pkey);
	si->pkey = key;
	
	if (!PKCS7_add_signer(p7p->pkcs7, si)) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	if (PKCS7_type_is_signed(p7p->pkcs7))
		PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
	
	return self;
}

static VALUE
ossl_pkcs7_get_signer(VALUE self)
{
	ossl_pkcs7 *p7p = NULL;
	STACK_OF(PKCS7_SIGNER_INFO) *sk = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	int num = 0, i;
	VALUE ary;
	
	GetPKCS7(self, p7p);

	if (!(sk = PKCS7_get_signer_info(p7p->pkcs7))) {
		rb_warning("OpenSSL::PKCS7 get_signer_info == NULL!");
		return rb_ary_new();
	}

	if ((num = sk_PKCS7_SIGNER_INFO_num(sk)) < 0) {
		rb_raise(ePKCS7Error, "negative no of signers!");
	}
	
	ary = rb_ary_new2(num);

	for (i=0; i<num; i++) {
		si = sk_PKCS7_SIGNER_INFO_value(sk, i);
		rb_ary_push(ary, ossl_pkcs7si_new(si));
	}
	
	return ary;
}

static VALUE
ossl_pkcs7_add_recipient(VALUE self, VALUE cert)
{
	ossl_pkcs7 *p7p = NULL;
	PKCS7_RECIP_INFO *ri = NULL;
	
	GetPKCS7(self, p7p);

	OSSL_Check_Type(cert, cX509Certificate);
	
	if (!(ri = PKCS7_RECIP_INFO_new())) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	if (!PKCS7_RECIP_INFO_set(ri, ossl_x509_get_X509(cert))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	if (!PKCS7_add_recipient_info(p7p->pkcs7, ri)) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	
	return self;
}

static VALUE
ossl_pkcs7_add_certificate(VALUE self, VALUE cert)
{
	ossl_pkcs7 *p7p = NULL;

	GetPKCS7(self, p7p);

	OSSL_Check_Type(cert, cX509Certificate);

	if (!PKCS7_add_certificate(p7p->pkcs7, ossl_x509_get_X509(cert))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	return self;
}

static VALUE
ossl_pkcs7_add_crl(VALUE self, VALUE crl)
{
	ossl_pkcs7 *p7p = NULL;

	GetPKCS7(self, p7p);

	OSSL_Check_Type(crl, cX509CRL);

	if (!PKCS7_add_crl(p7p->pkcs7, ossl_x509crl_get_X509_CRL(crl))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	return self;
}

static VALUE
ossl_pkcs7_add_data(int argc, VALUE *argv, VALUE self)
{
	ossl_pkcs7 *p7p = NULL;
	BIO *bio = NULL;
	int i;
	VALUE data, detached;
	
	GetPKCS7(self, p7p);

	rb_scan_args(argc, argv, "11", &data, &detached);
	
	Check_Type(data, T_STRING);
	Check_SafeStr(data);

	PKCS7_content_new(p7p->pkcs7, NID_pkcs7_data);

	if (detached == Qtrue)
		PKCS7_set_detached(p7p->pkcs7, 1);

	if (!(bio=PKCS7_dataInit(p7p->pkcs7, NULL))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	if ((i = BIO_write(bio, RSTRING(data)->ptr, RSTRING(data)->len)) != RSTRING(data)->len) {
		rb_raise(ePKCS7Error, "BIO_wrote %d, but should be %d!", i, RSTRING(data)->len);
	}
	if (!PKCS7_dataFinal(p7p->pkcs7, bio)) {
		BIO_free(bio);
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	BIO_free(bio);

	return self;
}

static VALUE
ossl_pkcs7_data_verify(VALUE self, VALUE x509store, VALUE detached)
{
	ossl_pkcs7 *p7p = NULL;
	BIO *bio = NULL, *data = NULL;
	char buf[1024*4];
	int i = 0;
	STACK_OF(PKCS7_SIGNER_INFO) *sk = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX ctx;
	VALUE ary;
	
	GetPKCS7(self, p7p);
	
	if (!PKCS7_type_is_signed(p7p->pkcs7)) {
		rb_raise(ePKCS7Error, "Wrong content type - PKCS7 is not SIGNED");
	}
	
	OSSL_Check_Type(x509store, cX509Store);
	Check_Type(detached, T_STRING);
	
	store = ossl_x509store_get_X509_STORE(x509store);
	
	if (!NIL_P(data)) {
		if (!(data = BIO_new_mem_buf(RSTRING(detached)->ptr, -1))) {
			rb_raise(ePKCS7Error, "%s", ossl_error());
		}
	}
	
	if (PKCS7_get_detached(p7p->pkcs7)) {
		if (!data)
			rb_raise(ePKCS7Error, "PKCS7 is detached, data needed!");
		bio = PKCS7_dataInit(p7p->pkcs7, data);
	} else {
		bio = PKCS7_dataInit(p7p->pkcs7, NULL);
	}
	if (!bio) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}

	/* We have to 'read' from bio to calculate digests etc. */
	for (;;) {
		i = BIO_read(bio, buf, sizeof(buf));
		if (i <= 0) break;
	}

	sk = PKCS7_get_signer_info(p7p->pkcs7);
	if (!sk) {
		rb_raise(ePKCS7Error, "NO SIGNATURES ON THIS DATA");
	}
	
	for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++) {
		si = sk_PKCS7_SIGNER_INFO_value(sk, i);
		i = PKCS7_dataVerify(store, &ctx, bio, p7p->pkcs7, si);
		if (i <= 0) {
			rb_warn("PKCS7::PKCS7.verify_data(): %s", ossl_error());
			return Qfalse;
		}
		
		/*
		 * Yeld signer info
		 */
		rb_yield(ossl_pkcs7si_new(si));
	}
	return Qtrue;
}

static VALUE
ossl_pkcs7_data_decode(VALUE self, VALUE key, VALUE cert)
{
	ossl_pkcs7 *p7p = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetPKCS7(self, p7p);

	if(!PKCS7_type_is_enveloped(p7p->pkcs7)) {
		rb_raise(ePKCS7Error, "Wrong content type - PKCS7 is not ENVELOPED");
	}
	
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(cert, cX509Certificate);

	if (rb_funcall(key, rb_intern("private?"), 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "private key needed!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	x509 = ossl_x509_get_X509(cert);

	if (!(bio = PKCS7_dataDecode(p7p->pkcs7, pkey, NULL, x509))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	BIO_get_mem_ptr(bio, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(bio);

	return str;
}

static VALUE
ossl_pkcs7_to_pem(VALUE self)
{
	ossl_pkcs7 *p7p = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetPKCS7(self, p7p);

	if (!(out = BIO_new(BIO_s_mem()))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	if (!PEM_write_bio_PKCS7(out, p7p->pkcs7)) {
		BIO_free(out);
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

/*
 * SIGNER INFO
 */
static VALUE
ossl_pkcs7si_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_pkcs7si *p7sip = NULL;
	VALUE obj;
	
	MakePKCS7si(obj, p7sip);
	
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE
ossl_pkcs7si_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_pkcs7si *p7sip = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	const EVP_MD *md = NULL;
	VALUE key, cert, digest;

	GetPKCS7si_unsafe(self, p7sip);

	rb_warn("HERE!");
	rb_scan_args(argc, argv, "30", &cert, &key, &digest);
	
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(cert, cX509Certificate);
	OSSL_Check_Type(digest, cDigest);

	if (rb_funcall(key, rb_intern("private?"), 0, NULL) != Qtrue) {
		rb_raise(ePKCS7Error, "private key needed!");
	}
	pkey = ossl_pkey_get_EVP_PKEY(key);
	x509 = ossl_x509_get_X509(cert);
	md = ossl_digest_get_EVP_MD(digest);

	if (!(si = PKCS7_SIGNER_INFO_new())) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	if (!(PKCS7_SIGNER_INFO_set(si, x509, pkey, md))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	p7sip->signer = si;

	return self;
}

static VALUE
ossl_pkcs7si_get_name(VALUE self)
{
	ossl_pkcs7si *p7sip = NULL;

	GetPKCS7si(self, p7sip);

	return ossl_x509name_new2(p7sip->signer->issuer_and_serial->issuer);
}

static VALUE
ossl_pkcs7si_get_serial(VALUE self)
{
	ossl_pkcs7si *p7sip = NULL;

	GetPKCS7si(self, p7sip);

	return INT2NUM(ASN1_INTEGER_get(p7sip->signer->issuer_and_serial->serial));
}

static VALUE
ossl_pkcs7si_get_signed_time(VALUE self)
{
	ossl_pkcs7si *p7sip = NULL;
	ASN1_TYPE *asn1obj = NULL;
	
	GetPKCS7si(self, p7sip);
	
	if (!(asn1obj = PKCS7_get_signed_attribute(p7sip->signer, NID_pkcs9_signingTime))) {
		rb_raise(ePKCS7Error, "%s", ossl_error());
	}
	if (asn1obj->type == V_ASN1_UTCTIME)
		return asn1time_to_time(asn1obj->value.utctime);

	return Qnil;
}

/*
 * INIT
 */
void
Init_pkcs7(VALUE mPKCS7)
{
	ePKCS7Error = rb_define_class_under(mPKCS7, "Error", rb_eStandardError);

	cPKCS7 = rb_define_class_under(mPKCS7, "PKCS7", rb_cObject);
	/*
	 * WORKS WELL, but we can implement this in Ruby space
	 * rb_define_singleton_method(cPKCS7, "sign", ossl_pkcs7_s_sign, 3);
	 */
	rb_define_singleton_method(cPKCS7, "new", ossl_pkcs7_s_new, -1);
	rb_define_method(cPKCS7, "initialize", ossl_pkcs7_initialize, -1);
	rb_define_method(cPKCS7, "add_signer", ossl_pkcs7_add_signer, 2);
	rb_define_method(cPKCS7, "signers", ossl_pkcs7_get_signer, 0);
	rb_define_method(cPKCS7, "cipher=", ossl_pkcs7_set_cipher, 1);
	rb_define_method(cPKCS7, "add_recipient", ossl_pkcs7_add_recipient, 1);
	rb_define_method(cPKCS7, "add_certificate", ossl_pkcs7_add_certificate, 1);
	rb_define_method(cPKCS7, "add_crl", ossl_pkcs7_add_crl, 1);
	rb_define_method(cPKCS7, "add_data", ossl_pkcs7_add_data, -1);
	rb_define_method(cPKCS7, "verify_data", ossl_pkcs7_data_verify, 2);
	rb_define_method(cPKCS7, "decode_data", ossl_pkcs7_data_decode, 2);
	rb_define_method(cPKCS7, "to_pem", ossl_pkcs7_to_pem, 0);
	
	cPKCS7SignerInfo = rb_define_class_under(mPKCS7, "Signer", rb_cObject);
	rb_define_singleton_method(cPKCS7SignerInfo, "new", ossl_pkcs7si_s_new, -1);
	rb_define_method(cPKCS7SignerInfo, "initialize", ossl_pkcs7si_initialize, -1);
	rb_define_method(cPKCS7SignerInfo, "name", ossl_pkcs7si_get_name, 0);
	rb_define_method(cPKCS7SignerInfo, "serial", ossl_pkcs7si_get_serial, 0);
	rb_define_method(cPKCS7SignerInfo, "signed_time", ossl_pkcs7si_get_signed_time, 0);
	
	DefPKCS7Const(SIGNED);
	DefPKCS7Const(ENVELOPED);
	DefPKCS7Const(SIGNED_ENVELOPED);
}

