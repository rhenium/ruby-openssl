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

#define MakeX509Req(obj, reqp) {\
	obj = Data_Make_Struct(cX509Request, ossl_x509req, 0, ossl_x509req_free, reqp);\
}

#define GetX509Req(obj, reqp) {\
	Data_Get_Struct(obj, ossl_x509req, reqp);\
}

/*
 * Classes
 */
VALUE cX509Request;
VALUE eX509RequestError;

/*
 * Struct
 */
typedef struct ossl_x509req_st {
	X509_REQ *request;
} ossl_x509req;


static void ossl_x509req_free(ossl_x509req *reqp)
{
	if(reqp) {
		if(reqp->request) X509_REQ_free(reqp->request);
		free(reqp);
	}
}

/*
 * Public functions
 */
VALUE ossl_x509req_new2(X509_REQ *req)
{
	ossl_x509req *reqp = NULL;
	VALUE self;
	
	MakeX509Req(self, reqp);
	if (!(reqp->request = X509_REQ_dup(req))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}

	return self;
}

X509_REQ *ossl_x509req_get_X509_REQ(VALUE self)
{
	ossl_x509req *reqp = NULL;
	X509_REQ *req = NULL;
	
	GetX509Req(self, reqp);
	
	if (!(req = X509_REQ_dup(reqp->request))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	return req;
}

/*
 * Private functions
 */
static VALUE ossl_x509req_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_x509req *reqp = NULL;
	VALUE obj;
	
	MakeX509Req(obj, reqp);
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE ossl_x509req_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_x509req *reqp = NULL;
	X509_REQ *req = NULL;
	BIO *in = NULL;
	VALUE buffer;
	
	GetX509Req(self, reqp);

	rb_scan_args(argc, argv, "01", &buffer);

	if (NIL_P(buffer)) {
		if (!(req = X509_REQ_new())) {
			rb_raise(eX509RequestError, "%s", ossl_error());
		}	
	} else switch (TYPE(buffer)) {
		case T_STRING:
			if (!(in = BIO_new_mem_buf(RSTRING(buffer)->ptr, -1))) {
				rb_raise(eX509RequestError, "%s", ossl_error());
			}
			if (!(req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL))) {
				BIO_free(in);
				rb_raise(eX509RequestError, "%s", ossl_error());
			}
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported type");
	}
	
	reqp->request = req;

	return self;
}

static VALUE ossl_x509req_to_pem(VALUE self)
{
	ossl_x509req *reqp = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509Req(self, reqp);

	if (!(out = BIO_new(BIO_s_mem()))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	if (!PEM_write_bio_X509_REQ(out, reqp->request)) {
		BIO_free(out);
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

static VALUE ossl_x509req_to_str(VALUE self)
{
	ossl_x509req *reqp = NULL;
	BIO *out = NULL;
	BUF_MEM *buf = NULL;
	VALUE str;
	
	GetX509Req(self, reqp);

	if (!(out = BIO_new(BIO_s_mem()))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	if (!X509_REQ_print(out, reqp->request)) {
		BIO_free(out);
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	BIO_get_mem_ptr(out, &buf);
	str = rb_str_new(buf->data, buf->length);
	BIO_free(out);
	
	return str;
}

/*
 * Makes X509 from X509_REQuest
 *
static VALUE ossl_x509req_to_x509(VALUE self, VALUE days, VALUE key)
{
	ossl_x509req *reqp = NULL;
	X509 *x509 = NULL;
	
	GetX509Req(self, reqp);
	...
	if (!(x509 = X509_REQ_to_X509(reqp->req, d, pkey))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}

	return ossl_x509req_new2(x509);
}
 */

static VALUE ossl_x509req_get_version(VALUE self)
{
	ossl_x509req *reqp = NULL;
	long version = 0;

	GetX509Req(self, reqp);
	
	version = X509_REQ_get_version(reqp->request);

	return INT2NUM(version);
}

static VALUE ossl_x509req_set_version(VALUE self, VALUE version)
{
	ossl_x509req *reqp = NULL;
	long ver = 0;

	GetX509Req(self, reqp);

	if ((ver = NUM2INT(version)) <= 0) {
		rb_raise(eX509RequestError, "version must be > 0!");
	}
	if (!X509_REQ_set_version(reqp->request, version)) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}

	return version;
}

static VALUE ossl_x509req_get_subject(VALUE self)
{
	ossl_x509req *reqp = NULL;
	X509_NAME *name = NULL;
	VALUE subject;
	
	GetX509Req(self, reqp);

	if (!(name = X509_REQ_get_subject_name(reqp->request))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	subject = ossl_x509name_new2(name);
	/*X509_NAME_free(name);*/
	
	return subject;
}

static VALUE ossl_x509req_set_subject(VALUE self, VALUE subject)
{
	ossl_x509req *reqp = NULL;
	X509_NAME *name = NULL;
	
	GetX509Req(self, reqp);

	OSSL_Check_Type(subject, cX509Name);
	name = ossl_x509name_get_X509_NAME(subject);

	if (!X509_REQ_set_subject_name(reqp->request, name)) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}

	return subject;
}

static VALUE ossl_x509req_get_public_key(VALUE self)
{
	ossl_x509req *reqp = NULL;
	EVP_PKEY *pkey = NULL;
	VALUE pub_key;

	GetX509Req(self, reqp);
	
	if (!(pkey = X509_REQ_get_pubkey(reqp->request))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	pub_key = ossl_pkey_new(pkey);
	EVP_PKEY_free(pkey);

	return pub_key;
}

static VALUE ossl_x509req_set_public_key(VALUE self, VALUE pubk)
{
	ossl_x509req *reqp = NULL;
	EVP_PKEY *pkey = NULL;

	GetX509Req(self, reqp);
	OSSL_Check_Type(pubk, cPKey);
	
	pkey = ossl_pkey_get_EVP_PKEY(pubk);

	if (!X509_REQ_set_pubkey(reqp->request, pkey)) {
		EVP_PKEY_free(pkey);
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	EVP_PKEY_free(pkey);

	return self;
}

VALUE ossl_x509req_sign(VALUE self, VALUE key, VALUE digest)
{
	ossl_x509req *reqp = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;

	GetX509Req(self, reqp);
	OSSL_Check_Type(key, cPKey);
	OSSL_Check_Type(digest, cDigest);
	
	if (rb_funcall(key, rb_intern("private?"), 0, NULL) == Qfalse) {
		rb_raise(eX509RequestError, "PRIVATE key needed to sign REQ!");
	}

	pkey = ossl_pkey_get_EVP_PKEY(key);
	md = ossl_digest_get_EVP_MD(digest);

	if (!X509_REQ_sign(reqp->request, pkey, md)) {
		EVP_PKEY_free(pkey);
		rb_raise(eX509RequestError, "%s", ossl_error());
	}
	EVP_PKEY_free(pkey);

	return self;
}

/*
 * Checks that cert signature is made with PRIVversion of this PUBLIC 'key'
 */
VALUE ossl_x509req_verify(VALUE self, VALUE key)
{
	ossl_x509req *reqp = NULL;
	EVP_PKEY *pkey = NULL;
	int i = 0;

	GetX509Req(self, reqp);
	OSSL_Check_Type(key, cPKey);
	
	pkey = ossl_pkey_get_EVP_PKEY(key);
	i = X509_REQ_verify(reqp->request, pkey);
	EVP_PKEY_free(pkey);

	if (i < 0) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	} else if (i > 0)
		return Qtrue;

	return Qfalse;
}

static VALUE ossl_x509req_get_attributes(VALUE self)
{
	ossl_x509req *reqp = NULL;
	int count = 0, i;
	X509_ATTRIBUTE *attr = NULL;
	VALUE ary;
	
	GetX509Req(self, reqp);

	count = X509_REQ_get_attr_count(reqp->request);

	if(count > 0) ary = rb_ary_new2(count);
	else return rb_ary_new();

	for (i=0; i<count; i++) {
		attr = X509_REQ_get_attr(reqp->request, i);
		rb_ary_push(ary, ossl_x509attr_new2(attr));
	}

	return ary;
}

static VALUE ossl_x509req_set_attributes(VALUE self, VALUE ary)
{
	ossl_x509req *reqp = NULL;
	X509_ATTRIBUTE *attr = NULL;
	int i = 0;
	VALUE item;

	GetX509Req(self, reqp);

	Check_Type(ary, T_ARRAY);

	sk_X509_ATTRIBUTE_pop_free(reqp->request->req_info->attributes, X509_ATTRIBUTE_free);
	reqp->request->req_info->attributes = NULL;
	
	for (i=0;i<RARRAY(ary)->len; i++) {
		item = RARRAY(ary)->ptr[i];
		OSSL_Check_Type(item, cX509Attribute);
		attr = ossl_x509attr_get_X509_ATTRIBUTE(item);
		if (!X509_REQ_add1_attr(reqp->request, attr)) {
			rb_raise(eX509RequestError, "%s", ossl_error());
		}
	}

	return ary;
}

static VALUE ossl_x509req_add_attribute(VALUE self, VALUE attr)
{
	ossl_x509req *reqp = NULL;
	int i = 0;
	VALUE item;

	GetX509Req(self, reqp);

	OSSL_Check_Type(attr, cX509Attribute);
	if (!X509_REQ_add1_attr(reqp->request, ossl_x509attr_get_X509_ATTRIBUTE(attr))) {
		rb_raise(eX509RequestError, "%s", ossl_error());
	}

	return attr;
}

/*
 * X509_REQUEST init
 */
void Init_ossl_x509req(VALUE mX509)
{
	eX509RequestError = rb_define_class_under(mX509, "RequestError", rb_eStandardError);
	
	cX509Request = rb_define_class_under(mX509, "Request", rb_cObject);
	rb_define_singleton_method(cX509Request, "new", ossl_x509req_s_new, -1);
	rb_define_method(cX509Request, "initialize", ossl_x509req_initialize, -1);
	rb_define_method(cX509Request, "to_pem", ossl_x509req_to_pem, 0);
	rb_define_method(cX509Request, "to_str", ossl_x509req_to_str, 0);
	rb_define_method(cX509Request, "version", ossl_x509req_get_version, 0);
	rb_define_method(cX509Request, "version=", ossl_x509req_set_version, 1);
	rb_define_method(cX509Request, "subject", ossl_x509req_get_subject, 0);
	rb_define_method(cX509Request, "subject=", ossl_x509req_set_subject, 1);
	rb_define_method(cX509Request, "public_key", ossl_x509req_get_public_key, 0);
	rb_define_method(cX509Request, "public_key=", ossl_x509req_set_public_key, 1);
	rb_define_method(cX509Request, "sign", ossl_x509req_sign, 2);
	rb_define_method(cX509Request, "verify", ossl_x509req_verify, 1);
	rb_define_method(cX509Request, "attributes", ossl_x509req_get_attributes, 0);
	rb_define_method(cX509Request, "attributes=", ossl_x509req_set_attributes, 1);
	rb_define_method(cX509Request, "add_attribute", ossl_x509req_add_attribute, 1);
}

