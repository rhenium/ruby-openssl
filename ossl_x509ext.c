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

#define WrapX509Ext(klass, obj, ext) do { \
	if (!ext) { \
		rb_raise(rb_eRuntimeError, "EXT wasn't initialized!"); \
	} \
	obj = Data_Wrap_Struct(klass, 0, X509_EXTENSION_free, ext); \
} while (0)
#define GetX509Ext(obj, ext) do { \
	Data_Get_Struct(obj, X509_EXTENSION, ext); \
	if (!ext) { \
		rb_raise(rb_eRuntimeError, "EXT wasn't initialized!"); \
	} \
} while (0)
#define SafeGetX509Ext(obj, ext) do { \
	OSSL_Check_Kind(obj, cX509Ext); \
	GetX509Ext(obj, ext); \
} while (0)

#define MakeX509ExtFactory(klass, obj, ctx) \
	obj = Data_Make_Struct(klass, X509V3_CTX, 0, ossl_x509extfactory_free, ctx)
#define GetX509ExtFactory(obj, ctx) do { \
	Data_Get_Struct(obj, X509V3_CTX, ctx); \
	if (!ctx) { \
		rb_raise(rb_eRuntimeError, "CTX wasn't initialized!"); \
	} \
} while (0)

/*
 * Classes
 */
VALUE cX509Ext;
VALUE cX509ExtFactory;
VALUE eX509ExtError;

/*
 * Public
 */
VALUE 
ossl_x509ext_new(X509_EXTENSION *ext)
{
	X509_EXTENSION *new;
	VALUE obj;

	if (!ext) {
		new = X509_EXTENSION_new();
	} else {
		new = X509_EXTENSION_dup(ext);
	}
	if (!new) {
		OSSL_Raise(eX509ExtError, "");
	}
	WrapX509Ext(cX509Ext, obj, new);
	
	return obj;
}

X509_EXTENSION *
ossl_x509ext_get_X509_EXTENSION(VALUE obj)
{
	X509_EXTENSION *ext, *new;

	SafeGetX509Ext(obj, ext);

	if (!(new = X509_EXTENSION_dup(ext))) {
		OSSL_Raise(eX509ExtError, "");
	}
	return new;
}

/*
 * Private
 */
/*
 * Ext factory
 */
static void
ossl_x509extfactory_free(X509V3_CTX *ctx)
{
	if (ctx) {
		if (ctx->issuer_cert)	X509_free(ctx->issuer_cert);
		if (ctx->subject_cert)	X509_free(ctx->subject_cert);
		if (ctx->crl)		X509_CRL_free(ctx->crl);
		if (ctx->subject_req)	X509_REQ_free(ctx->subject_req);
		OPENSSL_free(ctx);
	}
}

static VALUE 
ossl_x509extfactory_s_allocate(VALUE klass)
{
	X509V3_CTX *ctx;
	VALUE obj;
	
	MakeX509ExtFactory(klass, obj, ctx);

	return obj;
}

static VALUE 
ossl_x509extfactory_set_issuer_cert(VALUE self, VALUE cert)
{
	X509V3_CTX *ctx;

	GetX509ExtFactory(self, ctx);

	ctx->issuer_cert = DupX509CertPtr(cert); /* DUP NEEDED */

	return cert;
}

static VALUE 
ossl_x509extfactory_set_subject_cert(VALUE self, VALUE cert)
{
	X509V3_CTX *ctx;

	GetX509ExtFactory(self, ctx);

	ctx->subject_cert = DupX509CertPtr(cert); /* DUP NEEDED */

	return cert;
}

static VALUE 
ossl_x509extfactory_set_subject_req(VALUE self, VALUE req)
{
	X509V3_CTX *ctx;

	GetX509ExtFactory(self, ctx);

	ctx->subject_req = ossl_x509req_get_X509_REQ(req);

	return req;
}

static VALUE 
ossl_x509extfactory_set_crl(VALUE self, VALUE crl)
{
	X509V3_CTX *ctx;

	GetX509ExtFactory(self, ctx);

	ctx->crl = ossl_x509crl_get_X509_CRL(crl);

	return crl;
}

static VALUE 
ossl_x509extfactory_initialize(int argc, VALUE *argv, VALUE self)
{
	/*X509V3_CTX *ctx;*/
	VALUE issuer_cert, subject_cert, subject_req, crl;
	
	/*GetX509ExtFactory(self, ctx);*/

	rb_scan_args(argc, argv, "04", &issuer_cert, &subject_cert, &subject_req, &crl);

	if (!NIL_P(issuer_cert)) {
		ossl_x509extfactory_set_issuer_cert(self, issuer_cert);
	}
	if (!NIL_P(subject_cert)) {
		ossl_x509extfactory_set_subject_cert(self, subject_cert);
	}
	if (!NIL_P(subject_req)) {
		ossl_x509extfactory_set_subject_req(self, subject_req);
	}
	if (!NIL_P(crl)) {
		ossl_x509extfactory_set_crl(self, crl);
	}
	return self;
}

/*
 * Array to X509_EXTENSION
 * Structure:
 * ["ln", "value", bool_critical] or
 * ["sn", "value", bool_critical] or
 * ["ln", "critical,value"] or the same for sn
 * ["ln", "value"] => not critical
 */
static VALUE 
ossl_x509extfactory_create_ext_from_array(VALUE self, VALUE ary)
{
	X509V3_CTX *ctx;
	X509_EXTENSION *ext;
	int nid;
	char *value;
	VALUE item, obj;
	
	GetX509ExtFactory(self, ctx);
	
	Check_Type(ary, T_ARRAY);

	if ((RARRAY(ary)->len) < 2 || (RARRAY(ary)->len > 3)) { /*2 or 3 allowed*/
		rb_raise(eX509ExtError, "unsupported structure");
	}

	/* key [0] */
	item = RARRAY(ary)->ptr[0];
	StringValue(item);
	if (!(nid = OBJ_ln2nid(RSTRING(item)->ptr))) {
		if (!(nid = OBJ_sn2nid(RSTRING(item)->ptr))) {
			OSSL_Raise(eX509ExtError, "");
		}
	}

	/* data [1] */
	item = RARRAY(ary)->ptr[1];
	StringValue(item);

	/* (optional) critical [2] */
	if (RARRAY(ary)->len == 3 && RARRAY(ary)->ptr[2] == Qtrue) {
		if (!(value = OPENSSL_malloc(strlen("critical,") + (RSTRING(item)->len) + 1))) {
			OSSL_Raise(eX509ExtError, "malloc error");
		}
		strcpy(value, "critical,");
		strncat(value, RSTRING(item)->ptr, RSTRING(item)->len);
	} else {
		value = strdup(StringValuePtr(item));
	}
	if (!(ext = X509V3_EXT_conf_nid(NULL, ctx, nid, value))) {
		OPENSSL_free(value);
		OSSL_Raise(eX509ExtError, "");
	}
	OPENSSL_free(value);
	
	WrapX509Ext(cX509Ext, obj, ext);

	return obj;
}

/*
 * Ext
 */
static VALUE 
ossl_x509ext_to_a(VALUE obj)
{
	X509_EXTENSION *ext;
	BIO *out;
	BUF_MEM *buf;
	int nid, critical;
	VALUE ary, value;

	GetX509Ext(obj, ext);

	ary = rb_ary_new2(3);

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
	rb_ary_push(ary, rb_str_new2(OBJ_nid2sn(nid)));

	if (!(out = BIO_new(BIO_s_mem()))) {
		OSSL_Raise(eX509ExtError, "");
	}
	if (!X509V3_EXT_print(out, ext, 0, 0)) {
		BIO_free(out);
		OSSL_Raise(eX509ExtError, "");
	}
	BIO_get_mem_ptr(out, &buf);
	value = rb_str_new(buf->data, buf->length);
	BIO_free(out);

	rb_funcall(value, rb_intern("tr!"), 2, rb_str_new2("\n"), rb_str_new2(","));
	rb_ary_push(ary, value);
	
	critical = X509_EXTENSION_get_critical(ext);
	rb_ary_push(ary, (critical) ? Qtrue : Qfalse);

	return ary;
}

/*
 * INIT
 */
void
Init_ossl_x509ext()
{

	eX509ExtError = rb_define_class_under(mX509, "ExtensionError", eOSSLError);

	cX509ExtFactory = rb_define_class_under(mX509, "ExtensionFactory", rb_cObject);
	
	rb_define_singleton_method(cX509ExtFactory, "allocate", ossl_x509extfactory_s_allocate, 0);
	rb_define_method(cX509ExtFactory, "initialize", ossl_x509extfactory_initialize, -1);
	
	rb_define_method(cX509ExtFactory, "issuer_certificate=", ossl_x509extfactory_set_issuer_cert, 1);
	rb_define_method(cX509ExtFactory, "subject_certificate=", ossl_x509extfactory_set_subject_cert, 1);
	rb_define_method(cX509ExtFactory, "subject_request=", ossl_x509extfactory_set_subject_req, 1);
	rb_define_method(cX509ExtFactory, "crl=", ossl_x509extfactory_set_crl, 1);
	rb_define_method(cX509ExtFactory, "create_ext_from_array", ossl_x509extfactory_create_ext_from_array, 1);
	
	cX509Ext = rb_define_class_under(mX509, "Extension", rb_cObject);
	rb_undef_method(CLASS_OF(cX509Ext), "new");
/*
	rb_define_singleton_method(cX509Ext, "new", ossl_x509ext_s_new, -1);
	rb_define_method(cX509Ext, "initialize", ossl_x509ext_initialize, -1);
 */
	rb_define_method(cX509Ext, "to_a", ossl_x509ext_to_a, 0);
}

