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
#include <rubysig.h>

#define MakeX509Store(obj, storep) {\
	obj = Data_Make_Struct(cX509Store, ossl_x509store, 0, ossl_x509store_free, storep);\
}
#define GetX509Store_unsafe(obj, storep) Data_Get_Struct(obj, ossl_x509store, storep)
#define GetX509Store(obj, storep) {\
	GetX509Store_unsafe(obj, storep);\
	if (!storep->store) rb_raise(eX509StoreError, "not initialized!");\
}

#define DefX509StoreConst(x) rb_define_const(cX509Store, #x, INT2FIX(X509_V_ERR_##x))

/*
 * Classes
 */
VALUE cX509Store;
VALUE eX509StoreError;

/*
 * General callback for OpenSSL verify
 */
int 
ossl_x509store_verify_cb(int, X509_STORE_CTX *);

/*
 * Struct
 */
typedef struct ossl_x509store_st {
	char protect;
	X509_STORE_CTX *store;
} ossl_x509store;

static void 
ossl_x509store_free(ossl_x509store *storep)
{
	if (storep) {
		if (storep->store && storep->protect == 0)
			X509_STORE_CTX_free(storep->store);
		else
			storep->store = NULL;
		free(storep);
	}
}

/*
 * Public functions
 */
VALUE 
ossl_x509store_new2(X509_STORE_CTX *ctx)
{
	ossl_x509store *storep = NULL;
	X509_STORE_CTX *ctx2 = NULL;
	VALUE obj;

	MakeX509Store(obj, storep);

	/*
	 * Is there any way to _dup X509_STORE_CTX?
	 */
	/*
	if (!(ctx2 = X509_STORE_CTX_new())) {
		rb_raise(eX509StoreError, "%s", ossl_error());
	}
	X509_STORE_CTX_init(ctx2, X509_STORE_dup(ctx->ctx), X509_dup(ctx->cert), NULL);
	*/
	storep->store = ctx;
	storep->protect = 1; /* we're using pointer without DUP - don't free this one */
	
	return obj;
}

X509_STORE *
ossl_x509store_get_X509_STORE(VALUE obj)
{
	ossl_x509store *storep = NULL;
	
	GetX509Store(obj, storep);
	
	storep->protect = 1; /* we gave out internal pointer without DUP - don't free this one */
	return storep->store->ctx;
}

/*
 * verify_cb DATABASE for Stores
 * TODO:
 * clean entries when garbage collecting
 */
typedef struct ossl_session_db_st {
	void *key;
	VALUE data;
	struct ossl_session_db_st *next;
} ossl_session_db;

ossl_session_db *db_root;

static VALUE 
ossl_session_db_get(void *key)
{
	ossl_session_db *item = db_root;

	rb_thread_critical = 1;
	while (item) {
		if (item->key == key) {
			rb_thread_critical = 0;
			return item->data;
		}
		item = item->next;
	}
	rb_thread_critical = 0;
	return Qnil;
}

static VALUE 
ossl_session_db_set(void *key, VALUE data)
{
	ossl_session_db *item = db_root, *last = NULL;
	
	rb_thread_critical = 1;
	while (item) {
		if (item->key == key) {
			item->data = data;
			rb_thread_critical = 0;
			return data;
		}
		last = item;
		item = last->next;
	}
	if (!(item = (ossl_session_db *)malloc(sizeof(ossl_session_db)))) {
		rb_thread_critical = 0;
		rb_raise(ePKCS7Error, "MALLOC ERROR");
	}
	item->key = key;
	item->data = data;
	item->next = NULL;
	if (last)
		last->next = item;
	else db_root = item;
	rb_thread_critical = 0;

	return data;
}

/*
 * Private functions
 */
static VALUE 
ossl_x509store_s_new(int argc, VALUE *argv, VALUE klass)
{
	ossl_x509store *storep = NULL;
	VALUE obj;

	MakeX509Store(obj, storep);
	rb_obj_call_init(obj, argc, argv);

	return obj;
}

static VALUE 
ossl_x509store_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_x509store *storep = NULL;
	X509_STORE *store = NULL;

	GetX509Store_unsafe(self, storep);

	if (!(store = X509_STORE_new())) {
		rb_raise(eX509StoreError, "%s", ossl_error());
	}
	if (!(storep->store = X509_STORE_CTX_new())) {
		rb_raise(eX509StoreError, "%s", ossl_error());
	}
	X509_STORE_set_verify_cb_func(store, ossl_x509store_verify_cb);
	X509_STORE_CTX_init(storep->store, store, NULL, NULL);
	
	/*
	 * instance variable
	 */
	rb_ivar_set(self, rb_intern("@verify_callback"), Qnil);
	
	return self;
}

static VALUE 
ossl_x509store_add_trusted(VALUE self, VALUE cert)
{
	ossl_x509store *storep = NULL;
	X509 *x509 = NULL;
	
	GetX509Store(self, storep);
	
	OSSL_Check_Type(cert, cX509Certificate);
	x509 = ossl_x509_get_X509(cert);

	if (!X509_STORE_add_cert(storep->store->ctx, x509)) {
		rb_raise(eX509StoreError, "%s", ossl_error());
	}
	X509_free(x509);
	
	return cert;
}

/*
 * DOESN'T WORK!!!
 * I have to walk X509_OBJECTS in storep->store
static VALUE
ossl_x509store_get_chain(obj)
	VALUE obj;
{
	 ossl_x509store *storep = NULL;
	X509_STORE_CTX ctx;
	X509 *x509 = NULL;
	int i, num;
	VALUE ary, cert;

	GetX509Store(self, storep);

	X509_STORE_CTX_init(&ctx, storep->store, NULL, NULL);
	X509_verify_cert(&ctx);
	num = sk_X509_num(ctx.chain);
	rb_bug("chain=%d", num);
	
	if (num < 0) return rb_ary_new();
	ary = rb_ary_new2(num);
	for(i=0; i<num; i++) {
		x509 = sk_X509_value(ctx.chain, i);
		cert = ossl_x509_new2(x509);
		rb_ary_push(ary, cert);
	}
	
	return ary;
}
 */

static VALUE 
ossl_x509store_add_crl(VALUE self, VALUE crlst)
{
	ossl_x509store *storep = NULL;
	X509_CRL *crl = NULL;

	GetX509Store(self, storep);
	
	OSSL_Check_Type(crlst, cX509CRL);
	crl = ossl_x509crl_get_X509_CRL(crlst);

	if (!X509_STORE_add_crl(storep->store->ctx, crl)) {
		rb_raise(eX509StoreError, "%s", ossl_error());
	}
	X509_CRL_free(crl);

	return crlst;
}

/*
 * No need for
static VALUE
ossl_x509store_add(VALUE self, VALUE arg)
{
	ossl_x509store *storep = NULL;
	X509 *x509 = NULL;
	X509_CRL *crl = NULL;

	GetX509Store(self, storep);

	switch (OSSL_TYPE(arg)) {
		case T_OSSL_X509CRL:
			crl = ossl_x509crl_get_X509_CRL(arg);
			if (!X509_STORE_add_crl(storep->store, crl)) {
				rb_raise(eX509StoreError, "%s", ossl_error());
			}
			break;
		case T_OSSL_X509:
			x509 = ossl_x509_get_X509(arg);
			if (!X509_STORE_add_cert(storep->store, x509)) {
				rb_raise(eX509StoreError, "%s", ossl_error());
			}
			break;
		default:
			rb_raise(rb_eTypeError, "unsupported type");
	}
	
	return obj;
}
 */

static VALUE 
ossl_x509store_call_verify_cb_proc(VALUE args)
{
	VALUE proc, ok, store_ctx;

	proc = rb_ary_entry(args, 0);
	ok = rb_ary_entry(args, 1);
	store_ctx = rb_ary_entry(args, 2);

	return rb_funcall(proc, rb_intern("call"), 2, ok, store_ctx);
}

/*
 * rescue!
 */
static VALUE 
ossl_x509store_verify_false(VALUE dummy)
{
	return Qfalse;
}

int 
ossl_x509store_verify_cb(int ok, X509_STORE_CTX *ctx)
{
	VALUE proc, store_ctx, args, ret = Qnil;

	/*
	 * Get Proc from verify_cb Database
	 */
	proc = ossl_session_db_get((void *)ctx->ctx);
	
	if (!NIL_P(proc)) {
		store_ctx = ossl_x509store_new2(ctx);
		rb_funcall(store_ctx, rb_intern("protect"), 0, NULL); /* called default by ossl_..new2 */
		args = rb_ary_new2(3);
		rb_ary_store(args, 0, proc);
		rb_ary_store(args, 1, ok ? Qtrue : Qfalse);
		rb_ary_store(args, 2, store_ctx);
		ret = rb_rescue(ossl_x509store_call_verify_cb_proc, args, ossl_x509store_verify_false, Qnil);
	}

	return (ret == Qtrue) ? 1 : 0;
}

static VALUE 
ossl_x509store_verify(VALUE self, VALUE cert)
{
	ossl_x509store *storep = NULL;
	X509 *x509 = NULL;
	int result = 0;

	GetX509Store(self, storep);

	OSSL_Check_Type(cert, cX509Certificate);
	x509 = ossl_x509_get_X509(cert);
	X509_STORE_CTX_set_cert(storep->store, x509);
	
	result = X509_verify_cert(storep->store);
	/*X509_STORE_CTX_cleanup(storep->store); /*clears chain*/

	if (result == 1) return Qtrue;
	return Qfalse;
}

static VALUE 
ossl_x509store_get_verify_status(VALUE self)
{
	ossl_x509store *storep = NULL;

	GetX509Store(self, storep);

	return INT2FIX(X509_STORE_CTX_get_error(storep->store));
}

static VALUE 
ossl_x509store_get_verify_message(VALUE self)
{
	ossl_x509store *storep = NULL;
	VALUE messages;

	GetX509Store(self, storep);

	return rb_str_new2(X509_verify_cert_error_string(storep->store->error));
}

static VALUE 
ossl_x509store_get_verify_depth(VALUE self)
{
	ossl_x509store *storep = NULL;
	VALUE depth;

	GetX509Store(self, storep);

	return INT2FIX(X509_STORE_CTX_get_error_depth(storep->store));
}

static VALUE 
ossl_x509store_get_cert(VALUE self)
{
	ossl_x509store *storep = NULL;
	VALUE cert;

	GetX509Store(self, storep);
	
	return ossl_x509_new2(X509_STORE_CTX_get_current_cert(storep->store));
}

static VALUE 
ossl_x509store_protect(VALUE self)
{
	ossl_x509store *storep = NULL;

	GetX509Store(self, storep);
	storep->protect = 1;

	return self;
}

static VALUE 
ossl_x509store_set_default_paths(VALUE self)
{
	ossl_x509store *storep = NULL;

	GetX509Store(self, storep);

	if (!X509_STORE_set_default_paths(storep->store->ctx)) {
		rb_raise(eX509StoreError, "%s", ossl_error());
	}

	return self;
}

static VALUE 
ossl_x509store_load_locations(VALUE self, VALUE path)
{
	ossl_x509store *storep = NULL;

	GetX509Store(self, storep);
	
	Check_Type(path, T_STRING);
	Check_SafeStr(path);

	if (!X509_STORE_load_locations(storep->store->ctx, NULL, RSTRING(path)->ptr)) {
		rb_raise(eX509StoreError, "%s", ossl_error());
	}

	return self;
}

static VALUE 
ossl_x509store_set_verify_cb(VALUE self, VALUE proc)
{
	ossl_x509store *storep = NULL;

	GetX509Store(self, storep);

	/*
	 * Associate verify_cb with Store in DB
	 */
	ossl_session_db_set((void *)storep->store->ctx, proc);	
	rb_ivar_set(self, rb_intern("@verify_callback"), proc);
	
	return proc;
}

/*
 * INIT
 */
void 
Init_ossl_x509store(VALUE module)
{
	/*
	 * INIT verify_cb DB
	 */
	db_root = NULL;
	
	eX509StoreError = rb_define_class_under(module, "StoreError", rb_eStandardError);

	cX509Store = rb_define_class_under(module, "Store", rb_cObject);
	rb_define_singleton_method(cX509Store, "new", ossl_x509store_s_new, -1);
	rb_define_method(cX509Store, "initialize", ossl_x509store_initialize, -1);

	rb_attr(cX509Store, rb_intern("verify_callback"), 1, 0, Qfalse);
	rb_define_method(cX509Store, "verify_callback=", ossl_x509store_set_verify_cb, 1);
	
/*
 * DOESN'T WORK! :-(( - BUT NOW WILL! :-))
	rb_define_method(cX509Store, "chain", ossl_x509store_get_chain, 0);
 */
	rb_define_method(cX509Store, "add_trusted", ossl_x509store_add_trusted, 1);
	rb_define_method(cX509Store, "add_crl", ossl_x509store_add_crl, 1);
	/*rb_define_method(cX509Store, "<<", ossl_x509store_add, 1);*/
	rb_define_method(cX509Store, "verify", ossl_x509store_verify, 1);
	rb_define_method(cX509Store, "verify_status", ossl_x509store_get_verify_status, 0);
	rb_define_method(cX509Store, "verify_message", ossl_x509store_get_verify_message, 0);
	rb_define_method(cX509Store, "verify_depth", ossl_x509store_get_verify_depth, 0);
	rb_define_method(cX509Store, "cert", ossl_x509store_get_cert, 0);
	rb_define_method(cX509Store, "protect", ossl_x509store_protect, 0);
	rb_define_method(cX509Store, "set_default_paths", ossl_x509store_set_default_paths, 0);
	rb_define_method(cX509Store, "load_locations", ossl_x509store_load_locations, 1);
	
	DefX509StoreConst(UNABLE_TO_GET_ISSUER_CERT);
	DefX509StoreConst(UNABLE_TO_GET_CRL);
	DefX509StoreConst(UNABLE_TO_DECRYPT_CERT_SIGNATURE);
	DefX509StoreConst(UNABLE_TO_DECRYPT_CRL_SIGNATURE);
	DefX509StoreConst(UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
	DefX509StoreConst(CERT_SIGNATURE_FAILURE);
	DefX509StoreConst(CRL_SIGNATURE_FAILURE);
	DefX509StoreConst(CERT_NOT_YET_VALID);
	DefX509StoreConst(CERT_HAS_EXPIRED);
	DefX509StoreConst(CRL_NOT_YET_VALID);
	DefX509StoreConst(CRL_HAS_EXPIRED);
	DefX509StoreConst(ERROR_IN_CERT_NOT_BEFORE_FIELD);
	DefX509StoreConst(ERROR_IN_CERT_NOT_AFTER_FIELD);
	DefX509StoreConst(ERROR_IN_CRL_LAST_UPDATE_FIELD);
	DefX509StoreConst(ERROR_IN_CRL_NEXT_UPDATE_FIELD);
	DefX509StoreConst(OUT_OF_MEM);
	DefX509StoreConst(DEPTH_ZERO_SELF_SIGNED_CERT);
	DefX509StoreConst(SELF_SIGNED_CERT_IN_CHAIN);
	DefX509StoreConst(UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
	DefX509StoreConst(UNABLE_TO_VERIFY_LEAF_SIGNATURE);
	DefX509StoreConst(CERT_CHAIN_TOO_LONG);
	DefX509StoreConst(CERT_REVOKED);
	DefX509StoreConst(INVALID_CA);
	DefX509StoreConst(PATH_LENGTH_EXCEEDED);
	DefX509StoreConst(INVALID_PURPOSE);
	DefX509StoreConst(CERT_UNTRUSTED);
	DefX509StoreConst(CERT_REJECTED);
	DefX509StoreConst(SUBJECT_ISSUER_MISMATCH);
	DefX509StoreConst(AKID_SKID_MISMATCH);
	DefX509StoreConst(AKID_ISSUER_SERIAL_MISMATCH);
	DefX509StoreConst(KEYUSAGE_NO_CERTSIGN);
	DefX509StoreConst(APPLICATION_VERIFICATION);
}

