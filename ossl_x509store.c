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
#include <rubysig.h>

#define MakeX509Store(klass, obj, storep) do { \
	obj = Data_Make_Struct(klass, ossl_x509store, 0, ossl_x509store_free, storep); \
	if (!storep) { \
		ossl_raise(rb_eRuntimeError, "STORE wasn't initialized!"); \
	} \
} while (0)
#define GetX509Store(obj, storep) do { \
	Data_Get_Struct(obj, ossl_x509store, storep); \
	if (!storep) { \
		ossl_raise(rb_eRuntimeError, "STORE wasn't initialized!"); \
	} \
} while (0)
#define SafeGetX509Store(obj, storep) do { \
	OSSL_Check_Kind(obj, cX509Store); \
	GetX509Store(obj, storep); \
} while (0)

/*
 * Classes
 */
VALUE cX509Store;
VALUE eX509StoreError;

/*
 * General callback for OpenSSL verify
 */
int ossl_x509store_verify_cb(int, X509_STORE_CTX *);

/*
 * Struct
 */
typedef struct ossl_x509store_st {
	int protect;
	X509_STORE_CTX *store;
} ossl_x509store;

static void 
ossl_x509store_free(ossl_x509store *storep)
{
	if (storep) {
		if (storep->store && storep->protect == Qfalse) {
			X509_STORE_CTX_free(storep->store);
		}
		storep->store = NULL;
		free(storep);
	}
}

/*
 * Public functions
 */
VALUE 
ossl_x509store_new(X509_STORE_CTX *ctx)
{
	ossl_x509store *storep;
	VALUE obj;

	MakeX509Store(cX509Store, obj, storep);

	/*
	 * Is there any way to _dup X509_STORE_CTX?
	 */
	/*
	if (!(ctx2 = X509_STORE_CTX_new())) {
		ossl_raise(eX509StoreError, "");
	}
	X509_STORE_CTX_init(ctx2, X509_STORE_dup(ctx->ctx), X509_dup(ctx->cert), NULL);
	 */
	storep->store = ctx;
	storep->protect = Qtrue; /* we're using pointer without DUP - don't free this one */
	
	return obj;
}

X509_STORE *
ossl_x509store_get_X509_STORE(VALUE obj)
{
	ossl_x509store *storep;
	
	SafeGetX509Store(obj, storep);
	
	storep->protect = Qtrue; /* we gave out internal pointer without DUP - don't free this one */
	
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
	if (!(item = (ossl_session_db *)OPENSSL_malloc(sizeof(ossl_session_db)))) {
		rb_thread_critical = 0;
		ossl_raise(eX509StoreError, "");
	}
	item->key = key;
	item->data = data;
	item->next = NULL;
	
	if (last) {
		last->next = item;
	} else {
		db_root = item;
	}
	rb_thread_critical = 0;

	return data;
}

/*
 * Private functions
 */
static VALUE 
ossl_x509store_s_allocate(VALUE klass)
{
	ossl_x509store *storep;
	VALUE obj;

	MakeX509Store(klass, obj, storep);

	return obj;
}

static VALUE 
ossl_x509store_initialize(int argc, VALUE *argv, VALUE self)
{
	ossl_x509store *storep;
	X509_STORE *store;

	GetX509Store(self, storep);

	if (!(store = X509_STORE_new())) {
		ossl_raise(eX509StoreError, "");
	}
	if (!(storep->store = X509_STORE_CTX_new())) {
		ossl_raise(eX509StoreError, "");
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
	ossl_x509store *storep;
	
	GetX509Store(self, storep);
	
	if (!X509_STORE_add_cert(storep->store->ctx, GetX509CertPtr(cert))) { /* NO DUP needed! */
		ossl_raise(eX509StoreError, "");
	}
	return cert;
}

static VALUE
ossl_x509store_get_chain(VALUE self)
{
	ossl_x509store *storep;
	X509 *x509;
	int i, num;
	VALUE ary;

	GetX509Store(self, storep);

	num = sk_X509_num(storep->store->chain);
	
	if (num < 0) {
		OSSL_Debug("certs in chain < 0???");
		return rb_ary_new();
	}	
	ary = rb_ary_new2(num);
	
	for(i=0; i<num; i++) {
		x509 = sk_X509_value(storep->store->chain, i);
		rb_ary_push(ary, ossl_x509_new(x509));
/*
 * TODO
 * find out if we can free x509
		X509_free(x509);
 */
	}
	
	return ary;
}

static VALUE 
ossl_x509store_add_crl(VALUE self, VALUE crl)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);
	
	if (!X509_STORE_add_crl(storep->store->ctx, GetX509CRLPtr(crl))) { /* NO DUP needed */
		ossl_raise(eX509StoreError, "");
	}

	/*
	 * Check CRL
	 */
	X509_STORE_CTX_set_flags(storep->store, X509_V_FLAG_CRL_CHECK);

	return crl;
}

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
		store_ctx = ossl_x509store_new(ctx);
		args = rb_ary_new2(3);
		rb_ary_store(args, 0, proc);
		rb_ary_store(args, 1, ok ? Qtrue : Qfalse);
		rb_ary_store(args, 2, store_ctx);
		ret = rb_rescue(ossl_x509store_call_verify_cb_proc, args, ossl_x509store_verify_false, Qnil);
		
		if (ret == Qtrue) {
			ok = 1;
			X509_STORE_CTX_set_error(ctx, X509_V_OK);
		} else {
			ok = 0;
			if (X509_STORE_CTX_get_error(ctx) == X509_V_OK) {
				X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
			}
		}
	}
	return ok;
}

static VALUE 
ossl_x509store_verify(VALUE self, VALUE cert)
{
	ossl_x509store *storep;
	int result;

	GetX509Store(self, storep);

	X509_STORE_CTX_set_cert(storep->store, GetX509CertPtr(cert)); /* NO DUP NEEDED. */
	
	if ((result = X509_verify_cert(storep->store)) < 0) {
		ossl_raise(eX509StoreError, "");
	}
	/*
	 * TODO
	 * Should we clear chain?
	X509_STORE_CTX_cleanup(storep->store);
	 */
	if (result == 1) {
		return Qtrue;
	}
	return Qfalse;
}

static VALUE 
ossl_x509store_get_verify_status(VALUE self)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	return INT2FIX(X509_STORE_CTX_get_error(storep->store));
}

static VALUE
ossl_x509store_set_verify_status(VALUE self, VALUE err)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	X509_STORE_CTX_set_error(storep->store, FIX2INT(err));

	return err;
}

static VALUE 
ossl_x509store_get_verify_message(VALUE self)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	return rb_str_new2(X509_verify_cert_error_string(storep->store->error));
}

static VALUE 
ossl_x509store_get_verify_depth(VALUE self)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	return INT2FIX(X509_STORE_CTX_get_error_depth(storep->store));
}

static VALUE 
ossl_x509store_get_cert(VALUE self)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	/*
	 * TODO
	 * Find out if we can free X509
	 */
	return ossl_x509_new(X509_STORE_CTX_get_current_cert(storep->store));
}

static VALUE 
ossl_x509store_set_default_paths(VALUE self)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	if (!X509_STORE_set_default_paths(storep->store->ctx)) {
		ossl_raise(eX509StoreError, "");
	}
	return self;
}

static VALUE 
ossl_x509store_load_locations(VALUE self, VALUE path)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);
	
	SafeStringValue(path);

	if (!X509_STORE_load_locations(storep->store->ctx, NULL, RSTRING(path)->ptr)) {
		ossl_raise(eX509StoreError, "");
	}
	return self;
}

static VALUE 
ossl_x509store_set_verify_cb(VALUE self, VALUE proc)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	/*
	 * Associate verify_cb with Store in DB
	 */
	ossl_session_db_set((void *)storep->store->ctx, proc);
	
	rb_ivar_set(self, rb_intern("@verify_callback"), proc);
	
	return proc;
}

static VALUE
ossl_x509store_cleanup(VALUE self)
{
	ossl_x509store *storep;

	GetX509Store(self, storep);

	X509_STORE_CTX_cleanup(storep->store); 
	
	return self;
}

/*
 * INIT
 */
void 
Init_ossl_x509store()
{
	/*
	 * INIT verify_cb DB
	 */
	db_root = NULL;
	
	eX509StoreError = rb_define_class_under(mX509, "StoreError", eOSSLError);

	cX509Store = rb_define_class_under(mX509, "Store", rb_cObject);
	
	rb_define_singleton_method(cX509Store, "allocate", ossl_x509store_s_allocate, 0);
	rb_define_method(cX509Store, "initialize", ossl_x509store_initialize, -1);

	rb_attr(cX509Store, rb_intern("verify_callback"), 1, 0, Qfalse);
	rb_define_method(cX509Store, "verify_callback=", ossl_x509store_set_verify_cb, 1);
	
	rb_define_method(cX509Store, "add_trusted", ossl_x509store_add_trusted, 1);
	rb_define_method(cX509Store, "add_crl", ossl_x509store_add_crl, 1);
	
	rb_define_method(cX509Store, "verify", ossl_x509store_verify, 1);
	rb_define_method(cX509Store, "verify_status", ossl_x509store_get_verify_status, 0);
	rb_define_method(cX509Store, "verify_status=", ossl_x509store_set_verify_status, 1);
	rb_define_method(cX509Store, "verify_message", ossl_x509store_get_verify_message, 0);
	rb_define_method(cX509Store, "verify_depth", ossl_x509store_get_verify_depth, 0);
	rb_define_method(cX509Store, "chain", ossl_x509store_get_chain, 0);
	rb_define_method(cX509Store, "cert", ossl_x509store_get_cert, 0);
	rb_define_method(cX509Store, "set_default_paths", ossl_x509store_set_default_paths, 0);
	rb_define_method(cX509Store, "load_locations", ossl_x509store_load_locations, 1);

	rb_define_method(cX509Store, "cleanup!", ossl_x509store_cleanup, 0);
	
#define DefX509StoreConst(x) rb_define_const(cX509Store, #x, INT2FIX(X509_V_ERR_##x))

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

