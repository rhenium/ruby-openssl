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

#define WrapX509Store(klass, obj, ctx) do { \
    if (!ctx) { \
	ossl_raise(rb_eRuntimeError, "STORE wasn't initialized!"); \
    } \
    obj = Data_Wrap_Struct(klass, 0, ossl_x509store_free, ctx); \
} while (0)
#define GetX509Store(obj, ctx) do { \
    Data_Get_Struct(obj, X509_STORE_CTX, ctx); \
    if (!ctx) { \
	ossl_raise(rb_eRuntimeError, "STORE wasn't initialized!"); \
    } \
} while (0)
#define SafeGetX509Store(obj, ctx) do { \
    OSSL_Check_Kind(obj, cX509Store); \
    GetX509Store(obj, ctx); \
} while (0)

/*
 * Classes
 */
VALUE cX509Store;
VALUE eX509StoreError;

/*
 * EX-DATA indexes
 */
static int ossl_x509store_vcb_idx;
static int ossl_x509store_free_idx;

/*
 * General callback for OpenSSL verify
 */
int ossl_x509store_verify_cb(int, X509_STORE_CTX *);

static void 
ossl_x509store_free(X509_STORE_CTX *ctx)
{
#if 1
    if (ctx && (VALUE)X509_STORE_CTX_get_ex_data(ctx, ossl_x509store_free_idx) == Qtrue) {
	X509_STORE_CTX_free(ctx);
    }
#else
    /*
     * Relax free-rules
     * (Just to test whether it coredumps...)
     * EXPERIMENTAL!!!
     */
    X509_STORE_CTX_free(ctx);
#endif
}

/*
 * Public functions
 */
VALUE 
ossl_x509store_new(X509_STORE_CTX *ctx)
{
    VALUE obj;

    /*
     * Is there any way to _dup X509_STORE_CTX?
     */
    /*
    if (!(ctx2 = X509_STORE_CTX_new())) {
	ossl_raise(eX509StoreError, "");
    }
    X509_STORE_CTX_init(ctx2, X509_STORE_dup(ctx->ctx), X509_dup(ctx->cert), NULL);
    */
    
    /* Ruby-space callback */
    X509_STORE_set_verify_cb_func(ctx->ctx, ossl_x509store_verify_cb);

    /* we're using pointer without DUP - don't free this one */
    X509_STORE_CTX_set_ex_data(ctx, ossl_x509store_free_idx, (void *)Qfalse);
    
    WrapX509Store(cX509Store, obj, ctx);

    return obj;
}

X509_STORE *
ossl_x509store_get_X509_STORE(VALUE obj)
{
    X509_STORE_CTX *ctx;
	
    SafeGetX509Store(obj, ctx);
    /* we gave out internal pointer without DUP - don't free this one */
    X509_STORE_CTX_set_ex_data(ctx, ossl_x509store_free_idx, (void *)Qfalse);

    return ctx->ctx;
}

/*
 * Private functions
 */
static VALUE 
ossl_x509store_alloc(VALUE klass)
{
    X509_STORE_CTX *ctx;
    X509_STORE *store;
    VALUE obj;

    ctx = X509_STORE_CTX_new();
    if (!ctx) {
	ossl_raise(eX509StoreError, "");
    }
    store = X509_STORE_new();
    if (!store) {
	X509_STORE_CTX_free(ctx);
	ossl_raise(eX509StoreError, "");
    }
    X509_STORE_CTX_init(ctx, store, NULL, NULL);
    
    X509_STORE_set_verify_cb_func(store, ossl_x509store_verify_cb);
    X509_STORE_CTX_set_ex_data(ctx, ossl_x509store_free_idx, (void *)Qtrue);

    WrapX509Store(klass, obj, ctx);

    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_x509store_alloc)

static VALUE 
ossl_x509store_initialize(int argc, VALUE *argv, VALUE self)
{
    /*
     * instance variable
     */
    rb_ivar_set(self, rb_intern("@verify_callback"), Qnil);

    return self;
}

static VALUE 
ossl_x509store_add_trusted(VALUE self, VALUE cert)
{
    X509_STORE_CTX *ctx;
	
    GetX509Store(self, ctx);
    /* NO DUP needed! */
    if (!X509_STORE_add_cert(ctx->ctx, GetX509CertPtr(cert))) {
	ossl_raise(eX509StoreError, "");
    }

    return cert;
}

static VALUE
ossl_x509store_get_chain(VALUE self)
{
    X509_STORE_CTX *ctx;
    X509 *x509;
    int i, num;
    VALUE ary;

    GetX509Store(self, ctx);
    num = sk_X509_num(ctx->chain);
    if (num < 0) {
	OSSL_Debug("certs in chain < 0???");
	return rb_ary_new();
    }	
    ary = rb_ary_new2(num);
    for(i=0; i<num; i++) {
	x509 = sk_X509_value(ctx->chain, i);
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
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);
    /* NO DUP needed */
    if (!X509_STORE_add_crl(ctx->ctx, GetX509CRLPtr(crl))) {
	ossl_raise(eX509StoreError, "");
    }
    /*
     * Check CRL
     */
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK);

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

    proc = (VALUE)X509_STORE_CTX_get_ex_data(ctx, ossl_x509store_vcb_idx);
	
    if (!NIL_P(proc)) {
	store_ctx = ossl_x509store_new(ctx);
	args = rb_ary_new2(3);
	rb_ary_store(args, 0, proc);
	rb_ary_store(args, 1, ok ? Qtrue : Qfalse);
	rb_ary_store(args, 2, store_ctx);
	ret = rb_rescue(ossl_x509store_call_verify_cb_proc, args,
			ossl_x509store_verify_false, Qnil);
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
    X509_STORE_CTX *ctx;
    int result;

    GetX509Store(self, ctx);
    /* NO DUP NEEDED. */
    X509_STORE_CTX_set_cert(ctx, GetX509CertPtr(cert));
    if ((result = X509_verify_cert(ctx)) < 0) {
	ossl_raise(eX509StoreError, "");
    }
    /*
     * TODO
     * Should we clear chain?
     X509_STORE_CTX_cleanup(ctx);
    */
    if (result == 1) {
	return Qtrue;
    }

    return Qfalse;
}

static VALUE 
ossl_x509store_get_verify_status(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);

    return INT2FIX(X509_STORE_CTX_get_error(ctx));
}

static VALUE
ossl_x509store_set_verify_status(VALUE self, VALUE err)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);
    X509_STORE_CTX_set_error(ctx, FIX2INT(err));

    return err;
}

static VALUE 
ossl_x509store_get_verify_message(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);

    return rb_str_new2(X509_verify_cert_error_string(ctx->error));
}

static VALUE 
ossl_x509store_get_verify_depth(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);

    return INT2FIX(X509_STORE_CTX_get_error_depth(ctx));
}

static VALUE 
ossl_x509store_get_cert(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);

    /*
     * TODO
     * Find out if we can free X509
     */
    return ossl_x509_new(X509_STORE_CTX_get_current_cert(ctx));
}

static VALUE 
ossl_x509store_set_default_paths(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);
    if (!X509_STORE_set_default_paths(ctx->ctx)) {
	ossl_raise(eX509StoreError, "");
    }

    return self;
}

static VALUE 
ossl_x509store_load_locations(VALUE self, VALUE path)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);
    SafeStringValue(path);
    if (!X509_STORE_load_locations(ctx->ctx, NULL,
				   RSTRING(path)->ptr)) {
	ossl_raise(eX509StoreError, "");
    }

    return self;
}

static VALUE 
ossl_x509store_set_verify_cb(VALUE self, VALUE proc)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);
    /*
     * Associate verify_cb with Store in DB
     */
    X509_STORE_CTX_set_ex_data(ctx, ossl_x509store_vcb_idx, (void *)proc);
    rb_ivar_set(self, rb_intern("@verify_callback"), proc);

    return proc;
}

static VALUE
ossl_x509store_cleanup(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509Store(self, ctx);
    X509_STORE_CTX_cleanup(ctx); 

    return self;
}

/*
 * INIT
 */
void 
Init_ossl_x509store()
{
    ossl_x509store_vcb_idx = X509_STORE_CTX_get_ex_new_index(0, "ossl_x509store_ex_vcb", NULL, NULL, NULL);
    ossl_x509store_free_idx = X509_STORE_CTX_get_ex_new_index(0, "ossl_x509store_ex_free", NULL, NULL, NULL);

    eX509StoreError = rb_define_class_under(mX509, "StoreError", eOSSLError);

    cX509Store = rb_define_class_under(mX509, "Store", rb_cObject);
	
    rb_define_alloc_func(cX509Store, ossl_x509store_alloc);
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

