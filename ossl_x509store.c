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

#define WrapX509Store(klass, obj, st) do { \
    if (!st) { \
	ossl_raise(rb_eRuntimeError, "STORE wasn't initialized!"); \
    } \
    obj = Data_Wrap_Struct(klass, 0, X509_STORE_free, st); \
} while (0)
#define GetX509Store(obj, st) do { \
    Data_Get_Struct(obj, X509_STORE, st); \
    if (!st) { \
	ossl_raise(rb_eRuntimeError, "STORE wasn't initialized!"); \
    } \
} while (0)
#define SafeGetX509Store(obj, st) do { \
    OSSL_Check_Kind(obj, cX509Store); \
    GetX509Store(obj, st); \
} while (0)

#define WrapX509StCtx(klass, obj, ctx) do { \
    if (!ctx) { \
	ossl_raise(rb_eRuntimeError, "STORE_CTX wasn't initialized!"); \
    } \
    obj = Data_Wrap_Struct(klass, 0, X509_STORE_CTX_free, ctx); \
} while (0)
#define GetX509StCtx(obj, ctx) do { \
    Data_Get_Struct(obj, X509_STORE_CTX, ctx); \
    if (!ctx) { \
	ossl_raise(rb_eRuntimeError, "STORE_CTX is out of scope!"); \
    } \
} while (0)
#define SafeGetX509StCtx(obj, storep) do { \
    OSSL_Check_Kind(obj, cX509StoreContext); \
    GetX509Store(obj, ctx); \
} while (0)

/*
 * Classes
 */
VALUE cX509Store;
VALUE cX509StoreContext;
VALUE eX509StoreError;

/*
 * Public functions
 */
VALUE 
ossl_x509store_new(X509_STORE *store)
{
    VALUE obj;

    WrapX509Store(cX509Store, obj, store);

    return obj;
}

X509_STORE *
GetX509StorePtr(VALUE obj)
{
    X509_STORE *store;

    SafeGetX509Store(obj, store);

    return store;
}

/*
 * Private functions
 */
static VALUE 
ossl_x509store_alloc(VALUE klass)
{
    X509_STORE *store;
    VALUE obj;

    if((store = X509_STORE_new()) == NULL){
        ossl_raise(eX509StoreError, "");
    }
    WrapX509Store(klass, obj, store);

    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_x509store_alloc)

/*
 * General callback for OpenSSL verify
 */
int ossl_x509store_verify_cb(int, X509_STORE_CTX *);

static VALUE
ossl_x509store_initialize(int argc, VALUE *argv, VALUE self)
{
    X509_STORE *store;

    GetX509Store(self, store);
    X509_STORE_set_verify_cb_func(store, ossl_x509store_verify_cb);
    rb_ivar_set(self, rb_intern("@verify_callback"), Qnil);

    return self;
}

static VALUE
ossl_x509store_set_flags(VALUE self, VALUE flags)
{
    X509_STORE *store;

    GetX509Store(self, store);
    X509_STORE_set_flags(store, NUM2LONG(flags));

    return flags;
}

static VALUE 
ossl_x509store_add_file(VALUE self, VALUE file)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    Check_SafeStr(file);
    GetX509Store(self, store);
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if(lookup == NULL){
        ossl_raise(eX509StoreError, "");
    }
    if(X509_LOOKUP_load_file(lookup, RSTRING(file)->ptr,X509_FILETYPE_PEM) != 1){
        ossl_raise(eX509StoreError, "");
    }

    return self;
}

static VALUE 
ossl_x509store_add_path(VALUE self, VALUE path)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    Check_SafeStr(path);
    GetX509Store(self, store);
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if(lookup == NULL){
        ossl_raise(eX509StoreError, "");
    }
    if(X509_LOOKUP_add_dir(lookup, RSTRING(path)->ptr,X509_FILETYPE_PEM) != 1){
        ossl_raise(eX509StoreError, "");
    }

    return self;
}

static VALUE
ossl_x509store_add_crl_file(VALUE self, VALUE file)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    Check_SafeStr(file);
    GetX509Store(self, store);
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if(lookup == NULL){
        ossl_raise(eX509StoreError, "");
    }
    if(X509_load_crl_file(lookup, RSTRING(file)->ptr,X509_FILETYPE_PEM) != 1){
        ossl_raise(eX509StoreError, "");
    }

    return self;
}

static VALUE
ossl_x509store_add_cert(VALUE self, VALUE arg)
{
    X509_STORE *store;
    X509 *cert;

    cert = DupX509CertPtr(arg);
    GetX509Store(self, store);
    X509_STORE_add_cert(store, cert);

    return self;
}

static VALUE
ossl_x509store_add_crl(VALUE self, VALUE arg)
{
    X509_STORE *store;
    X509_CRL *crl;

    crl = DupX509CRLPtr(arg);
    GetX509Store(self, store);
    X509_STORE_add_crl(store, crl);

    return self;
}

static int ossl_x509store_vcb_idx;

static VALUE 
ossl_x509store_call_verify_cb_proc(VALUE args)
{
    VALUE proc, ok, store_ctx;

    proc = rb_ary_entry(args, 0);
    ok = rb_ary_entry(args, 1);
    store_ctx = rb_ary_entry(args, 2);

    return rb_funcall(proc, rb_intern("call"), 2, ok, store_ctx);
}

static VALUE
ossl_x509store_verify_false(VALUE dummy)
{
    return Qfalse;
}

int
ossl_x509store_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    VALUE proc, rctx, args, ret = Qnil;

    proc = (VALUE)X509_STORE_CTX_get_ex_data(ctx, ossl_x509store_vcb_idx);
    if (!NIL_P(proc)) {
        rctx = ossl_x509stctx_new(ctx);
	args = rb_ary_new2(3);
	rb_ary_store(args, 0, proc);
	rb_ary_store(args, 1, ok ? Qtrue : Qfalse);
	rb_ary_store(args, 2, rctx);
	ret = rb_rescue(ossl_x509store_call_verify_cb_proc, args,
			ossl_x509store_verify_false, Qnil);
        ossl_x509stctx_clear_ptr(rctx);
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
ossl_x509store_verify(VALUE self, VALUE arg)
{
    int result;
    X509_STORE_CTX *ctx;
    X509_STORE *store;
    X509 *cert;

    GetX509Store(self, store);
    cert = GetX509CertPtr(arg);
    if((ctx = X509_STORE_CTX_new()) == NULL){
        ossl_raise(eX509StoreError, "");
    }
    if(X509_STORE_CTX_init(ctx, store, cert, NULL) != 1){
        X509_STORE_CTX_free(ctx);
        ossl_raise(eX509StoreError, "");
    }
    X509_STORE_CTX_set_ex_data(ctx, ossl_x509store_vcb_idx,
                               (void*)rb_iv_get(self, "@verify_callback"));
    result = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);

    return result ? Qtrue : Qfalse;
}

/*
 * Public Functions
 */
VALUE
ossl_x509stctx_new(X509_STORE_CTX *ctx)
{
    VALUE obj;

    WrapX509StCtx(cX509StoreContext, obj, ctx);

    return obj;
}

VALUE
ossl_x509stctx_clear_ptr(VALUE obj)
{
    X509_STORE_CTX *ctx;

    OSSL_Check_Kind(obj, cX509StoreContext);
    RDATA(obj)->data = NULL;

    return obj;
}

/*
 * Private functions
 */
static VALUE 
ossl_x509stctx_alloc(VALUE klass)
{
    X509_STORE_CTX *ctx;
    VALUE obj;

    if((ctx = X509_STORE_CTX_new()) == NULL){
        ossl_raise(eX509StoreError, "");
    }
    WrapX509StCtx(klass, obj, ctx);

    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_x509stctx_alloc)

static VALUE
ossl_x509stctx_initialize(int argc, VALUE *argv, VALUE self)
{
    return self;
}

static VALUE
ossl_x509stctx_get_chain(VALUE self)
{
    X509_STORE_CTX *ctx;
    STACK_OF(X509) *chain;
    X509 *x509;
    int i, num;
    VALUE ary;

    GetX509StCtx(self, ctx);
    if((chain = X509_STORE_CTX_get_chain(ctx)) == NULL){
        return Qnil;
    }
    if((num = sk_X509_num(chain)) < 0){
	OSSL_Debug("certs in chain < 0???");
	return rb_ary_new();
    }
    ary = rb_ary_new2(num);
    for(i = 0; i < num; i++) {
	x509 = sk_X509_value(chain, i);
	rb_ary_push(ary, ossl_x509_new(x509));
    }

    return ary;
}

static VALUE 
ossl_x509stctx_get_error(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509StCtx(self, ctx);

    return INT2FIX(X509_STORE_CTX_get_error(ctx));
}

static VALUE
ossl_x509stctx_set_error(VALUE self, VALUE err)
{
    X509_STORE_CTX *ctx;

    GetX509StCtx(self, ctx);
    X509_STORE_CTX_set_error(ctx, FIX2INT(err));

    return err;
}

static VALUE 
ossl_x509stctx_get_err_string(VALUE self)
{
    X509_STORE_CTX *ctx;
    long err;

    GetX509StCtx(self, ctx);
    err = X509_STORE_CTX_get_error(ctx);

    return rb_str_new2(X509_verify_cert_error_string(err));
}

static VALUE 
ossl_x509stctx_get_err_depth(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509StCtx(self, ctx);

    return INT2FIX(X509_STORE_CTX_get_error_depth(ctx));
}

static VALUE 
ossl_x509stctx_get_curr_cert(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509StCtx(self, ctx);

    return ossl_x509_new(X509_STORE_CTX_get_current_cert(ctx));
}

static VALUE
ossl_x509stctx_cleanup(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509StCtx(self, ctx);
    X509_STORE_CTX_cleanup(ctx);

    return self;
}

/*
 * INIT
 */
void 
Init_ossl_x509store()
{
    VALUE x509stctx;
    VALUE mX509VErr;
    VALUE mX509VFlag;

    eX509StoreError = rb_define_class_under(mX509, "StoreError", eOSSLError);

    ossl_x509store_vcb_idx =
      X509_STORE_CTX_get_ex_new_index(0,"ossl_x509store_ex_vcb",NULL,NULL,NULL);

    cX509Store = rb_define_class_under(mX509, "Store", rb_cObject);
    rb_attr(cX509Store, rb_intern("verify_callback"), 1, 1, Qfalse);
    rb_define_alloc_func(cX509Store, ossl_x509store_alloc);
    rb_define_method(cX509Store, "initialize",   ossl_x509store_initialize, -1);
    rb_define_method(cX509Store, "flags=",       ossl_x509store_set_flags, 1);
    rb_define_method(cX509Store, "add_path",     ossl_x509store_add_path, 1);
    rb_define_method(cX509Store, "add_file",     ossl_x509store_add_file, 1);
    rb_define_method(cX509Store, "add_crl_file", ossl_x509store_add_crl_file, 1);
    rb_define_method(cX509Store, "add_cert",     ossl_x509store_add_cert, 1);
    rb_define_method(cX509Store, "add_crl",      ossl_x509store_add_crl, 1);
    rb_define_method(cX509Store, "verify",       ossl_x509store_verify, 1);

    cX509StoreContext = rb_define_class_under(mX509,"StoreContext",rb_cObject);
    x509stctx = cX509StoreContext;
    rb_define_alloc_func(cX509StoreContext, ossl_x509stctx_alloc);
    rb_define_method(x509stctx,"initialize",  ossl_x509stctx_initialize, -1);
    rb_define_method(x509stctx,"chain",       ossl_x509stctx_get_chain,0);
    rb_define_method(x509stctx,"error",       ossl_x509stctx_get_error, 0);
    rb_define_method(x509stctx,"error=",      ossl_x509stctx_set_error, 1);
    rb_define_method(x509stctx,"error_string",ossl_x509stctx_get_err_string,0);
    rb_define_method(x509stctx,"error_depth", ossl_x509stctx_get_err_depth, 0);
    rb_define_method(x509stctx,"current_cert",ossl_x509stctx_get_curr_cert, 0);
    rb_define_method(x509stctx,"cleanup",     ossl_x509stctx_cleanup, 0);
	
#define DefX509StoreVError(x) \
rb_define_const(mX509VErr, #x, INT2FIX(X509_V_ERR_##x))

    mX509VErr = rb_define_module_under(cX509Store, "V_ERR");
    DefX509StoreVError(UNABLE_TO_GET_ISSUER_CERT);
    DefX509StoreVError(UNABLE_TO_GET_CRL);
    DefX509StoreVError(UNABLE_TO_DECRYPT_CERT_SIGNATURE);
    DefX509StoreVError(UNABLE_TO_DECRYPT_CRL_SIGNATURE);
    DefX509StoreVError(UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
    DefX509StoreVError(CERT_SIGNATURE_FAILURE);
    DefX509StoreVError(CRL_SIGNATURE_FAILURE);
    DefX509StoreVError(CERT_NOT_YET_VALID);
    DefX509StoreVError(CERT_HAS_EXPIRED);
    DefX509StoreVError(CRL_NOT_YET_VALID);
    DefX509StoreVError(CRL_HAS_EXPIRED);
    DefX509StoreVError(ERROR_IN_CERT_NOT_BEFORE_FIELD);
    DefX509StoreVError(ERROR_IN_CERT_NOT_AFTER_FIELD);
    DefX509StoreVError(ERROR_IN_CRL_LAST_UPDATE_FIELD);
    DefX509StoreVError(ERROR_IN_CRL_NEXT_UPDATE_FIELD);
    DefX509StoreVError(OUT_OF_MEM);
    DefX509StoreVError(DEPTH_ZERO_SELF_SIGNED_CERT);
    DefX509StoreVError(SELF_SIGNED_CERT_IN_CHAIN);
    DefX509StoreVError(UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    DefX509StoreVError(UNABLE_TO_VERIFY_LEAF_SIGNATURE);
    DefX509StoreVError(CERT_CHAIN_TOO_LONG);
    DefX509StoreVError(CERT_REVOKED);
    DefX509StoreVError(INVALID_CA);
    DefX509StoreVError(PATH_LENGTH_EXCEEDED);
    DefX509StoreVError(INVALID_PURPOSE);
    DefX509StoreVError(CERT_UNTRUSTED);
    DefX509StoreVError(CERT_REJECTED);
    DefX509StoreVError(SUBJECT_ISSUER_MISMATCH);
    DefX509StoreVError(AKID_SKID_MISMATCH);
    DefX509StoreVError(AKID_ISSUER_SERIAL_MISMATCH);
    DefX509StoreVError(KEYUSAGE_NO_CERTSIGN);
    DefX509StoreVError(APPLICATION_VERIFICATION);

#define DefX509StoreVFlag(x) \
rb_define_const(mX509VFlag, #x, INT2FIX(X509_V_FLAG_##x))

    mX509VFlag = rb_define_module_under(mX509, "V_FLAG");
    DefX509StoreVFlag(CRL_CHECK);
    DefX509StoreVFlag(CRL_CHECK_ALL);

}
