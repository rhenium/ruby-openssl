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
    obj = Data_Wrap_Struct(klass, 0, ossl_x509stctx_free, ctx); \
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

X509_STORE *
DupX509StorePtr(VALUE obj)
{   
    X509_STORE *store;

    SafeGetX509Store(obj, store);
    CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
    
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
        ossl_raise(eX509StoreError, NULL);
    }
    WrapX509Store(klass, obj, store);

    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_x509store_alloc)

/*
 * General callback for OpenSSL verify
 */
static VALUE
ossl_x509store_set_vfy_cb(VALUE self, VALUE cb)
{
    X509_STORE *store;

    GetX509Store(self, store);
    X509_STORE_set_ex_data(store, ossl_verify_cb_idx, (void*)cb);
    rb_iv_set(self, "@verify_callback", cb);

    return cb;
}

static VALUE
ossl_x509store_initialize(int argc, VALUE *argv, VALUE self)
{
    X509_STORE *store;

    GetX509Store(self, store);
    X509_STORE_set_verify_cb_func(store, ossl_verify_cb);
    ossl_x509store_set_vfy_cb(self, Qnil);

    /* last verification status */
    rb_iv_set(self, "@error", Qnil);
    rb_iv_set(self, "@error_string", Qnil);
    rb_iv_set(self, "@chain", Qnil);

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
ossl_x509store_set_purpose(VALUE self, VALUE purpose)
{
    X509_STORE *store;

    GetX509Store(self, store);
    X509_STORE_set_purpose(store, NUM2LONG(purpose));

    return purpose;
}

static VALUE
ossl_x509store_set_trust(VALUE self, VALUE trust)
{
    X509_STORE *store;

    GetX509Store(self, store);
    X509_STORE_set_trust(store, NUM2LONG(trust));

    return trust;
}

static VALUE 
ossl_x509store_add_file(VALUE self, VALUE file)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;
    char *path = NULL;

    if(file != Qnil){
        Check_SafeStr(file);
	path = RSTRING(file)->ptr;
    }
    GetX509Store(self, store);
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if(lookup == NULL) ossl_raise(eX509StoreError, NULL);
    if(X509_LOOKUP_load_file(lookup, path, X509_FILETYPE_PEM) != 1){
        ossl_raise(eX509StoreError, NULL);
    }

    return self;
}

static VALUE 
ossl_x509store_add_path(VALUE self, VALUE dir)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;
    char *path = NULL;

    if(dir != Qnil){
        Check_SafeStr(dir);
	path = RSTRING(dir)->ptr;
    }
    GetX509Store(self, store);
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if(lookup == NULL) ossl_raise(eX509StoreError, NULL);
    if(X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM) != 1){
        ossl_raise(eX509StoreError, NULL);
    }

    return self;
}

static VALUE
ossl_x509store_add_cert(VALUE self, VALUE arg)
{
    X509_STORE *store;
    X509 *cert;

    cert = GetX509CertPtr(arg); /* NO NEED TO DUP */
    GetX509Store(self, store);
    X509_STORE_add_cert(store, cert);

    return self;
}

static VALUE
ossl_x509store_add_crl(VALUE self, VALUE arg)
{
    X509_STORE *store;
    X509_CRL *crl;

    crl = GetX509CRLPtr(arg); /* NO NEED TO DUP */
    GetX509Store(self, store);
    X509_STORE_add_crl(store, crl);

    return self;
}

static VALUE ossl_x509stctx_get_err(VALUE);
static VALUE ossl_x509stctx_get_err_string(VALUE);
static VALUE ossl_x509stctx_get_chain(VALUE);

static VALUE 
ossl_x509store_verify(int argc, VALUE *argv, VALUE self)
{
    VALUE cert, chain;
    VALUE ctx, proc, result;

    rb_scan_args(argc, argv, "11", &cert, &chain);
    ctx = rb_funcall(cX509StoreContext, rb_intern("new"), 3, self, cert, chain);
    proc = rb_block_given_p() ?  rb_block_proc() :
	   rb_iv_get(self, "@verify_callback");
    rb_iv_set(ctx, "@verify_callback", proc);
    result = rb_funcall(ctx, rb_intern("verify"), 0);

    rb_iv_set(self, "@error", ossl_x509stctx_get_err(ctx));
    rb_iv_set(self, "@error_string", ossl_x509stctx_get_err_string(ctx));
    rb_iv_set(self, "@chain", ossl_x509stctx_get_chain(ctx));

    return result;
}

/*
 * Public Functions
 */
static void
ossl_x509stctx_free(X509_STORE_CTX *ctx)
{
    if(ctx->untrusted)
	sk_X509_pop_free(ctx->untrusted, X509_free);
    if(ctx->cert) ctx->cert;
}

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
        ossl_raise(eX509StoreError, NULL);
    }
    WrapX509StCtx(klass, obj, ctx);

    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_x509stctx_alloc)

static VALUE
ossl_x509stctx_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE store, cert, chain;
    X509_STORE_CTX *ctx;
    X509_STORE *x509st;
    X509 *x509 = NULL;
    STACK_OF(X509) *x509s = NULL;

    GetX509StCtx(self, ctx);
    rb_scan_args(argc, argv, "12", &store, &cert, &chain);
    SafeGetX509Store(store, x509st);
    if(!NIL_P(cert)) x509 = DupX509CertPtr(cert);
    if(!NIL_P(chain)) x509s = ossl_x509_ary2sk(chain);
    if(X509_STORE_CTX_init(ctx, x509st, x509, x509s) != 1){
        sk_X509_pop_free(x509s, X509_free);
        ossl_raise(eX509StoreError, NULL);
    }
    rb_iv_set(self, "@verify_callback", rb_iv_get(store, "@verify_callback"));
    rb_iv_set(self, "@cert", cert);

    return self;
}

static VALUE
ossl_x509stctx_verify(VALUE self)
{
    X509_STORE_CTX *ctx;
    int result;

    GetX509StCtx(self, ctx);
    X509_STORE_CTX_set_ex_data(ctx, ossl_verify_cb_idx,
                               (void*)rb_iv_get(self, "@verify_callback"));
    result = X509_verify_cert(ctx);

    return result ? Qtrue : Qfalse;
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
ossl_x509stctx_get_err(VALUE self)
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
ossl_x509stctx_get_curr_crl(VALUE self)
{
    X509_STORE_CTX *ctx;

    GetX509StCtx(self, ctx);
    if(!ctx->current_crl) return Qnil;

    return ossl_x509crl_new(ctx->current_crl);
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

    eX509StoreError = rb_define_class_under(mX509, "StoreError", eOSSLError);

    cX509Store = rb_define_class_under(mX509, "Store", rb_cObject);
    rb_attr(cX509Store, rb_intern("verify_callback"), 1, 0, Qfalse);
    rb_attr(cX509Store, rb_intern("error"), 1, 0, Qfalse);
    rb_attr(cX509Store, rb_intern("error_string"), 1, 0, Qfalse);
    rb_attr(cX509Store, rb_intern("chain"), 1, 0, Qfalse);
    rb_define_alloc_func(cX509Store, ossl_x509store_alloc);
    rb_define_method(cX509Store, "initialize",   ossl_x509store_initialize, -1);
    rb_define_method(cX509Store, "verify_callback=", ossl_x509store_set_vfy_cb, 1);
    rb_define_method(cX509Store, "flags=",       ossl_x509store_set_flags, 1);
    rb_define_method(cX509Store, "purpose=",     ossl_x509store_set_purpose, 1);
    rb_define_method(cX509Store, "trust=",       ossl_x509store_set_trust, 1);
    rb_define_method(cX509Store, "add_path",     ossl_x509store_add_path, 1);
    rb_define_method(cX509Store, "add_file",     ossl_x509store_add_file, 1);
    rb_define_method(cX509Store, "add_cert",     ossl_x509store_add_cert, 1);
    rb_define_method(cX509Store, "add_crl",      ossl_x509store_add_crl, 1);
    rb_define_method(cX509Store, "verify",       ossl_x509store_verify, -1);

    cX509StoreContext = rb_define_class_under(mX509,"StoreContext",rb_cObject);
    x509stctx = cX509StoreContext;
    rb_define_alloc_func(cX509StoreContext, ossl_x509stctx_alloc);
    rb_define_method(x509stctx,"initialize",  ossl_x509stctx_initialize, -1);
    rb_define_method(x509stctx,"verify",      ossl_x509stctx_verify, 0);
    rb_define_method(x509stctx,"chain",       ossl_x509stctx_get_chain,0);
    rb_define_method(x509stctx,"error",       ossl_x509stctx_get_err, 0);
    rb_define_method(x509stctx,"error=",      ossl_x509stctx_set_error, 1);
    rb_define_method(x509stctx,"error_string",ossl_x509stctx_get_err_string,0);
    rb_define_method(x509stctx,"error_depth", ossl_x509stctx_get_err_depth, 0);
    rb_define_method(x509stctx,"current_cert",ossl_x509stctx_get_curr_cert, 0);
    rb_define_method(x509stctx,"current_crl", ossl_x509stctx_get_curr_crl, 0);
    rb_define_method(x509stctx,"cleanup",     ossl_x509stctx_cleanup, 0);

}
