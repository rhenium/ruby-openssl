/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2000-2002  GOTOU Yuuzou <gotoyuzo@notwork.org>
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"
#include <rubysig.h>
#include <rubyio.h>

#if defined(HAVE_UNISTD_H)
#  include <unistd.h> /* for read(), and write() */
#endif

#define numberof(ary) (sizeof(ary)/sizeof(ary[0]))

VALUE mSSL;
VALUE eSSLError;
VALUE cSSLContext;
VALUE cSSLSocket;

/*
 * SSLContext class
 */
#define ossl_sslctx_set_method(o,v)      rb_iv_set((o),"@ssl_method",(v))
#define ossl_sslctx_set_cert(o,v)        rb_iv_set((o),"@cert",(v))
#define ossl_sslctx_set_cert_file(o,v)   rb_iv_set((o),"@cert_file",(v))
#define ossl_sslctx_set_key(o,v)         rb_iv_set((o),"@key",(v))
#define ossl_sslctx_set_key_file(o,v)    rb_iv_set((o),"@key_file",(v))
#define ossl_sslctx_set_ca(o,v)          rb_iv_set((o),"@ca_cert",(v))
#define ossl_sslctx_set_ca_file(o,v)     rb_iv_set((o),"@ca_file",(v))
#define ossl_sslctx_set_ca_path(o,v)     rb_iv_set((o),"@ca_path",(v))
#define ossl_sslctx_set_timeout(o,v)     rb_iv_set((o),"@timeout",(v))
#define ossl_sslctx_set_verify_mode(o,v) rb_iv_set((o),"@verify_mode",(v))
#define ossl_sslctx_set_verify_dep(o,v)  rb_iv_set((o),"@verify_depth",(v))
#define ossl_sslctx_set_verify_cb(o,v)   rb_iv_set((o),"@verify_callback",(v))

#define ossl_sslctx_get_method(o,v)      rb_iv_get((o),"@ssl_method",(v))
#define ossl_sslctx_get_cert(o)          rb_iv_get((o),"@cert")
#define ossl_sslctx_get_cert_file(o)     rb_iv_get((o),"@cert_file")
#define ossl_sslctx_get_key(o)           rb_iv_get((o),"@key")
#define ossl_sslctx_get_key_file(o)      rb_iv_get((o),"@key_file")
#define ossl_sslctx_get_ca(o)            rb_iv_get((o),"@ca_cert")
#define ossl_sslctx_get_ca_file(o)       rb_iv_get((o),"@ca_file")
#define ossl_sslctx_get_ca_path(o)       rb_iv_get((o),"@ca_path")
#define ossl_sslctx_get_timeout(o)       rb_iv_get((o),"@timeout")
#define ossl_sslctx_get_verify_mode(o)   rb_iv_get((o),"@verify_mode")
#define ossl_sslctx_get_verify_dep(o)    rb_iv_get((o),"@verify_depth")
#define ossl_sslctx_get_verify_cb(o)     rb_iv_get((o),"@verify_callback")

static VALUE ossl_sslctx_set_cert2(VALUE, VALUE);
static VALUE ossl_sslctx_set_cert_file2(VALUE, VALUE);
static VALUE ossl_sslctx_set_key2(VALUE, VALUE);
static VALUE ossl_sslctx_set_key_file2(VALUE, VALUE);

typedef struct ossl_sslctx_st_t{
    SSL_METHOD *method;
    SSL_CTX *ctx;
} ossl_sslctx_st;

static char *ossl_sslctx_attrs[] = {
    "cert", "cert_file", "key", "key_file", "ca_cert", "ca_file", "ca_path",
    "timeout", "verify_mode", "verify_depth", "verify_callback", "ssl_method",
}; 

#define OSSL_SSL_METHOD_ENTRY(name) { #name, name##_method }

struct {
    const char *name;
    SSL_METHOD *(*f)(void);
} ossl_ssl_method_tab[] = {
    OSSL_SSL_METHOD_ENTRY(TLSv1),
    OSSL_SSL_METHOD_ENTRY(TLSv1_server),
    OSSL_SSL_METHOD_ENTRY(TLSv1_client),
    OSSL_SSL_METHOD_ENTRY(SSLv2),
    OSSL_SSL_METHOD_ENTRY(SSLv2_server),
    OSSL_SSL_METHOD_ENTRY(SSLv2_client),
    OSSL_SSL_METHOD_ENTRY(SSLv3),
    OSSL_SSL_METHOD_ENTRY(SSLv3_server),
    OSSL_SSL_METHOD_ENTRY(SSLv3_client),
    OSSL_SSL_METHOD_ENTRY(SSLv23),
    OSSL_SSL_METHOD_ENTRY(SSLv23_server),
    OSSL_SSL_METHOD_ENTRY(SSLv23_client),
};

static void
ossl_sslctx_free(ossl_sslctx_st *p)
{
    SSL_CTX_free(p->ctx);
    p->ctx = NULL;
}

static VALUE
ossl_sslctx_s_alloc(VALUE klass)
{
    ossl_sslctx_st *p;
    return Data_Make_Struct(klass, ossl_sslctx_st, 0, ossl_sslctx_free, p);
}

static VALUE
ossl_sslctx_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE ssl_method;
    ossl_sslctx_st *p;
    int i;
    char *s;

    rb_scan_args(argc, argv, "01", &ssl_method);
    Data_Get_Struct(self, ossl_sslctx_st, p);
    s = NIL_P(ssl_method) ? "SSLv23" : StringValuePtr(ssl_method);
    for(i = 0; i < numberof(ossl_ssl_method_tab); i++){
        if(strcmp(ossl_ssl_method_tab[i].name, s) == 0){
            p->method = ossl_ssl_method_tab[i].f();
            ossl_sslctx_set_method(self, ssl_method);
            break;
        }
    }
    if(p->method == NULL)
        rb_raise(rb_eArgError, "unknown SSL method `%s'.", s);

    return self;
}

static int ossl_ssl_ex_vcb_idx;

static VALUE
ossl_ssl_call_verify_cb(VALUE args)
{
    VALUE cb, ok, store;

    cb = rb_ary_shift(args);
    ok = rb_ary_shift(args);
    store = rb_ary_shift(args);
    return rb_funcall(cb, rb_intern("call"), 2, ok, store);
}

static VALUE
ossl_ssl_verify_failure(VALUE dummy)
{
    char *msg;

    msg = StringValuePtr(ruby_errinfo);
    rb_warn("verify callback error: %s", msg);

    return Qfalse;
}

static int
ossl_ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    int verify_ok = preverify_ok;
    VALUE args, cb, result;
    SSL *ssl;

    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    cb = SSL_get_ex_data(ssl, ossl_ssl_ex_vcb_idx);
    if(!NIL_P(cb)){
        args = rb_ary_new2(3);
        rb_ary_push(args, cb);
        rb_ary_push(args, preverify_ok ? Qtrue : Qfalse);
        rb_ary_push(args, ossl_x509store_new(ctx));
	result = rb_rescue(ossl_ssl_call_verify_cb, args,
                           ossl_ssl_verify_failure, Qnil);
        if(result == Qtrue){
            X509_STORE_CTX_set_error(ctx, X509_V_OK);
            verify_ok = 1;
        }
        else{
            if(X509_STORE_CTX_get_error(ctx) == X509_V_OK)
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
            verify_ok = 0;
        }
    }
    
    return verify_ok;
}

static VALUE
ossl_sslctx_setup(VALUE self)
{
    ossl_sslctx_st *p = NULL;
    X509 *cert = NULL, *ca = NULL;
    EVP_PKEY *key = NULL;
    char *ca_path = NULL, *ca_file = NULL;
    int verify_mode;
    VALUE val;

    Data_Get_Struct(self, ossl_sslctx_st, p);
    if(p->ctx) return Qfalse;

    if((p->ctx = SSL_CTX_new(p->method)) == NULL)
        ossl_raise(eSSLError, "SSL_CTX_new:");
    SSL_CTX_set_options(p->ctx, SSL_OP_ALL);

    /* private key may be bundled in certificate file. */
    val = ossl_sslctx_get_cert(self);
    cert = NIL_P(val) ? NULL : GetX509CertPtr(val); /* NO DUP NEEDED */
    val = ossl_sslctx_get_key(self);
    key = NIL_P(val) ? NULL : GetPKeyPtr(val); /* NO NEED TO DUP */

    if (cert && key) {
        if (!SSL_CTX_use_certificate(p->ctx, cert)) {
            /* Adds a ref => Safe to FREE */
            ossl_raise(eSSLError, "SSL_CTX_use_certificate:");
        }
        if (!SSL_CTX_use_PrivateKey(p->ctx, key)) {
            /* Adds a ref => Safe to FREE */
            ossl_raise(eSSLError, "SSL_CTX_use_PrivateKey:");
        }
        if (!SSL_CTX_check_private_key(p->ctx)) {
            ossl_raise(eSSLError, "SSL_CTX_check_private_key:");
        }
    }

    val = ossl_sslctx_get_ca(self);
    ca = NIL_P(val) ? NULL : GetX509CertPtr(val); /* NO DUP NEEDED. */
    val = ossl_sslctx_get_ca_file(self);
    ca_file = NIL_P(val) ? NULL : StringValuePtr(val);
    val = ossl_sslctx_get_ca_path(self);
    ca_path = NIL_P(val) ? NULL : StringValuePtr(val);

    if (ca){
        if (!SSL_CTX_add_client_CA(p->ctx, ca)){
            /* Copies X509_NAME => FREE it. */
            ossl_raise(eSSLError, "SSL_CTX_add_client_CA");
        }
    }
    if ((!SSL_CTX_load_verify_locations(p->ctx, ca_file, ca_path) ||
         !SSL_CTX_set_default_verify_paths(p->ctx))) {
        rb_warning("can't set verify locations");
    }

    val = ossl_sslctx_get_verify_mode(self);
    verify_mode = NIL_P(val) ? SSL_VERIFY_NONE : NUM2INT(val);
    SSL_CTX_set_verify(p->ctx, verify_mode, ossl_ssl_verify_callback);

    val = ossl_sslctx_get_timeout(self);
    if(!NIL_P(val)) SSL_CTX_set_timeout(p->ctx, NUM2LONG(val));

    val = ossl_sslctx_get_verify_dep(self);
    if(!NIL_P(val)) SSL_CTX_set_verify_depth(p->ctx, NUM2LONG(val));

    return Qtrue;
}

static VALUE
ossl_ssl_cipher_to_ary(SSL_CIPHER *cipher)
{
    VALUE ary;
    int bits, alg_bits;

    ary = rb_ary_new2(4);
    rb_ary_push(ary, rb_str_new2(SSL_CIPHER_get_name(cipher)));
    rb_ary_push(ary, rb_str_new2(SSL_CIPHER_get_version(cipher)));
    bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
    rb_ary_push(ary, INT2FIX(bits));
    rb_ary_push(ary, INT2FIX(alg_bits));

    return ary;
}

static VALUE
ossl_sslctx_get_ciphers(VALUE self)
{
    ossl_sslctx_st *p;
    STACK_OF(SSL_CIPHER) *ciphers;
    SSL_CIPHER *cipher;
    VALUE ary;
    int i, num;

    Data_Get_Struct(self, ossl_sslctx_st, p);
    if(!p->ctx){
        rb_warning("SSL_CTX is not initialized.");
        return Qnil;
    }
    ciphers = p->ctx->cipher_list;

    if (!ciphers)
        return rb_ary_new();

    num = sk_num((STACK*)ciphers);
    ary = rb_ary_new2(num);
    for(i = 0; i < num; i++){
        cipher = (SSL_CIPHER*)sk_value((STACK*)ciphers, i);
        rb_ary_push(ary, ossl_ssl_cipher_to_ary(cipher));
    }
    return ary;
}

static VALUE
ossl_sslctx_set_ciphers(VALUE self, VALUE v)
{
    ossl_sslctx_st *p;
    VALUE str, elem;
    int i;

    Data_Get_Struct(self, ossl_sslctx_st, p);
    if(!p->ctx){
        ossl_raise(eSSLError, "SSL_CTX is not initialized.");
        return Qnil;
    }

    if (TYPE(v) == T_ARRAY) {
        str = rb_str_new2("");
        for (i = 0; i < RARRAY(v)->len; i++) {
            elem = rb_ary_entry(v, i);
            if (TYPE(elem) == T_ARRAY) elem = rb_ary_entry(elem, 0);
            elem = rb_String(elem);
            rb_str_append(str, elem);
            if (i < RARRAY(v)->len-1) rb_str_cat2(str, ":");
        }
    } else {
        str = v;
        StringValue(str);
    }

    if (!SSL_CTX_set_cipher_list(p->ctx, RSTRING(str)->ptr)) {
        ossl_raise(eSSLError, "SSL_CTX_set_ciphers:");
    }
    return Qnil;
}

static VALUE
ossl_sslctx_set_cert2(VALUE self, VALUE v)
{
    if(!NIL_P(v)) OSSL_Check_Kind(v, cX509Cert);
    ossl_sslctx_set_cert(self, v);
    ossl_sslctx_set_cert_file(self, Qnil);
    return v;
}

static VALUE
ossl_sslctx_set_cert_file2(VALUE self, VALUE v)
{
    VALUE cert;
    cert = NIL_P(v) ? Qnil : ossl_x509_new_from_file(v);
    ossl_sslctx_set_cert(self, cert);
    ossl_sslctx_set_cert_file(self, v);
    return v;
}

static VALUE
ossl_sslctx_set_key2(VALUE self, VALUE v)
{
    if(!NIL_P(v)) OSSL_Check_Kind(v, cPKey);
    ossl_sslctx_set_key(self, v);
    ossl_sslctx_set_key_file(self, Qnil);
    return v;
}

static VALUE
ossl_sslctx_set_key_file2(VALUE self, VALUE v)
{
    VALUE key;
    key = NIL_P(v) ? Qnil : ossl_pkey_new_from_file(v);
    ossl_sslctx_set_key(self, key);
    ossl_sslctx_set_key_file(self, v);
    return v;
}

/*
 * SSLSocket class
 */
#define ossl_ssl_get_io(o)    rb_iv_get((o),"@io")
#define ossl_ssl_get_ctx(o)   rb_iv_get((o),"@context")

#define ossl_ssl_set_io(o,v)  rb_iv_set((o),"@io",(v))
#define ossl_ssl_set_ctx(o,v) rb_iv_set((o),"@context",(v))

typedef struct ossl_ssl_st_t{
    SSL *ssl;
} ossl_ssl_st;

static char *ossl_ssl_attrs[] = { "io" };

static void
ossl_ssl_shutdown(ossl_ssl_st *p)
{
    if(p->ssl){
        SSL_shutdown(p->ssl);
        SSL_clear(p->ssl);
    }
}

static void
ossl_ssl_free(ossl_ssl_st *p)
{
    ossl_ssl_shutdown(p);
    SSL_free(p->ssl);
    p->ssl = NULL;
    free(p);
}

static VALUE
ossl_ssl_s_alloc(VALUE klass)
{
    ossl_ssl_st *p;
    return Data_Make_Struct(klass, ossl_ssl_st, 0, ossl_ssl_free, p);
}

static VALUE
ossl_ssl_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE io, ctx;

    if(rb_scan_args(argc, argv, "11", &io, &ctx) == 1)
        ctx = rb_funcall(cSSLContext, rb_intern("new"), 0);
    OSSL_Check_Kind(ctx, cSSLContext);
    ossl_ssl_set_io(self, io);
    ossl_ssl_set_ctx(self, ctx);
    ossl_sslctx_setup(ctx);

    return self;
}

static VALUE
ossl_ssl_setup(VALUE self)
{
    ossl_ssl_st *p;
    VALUE io, ctx;
    ossl_sslctx_st *ctx_p;
    OpenFile *fptr;

    Data_Get_Struct(self, ossl_ssl_st, p);
    if(!p->ssl){
        ctx = ossl_ssl_get_ctx(self);
        Data_Get_Struct(ctx, ossl_sslctx_st, ctx_p);
        if((p->ssl = SSL_new(ctx_p->ctx)) == NULL)
            ossl_raise(eSSLError, "SSL_new:");

        io = ossl_ssl_get_io(self);
        GetOpenFile(io, fptr);
        rb_io_check_readable(fptr);
        rb_io_check_writable(fptr);
        SSL_set_fd(p->ssl, fileno(fptr->f));
    }

    return Qtrue;
}

static VALUE
ossl_ssl_connect(VALUE self)
{
    ossl_ssl_st *p;
    VALUE cb;

    ossl_ssl_setup(self);
    Data_Get_Struct(self, ossl_ssl_st, p);
    cb = ossl_sslctx_get_verify_cb(ossl_ssl_get_ctx(self));
    SSL_set_ex_data(p->ssl, ossl_ssl_ex_vcb_idx, cb);
    if(SSL_connect(p->ssl) <= 0)
        ossl_raise(eSSLError, "SSL_connect:");

    return self;
}

static VALUE
ossl_ssl_accept(VALUE self)
{
    ossl_ssl_st *p;
    VALUE cb;

    ossl_ssl_setup(self);
    Data_Get_Struct(self, ossl_ssl_st, p);
    cb = ossl_sslctx_get_verify_cb(ossl_ssl_get_ctx(self));
    SSL_set_ex_data(p->ssl, ossl_ssl_ex_vcb_idx, cb);
    if(SSL_accept(p->ssl) <= 0)
        ossl_raise(eSSLError, "SSL_accept:");

    return self;
}

static VALUE
ossl_ssl_read(VALUE self, VALUE len)
{
    ossl_ssl_st *p;
    size_t ilen, nread = 0;
    VALUE str;
    OpenFile *fptr;

    Data_Get_Struct(self, ossl_ssl_st, p);
    ilen = NUM2INT(len);
    str = rb_str_new(0, ilen);

    if (p->ssl) {
        nread = SSL_read(p->ssl, RSTRING(str)->ptr, RSTRING(str)->len);
        if(nread < 0)
            ossl_raise(eSSLError, "SSL_read:");
    }
    else {
        if(ruby_verbose) rb_warning("SSL session is not started yet.");
        GetOpenFile(ossl_ssl_get_io(self), fptr);
        rb_io_check_readable(fptr);
        TRAP_BEG;
        nread = read(fileno(fptr->f), RSTRING(str)->ptr, RSTRING(str)->len);
        TRAP_END;
        if(nread < 0)
            ossl_raise(eSSLError, "read:%s", strerror(errno));
    }

    if(nread == 0)
        ossl_raise(rb_eEOFError, "End of file reached");

    RSTRING(str)->len = nread;
    RSTRING(str)->ptr[nread] = 0;
    OBJ_TAINT(str);

    return str;
}

static VALUE
ossl_ssl_write(VALUE self, VALUE str)
{
    ossl_ssl_st *p;
    size_t nwrite = 0;
    OpenFile *fptr;
    FILE *fp;

    Data_Get_Struct(self, ossl_ssl_st, p);
    StringValue(str);

    if (p->ssl) {
        nwrite = SSL_write(p->ssl, RSTRING(str)->ptr, RSTRING(str)->len);
        if (nwrite <= 0)
            ossl_raise(eSSLError, "SSL_write:");
    }
    else {
        if(ruby_verbose) rb_warning("SSL session is not started yet.");
        GetOpenFile(ossl_ssl_get_io(self), fptr);
        rb_io_check_writable(fptr);
        fp = GetWriteFile(fptr);
        nwrite = write(fileno(fp), RSTRING(str)->ptr, RSTRING(str)->len);
        if(nwrite < 0)
            ossl_raise(eSSLError, "write:%s", strerror(errno));
    }

    return INT2NUM(nwrite);
}

static VALUE
ossl_ssl_close(VALUE self)
{
    ossl_ssl_st *p;

    Data_Get_Struct(self, ossl_ssl_st, p);
    ossl_ssl_shutdown(p);
    return Qnil;
}

static VALUE
ossl_ssl_get_cert(VALUE self)
{
    ossl_ssl_st *p;
    X509 *cert = NULL;

    Data_Get_Struct(self, ossl_ssl_st, p);
    if(!p->ssl){
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }

    /*
     * Is this OpenSSL bug? Should add a ref?
     * TODO: Ask for.
     */
    if ((cert = SSL_get_certificate(p->ssl)) == NULL){
        /* NO DUPs => DON'T FREE. */
        return Qnil;
    }

    return ossl_x509_new(cert);
}

static VALUE
ossl_ssl_get_peer_cert(VALUE self)
{
    ossl_ssl_st *p;
    X509 *cert = NULL;
    VALUE obj;

    Data_Get_Struct(self, ossl_ssl_st, p);

    if (!p->ssl){
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }

    if ((cert = SSL_get_peer_certificate(p->ssl)) == NULL){
        /* Adds a ref => Safe to FREE. */
        return Qnil;
    }

    obj = ossl_x509_new(cert);
    X509_free(cert);

    return obj;
}

static VALUE
ossl_ssl_get_cipher(VALUE self)
{
    ossl_ssl_st *p;
    SSL_CIPHER *cipher;

    Data_Get_Struct(self, ossl_ssl_st, p);
    if(!p->ssl){
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }
    cipher = SSL_get_current_cipher(p->ssl);

    return ossl_ssl_cipher_to_ary(cipher);
}

static VALUE
ossl_ssl_get_state(VALUE self)
{
    ossl_ssl_st *p;
    VALUE ret;

    Data_Get_Struct(self, ossl_ssl_st, p);
    if(!p->ssl){
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }
    ret = rb_str_new2(SSL_state_string(p->ssl));
    if(ruby_verbose){
        rb_str_cat2(ret, ": ");
        rb_str_cat2(ret, SSL_state_string_long(p->ssl));
    }
    return ret;
}

void
Init_ossl_ssl()
{
    int i;

    ossl_ssl_ex_vcb_idx =
        SSL_get_ex_new_index(0, "ossl_ssl_ex_vcb_idx", NULL, NULL, NULL);

    mSSL = rb_define_module_under(mOSSL, "SSL");
    eSSLError = rb_define_class_under(mSSL, "SSLError", eOSSLError);

    /* class SSLContext */
    cSSLContext = rb_define_class_under(mSSL, "SSLContext", rb_cObject);
    rb_define_singleton_method(cSSLContext, "allocate", ossl_sslctx_s_alloc, 0);
    for(i = 0; i < numberof(ossl_sslctx_attrs); i++)
        rb_attr(cSSLContext, rb_intern(ossl_sslctx_attrs[i]), 1, 1, Qfalse);
    rb_define_method(cSSLContext, "initialize",  ossl_sslctx_initialize, -1);
    rb_define_method(cSSLContext, "ciphers",     ossl_sslctx_get_ciphers, 0);
    rb_define_method(cSSLContext, "ciphers=",    ossl_sslctx_set_ciphers, 1);
    rb_define_method(cSSLContext, "cert=",       ossl_sslctx_set_cert2, 1);
    rb_define_method(cSSLContext, "cert_file=",  ossl_sslctx_set_cert_file2, 1);
    rb_define_method(cSSLContext, "key=",        ossl_sslctx_set_key2, 1);
    rb_define_method(cSSLContext, "key_file=",   ossl_sslctx_set_key_file2, 1);
    rb_define_method(cSSLContext, "setup",       ossl_sslctx_setup, 0);

    /* class SSLSocket */
    cSSLSocket = rb_define_class_under(mSSL, "SSLSocket", rb_cObject);
    rb_define_singleton_method(cSSLSocket, "allocate", ossl_ssl_s_alloc, 0);
    for(i = 0; i < numberof(ossl_ssl_attrs); i++)
        rb_attr(cSSLSocket, rb_intern(ossl_ssl_attrs[i]), 1, 1, Qfalse);
    rb_define_alias(cSSLSocket, "to_io", "io");
    rb_define_method(cSSLSocket, "initialize", ossl_ssl_initialize, -1);
    rb_define_method(cSSLSocket, "connect",    ossl_ssl_connect, 0);
    rb_define_method(cSSLSocket, "accept",     ossl_ssl_accept, 0);
    rb_define_method(cSSLSocket, "sysread",    ossl_ssl_read, 1);
    rb_define_method(cSSLSocket, "syswrite",   ossl_ssl_write, 1);
    rb_define_method(cSSLSocket, "sysclose",   ossl_ssl_close, 0);
    rb_define_method(cSSLSocket, "cert",       ossl_ssl_get_cert, 0);
    rb_define_method(cSSLSocket, "peer_cert",  ossl_ssl_get_peer_cert, 0);
    rb_define_method(cSSLSocket, "cipher",     ossl_ssl_get_cipher, 0);
    rb_define_method(cSSLSocket, "state",      ossl_ssl_get_state, 0);

#define ossl_ssl_def_const(x) rb_define_const(mSSL, #x, INT2FIX(SSL_##x))

    ossl_ssl_def_const(VERIFY_NONE);
    ossl_ssl_def_const(VERIFY_PEER);
    ossl_ssl_def_const(VERIFY_FAIL_IF_NO_PEER_CERT);
    ossl_ssl_def_const(VERIFY_CLIENT_ONCE);
}
