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
#define ossl_sslctx_set_cert(o,v)        rb_iv_set((o),"@cert",(v))
#define ossl_sslctx_set_key(o,v)         rb_iv_set((o),"@key",(v))
#define ossl_sslctx_set_ca_cert(o,v)     rb_iv_set((o),"@ca_cert",(v))
#define ossl_sslctx_set_ca_file(o,v)     rb_iv_set((o),"@ca_file",(v))
#define ossl_sslctx_set_ca_path(o,v)     rb_iv_set((o),"@ca_path",(v))
#define ossl_sslctx_set_timeout(o,v)     rb_iv_set((o),"@timeout",(v))
#define ossl_sslctx_set_verify_mode(o,v) rb_iv_set((o),"@verify_mode",(v))
#define ossl_sslctx_set_verify_dep(o,v)  rb_iv_set((o),"@verify_depth",(v))
#define ossl_sslctx_set_verify_cb(o,v)   rb_iv_set((o),"@verify_callback",(v))
#define ossl_sslctx_set_options(o,v)     rb_iv_set((o),"@options",(v))

#define ossl_sslctx_get_cert(o)          rb_iv_get((o),"@cert")
#define ossl_sslctx_get_key(o)           rb_iv_get((o),"@key")
#define ossl_sslctx_get_ca_cert(o)       rb_iv_get((o),"@ca_cert")
#define ossl_sslctx_get_ca_file(o)       rb_iv_get((o),"@ca_file")
#define ossl_sslctx_get_ca_path(o)       rb_iv_get((o),"@ca_path")
#define ossl_sslctx_get_timeout(o)       rb_iv_get((o),"@timeout")
#define ossl_sslctx_get_verify_mode(o)   rb_iv_get((o),"@verify_mode")
#define ossl_sslctx_get_verify_dep(o)    rb_iv_get((o),"@verify_depth")
#define ossl_sslctx_get_verify_cb(o)     rb_iv_get((o),"@verify_callback")
#define ossl_sslctx_get_options(o)       rb_iv_get((o),"@options")

static char *ossl_sslctx_attrs[] = {
    "cert", "key", "ca_cert", "ca_file", "ca_path",
    "timeout", "verify_mode", "verify_depth",
    "verify_callback", "options", "cert_store",
}; 

struct {
    const char *name;
    SSL_METHOD *(*func)(void);
} ossl_ssl_method_tab[] = {
#define OSSL_SSL_METHOD_ENTRY(name) { #name, name##_method }
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
#undef OSSL_SSL_METHOD_ENTRY
};

static VALUE
ossl_sslctx_s_alloc(VALUE klass)
{
    SSL_CTX *ctx;
    
    ctx = SSL_CTX_new(SSLv23_method());
    if (!ctx) {
        ossl_raise(eSSLError, "SSL_CTX_new:");
    }
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    return Data_Wrap_Struct(klass, 0, SSL_CTX_free, ctx);
}
DEFINE_ALLOC_WRAPPER(ossl_sslctx_s_alloc)

static VALUE
ossl_sslctx_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE ssl_method;
    SSL_METHOD *method = NULL;
    SSL_CTX *ctx;
    int i;
    char *s;

    Data_Get_Struct(self, SSL_CTX, ctx);
    
    if (rb_scan_args(argc, argv, "01", &ssl_method) == 0){
        return self;
    }
    s =  StringValuePtr(ssl_method);
    for (i = 0; i < numberof(ossl_ssl_method_tab); i++) {
        if (strcmp(ossl_ssl_method_tab[i].name, s) == 0) {
            method = ossl_ssl_method_tab[i].func();
            break;
        }
    }
    if (!method) {
        ossl_raise(rb_eArgError, "unknown SSL method `%s'.", s);
    }
    if (SSL_CTX_set_ssl_version(ctx, method) != 1) {
        ossl_raise(eSSLError, "SSL_CTX_set_ssl_version:");
    }

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
ossl_ssl_callback_failure(VALUE cbname)
{
    char *msg;

    msg = StringValuePtr(ruby_errinfo);
    rb_warn("%s error: %s", RSTRING(cbname)->ptr, msg);

    return Qfalse;
}

static int
ossl_ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    VALUE args, cb, result, rctx;
    SSL *ssl;

    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    cb = (VALUE)SSL_get_ex_data(ssl, ossl_ssl_ex_vcb_idx);
    if(!NIL_P(cb)){
        rctx = ossl_x509stctx_new(ctx);
        args = rb_ary_new2(3);
        rb_ary_push(args, cb);
        rb_ary_push(args, preverify_ok ? Qtrue : Qfalse);
        rb_ary_push(args, rctx);
        result = rb_rescue(ossl_ssl_call_verify_cb, args,
                           ossl_ssl_callback_failure, 
                           rb_str_new2("verify_callback"));
        ossl_x509stctx_clear_ptr(rctx);
        if(result != Qtrue){
            if(X509_STORE_CTX_get_error(ctx) == X509_V_OK)
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
            return 0; /* verify NG. */
        }
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        return 1;     /* verify OK. */
    }
    
    return preverify_ok;
}

#if 0 /* enable if use SSL_CTX_user_PrivateKey_file */
static VALUE
ossl_ssl_call_passwd_cb(VALUE cb)
{
    VALUE ret;

    ret = rb_funcall(cb, rb_intern("call"), 0);
    StringValue(ret);

    return ret;
}

static int
ossl_ssl_passwd_cb(char *buf, int size, int rwflag, void *cb)
{
    VALUE result;

    result = rb_rescue(ossl_ssl_call_passwd_cb, (VALUE)cb,
                       ossl_ssl_callback_failure,
                       rb_str_new2("passwd_callback"));
    strncpy(buf, RSTRING(result)->ptr, size);
    buf[size-1] = 0;
    return strlen(buf);
}
#endif

static VALUE
ossl_sslctx_setup(VALUE self)
{
    SSL_CTX *ctx;
    X509 *cert = NULL, *ca_cert = NULL;
    X509_STORE *store; 
    EVP_PKEY *key = NULL;
    char *ca_path = NULL, *ca_file = NULL;
    int verify_mode;
    VALUE val;

    if(OBJ_FROZEN(self)) return Qnil;
    Data_Get_Struct(self, SSL_CTX, ctx);

#if 0 /* enable if use SSL_CTX_user_PrivateKey_file */
    val = ossl_sslctx_get_passwd_cb(self);
    if(!NIL_P(val)){
        SSL_CTX_set_default_passwd_cb_userdata(ctx, val);
        SSL_CTX_set_default_passwd_cb(ctx, ossl_ssl_passwd_cb);
    }
#endif

    /* private key may be bundled in certificate file. */
    val = ossl_sslctx_get_cert(self);
    cert = NIL_P(val) ? NULL : GetX509CertPtr(val); /* NO DUP NEEDED */
    val = ossl_sslctx_get_key(self);
    key = NIL_P(val) ? NULL : GetPKeyPtr(val); /* NO DUP NEEDED */
    if (cert && key) {
        if (!SSL_CTX_use_certificate(ctx, cert)) {
            /* Adds a ref => Safe to FREE */
            ossl_raise(eSSLError, "SSL_CTX_use_certificate:");
        }
        if (!SSL_CTX_use_PrivateKey(ctx, key)) {
            /* Adds a ref => Safe to FREE */
            ossl_raise(eSSLError, "SSL_CTX_use_PrivateKey:");
        }
        if (!SSL_CTX_check_private_key(ctx)) {
            ossl_raise(eSSLError, "SSL_CTX_check_private_key:");
        }
    }

    val = ossl_sslctx_get_ca_cert(self);
    ca_cert = NIL_P(val) ? NULL : GetX509CertPtr(val); /* NO DUP NEEDED. */
    if (ca_cert){
        if (!SSL_CTX_add_client_CA(ctx, ca_cert)){
            /* Copies X509_NAME => FREE it. */
            ossl_raise(eSSLError, "SSL_CTX_add_client_CA");
        }
    }

    val = ossl_sslctx_get_ca_file(self);
    ca_file = NIL_P(val) ? NULL : StringValuePtr(val);
    val = ossl_sslctx_get_ca_path(self);
    ca_path = NIL_P(val) ? NULL : StringValuePtr(val);
    if ((!SSL_CTX_load_verify_locations(ctx, ca_file, ca_path) ||
         !SSL_CTX_set_default_verify_paths(ctx))) {
        rb_warning("can't set verify locations");
    }

    val = ossl_sslctx_get_verify_mode(self);
    verify_mode = NIL_P(val) ? SSL_VERIFY_NONE : NUM2INT(val);
    SSL_CTX_set_verify(ctx, verify_mode, ossl_ssl_verify_callback);

    val = ossl_sslctx_get_timeout(self);
    if(!NIL_P(val)) SSL_CTX_set_timeout(ctx, NUM2LONG(val));

    val = ossl_sslctx_get_verify_dep(self);
    if(!NIL_P(val)) SSL_CTX_set_verify_depth(ctx, NUM2LONG(val));

    val = ossl_sslctx_get_cert_store(self);
    if(!NIL_P(val)){
        store = DupX509StorePtr(val);
        SSL_CTX_set_cert_store(ctx, store);
    }

    val = ossl_sslctx_get_options(self);
    if(!NIL_P(val)) SSL_CTX_set_options(ctx, NUM2LONG(val));
    rb_obj_freeze(self);

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
    SSL_CTX *ctx;
    STACK_OF(SSL_CIPHER) *ciphers;
    SSL_CIPHER *cipher;
    VALUE ary;
    int i, num;

    Data_Get_Struct(self, SSL_CTX, ctx);
    if(!ctx){
        rb_warning("SSL_CTX is not initialized.");
        return Qnil;
    }
    ciphers = ctx->cipher_list;

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
    SSL_CTX *ctx;
    VALUE str, elem;
    int i;

    rb_check_frozen(self);
    Data_Get_Struct(self, SSL_CTX, ctx);
    if(!ctx){
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

    if (!SSL_CTX_set_cipher_list(ctx, RSTRING(str)->ptr)) {
        ossl_raise(eSSLError, "SSL_CTX_set_ciphers:");
    }
    return Qnil;
}

/*
 * SSLSocket class
 */
#define ossl_ssl_get_io(o)    rb_iv_get((o),"@io")
#define ossl_ssl_get_ctx(o)   rb_iv_get((o),"@context")

#define ossl_ssl_set_io(o,v)  rb_iv_set((o),"@io",(v))
#define ossl_ssl_set_ctx(o,v) rb_iv_set((o),"@context",(v))

static char *ossl_ssl_attrs[] = { "io", "context", };

static void
ossl_ssl_shutdown(SSL *ssl)
{
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_clear(ssl);
    }
}

static void
ossl_ssl_free(SSL *ssl)
{
    ossl_ssl_shutdown(ssl);
    SSL_free(ssl);
}

static VALUE
ossl_ssl_s_alloc(VALUE klass)
{
    return Data_Wrap_Struct(klass, 0, ossl_ssl_free, NULL);
}
DEFINE_ALLOC_WRAPPER(ossl_ssl_s_alloc)

static VALUE
ossl_ssl_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE io, ctx;

    if (rb_scan_args(argc, argv, "11", &io, &ctx) == 1) {
        ctx = rb_funcall(cSSLContext, rb_intern("new"), 0);
    }
    OSSL_Check_Kind(ctx, cSSLContext);
    Check_Type(io, T_FILE);
    ossl_ssl_set_io(self, io);
    ossl_ssl_set_ctx(self, ctx);
    ossl_sslctx_setup(ctx);

    return self;
}

static VALUE
ossl_ssl_setup(VALUE self)
{
    VALUE io, v_ctx;
    SSL_CTX *ctx;
    SSL *ssl;
    OpenFile *fptr;

    Data_Get_Struct(self, SSL, ssl);
    if(!ssl){
        v_ctx = ossl_ssl_get_ctx(self);
        Data_Get_Struct(v_ctx, SSL_CTX, ctx);

        ssl = SSL_new(ctx);
        if (!ssl) {
            ossl_raise(eSSLError, "SSL_new:");
        }
        DATA_PTR(self) = ssl;

        io = ossl_ssl_get_io(self);
        GetOpenFile(io, fptr);
        rb_io_check_readable(fptr);
        rb_io_check_writable(fptr);
        SSL_set_fd(ssl, fileno(fptr->f));
    }

    return Qtrue;
}

static VALUE
ossl_ssl_connect(VALUE self)
{
    SSL *ssl;
    VALUE cb;

    ossl_ssl_setup(self);
    Data_Get_Struct(self, SSL, ssl);
    cb = ossl_sslctx_get_verify_cb(ossl_ssl_get_ctx(self));
    SSL_set_ex_data(ssl, ossl_ssl_ex_vcb_idx, (void *)cb);
    if (SSL_connect(ssl) <= 0) {
        ossl_raise(eSSLError, "SSL_connect:");
    }

    return self;
}

static VALUE
ossl_ssl_accept(VALUE self)
{
    SSL *ssl;
    VALUE cb;

    ossl_ssl_setup(self);
    Data_Get_Struct(self, SSL, ssl);
    cb = ossl_sslctx_get_verify_cb(ossl_ssl_get_ctx(self));
    SSL_set_ex_data(ssl, ossl_ssl_ex_vcb_idx, (void *)cb);
    if (SSL_accept(ssl) <= 0) {
        ossl_raise(eSSLError, "SSL_accept:");
    }

    return self;
}

static VALUE
ossl_ssl_read(VALUE self, VALUE len)
{
    SSL *ssl;
    int ilen, nread = 0;
    VALUE str;
    OpenFile *fptr;

    Data_Get_Struct(self, SSL, ssl);
    ilen = NUM2INT(len);
    str = rb_str_new(0, ilen);

    if (ssl) {
        nread = SSL_read(ssl, RSTRING(str)->ptr, RSTRING(str)->len);
        if (nread < 0) {
            ossl_raise(eSSLError, "SSL_read:");
        }
    }
    else {
        rb_warning("SSL session is not started yet.");
        GetOpenFile(ossl_ssl_get_io(self), fptr);
        rb_io_check_readable(fptr);
        TRAP_BEG;
        nread = read(fileno(fptr->f), RSTRING(str)->ptr, RSTRING(str)->len);
        TRAP_END;
        if(nread < 0) {
            ossl_raise(eSSLError, "read:%s", strerror(errno));
        }
    }

    if (nread == 0) {
        ossl_raise(rb_eEOFError, "End of file reached");
    }

    RSTRING(str)->len = nread;
    RSTRING(str)->ptr[nread] = 0;
    OBJ_TAINT(str);

    return str;
}

static VALUE
ossl_ssl_write(VALUE self, VALUE str)
{
    SSL *ssl;
    int nwrite = 0;
    OpenFile *fptr;
    FILE *fp;

    Data_Get_Struct(self, SSL, ssl);
    StringValue(str);

    if (ssl) {
        nwrite = SSL_write(ssl, RSTRING(str)->ptr, RSTRING(str)->len);
        if (nwrite <= 0) {
            ossl_raise(eSSLError, "SSL_write:");
        }
    }
    else {
        rb_warning("SSL session is not started yet.");
        GetOpenFile(ossl_ssl_get_io(self), fptr);
        rb_io_check_writable(fptr);
        fp = GetWriteFile(fptr);
        nwrite = write(fileno(fp), RSTRING(str)->ptr, RSTRING(str)->len);
        if (nwrite < 0) {
            ossl_raise(eSSLError, "write:%s", strerror(errno));
        }
    }

    return INT2NUM(nwrite);
}

static VALUE
ossl_ssl_close(VALUE self)
{
    SSL *ssl;

    Data_Get_Struct(self, SSL, ssl);

    ossl_ssl_shutdown(ssl);
    
    return Qnil;
}

static VALUE
ossl_ssl_get_cert(VALUE self)
{
    SSL *ssl;
    X509 *cert = NULL;

    Data_Get_Struct(self, SSL, ssl);
    if (ssl) {
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }

    /*
     * Is this OpenSSL bug? Should add a ref?
     * TODO: Ask for.
     */
    cert = SSL_get_certificate(ssl); /* NO DUPs => DON'T FREE. */

    if (!cert) {
        return Qnil;
    }
    return ossl_x509_new(cert);
}

static VALUE
ossl_ssl_get_peer_cert(VALUE self)
{
    SSL *ssl;
    X509 *cert = NULL;
    VALUE obj;

    Data_Get_Struct(self, SSL, ssl);

    if (!ssl){
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }

    cert = SSL_get_peer_certificate(ssl); /* Adds a ref => Safe to FREE. */

    if (!cert) {
        return Qnil;
    }
    obj = ossl_x509_new(cert);
    X509_free(cert);

    return obj;
}

static VALUE
ossl_ssl_get_cipher(VALUE self)
{
    SSL *ssl;
    SSL_CIPHER *cipher;

    Data_Get_Struct(self, SSL, ssl);
    if (!ssl) {
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }
    cipher = SSL_get_current_cipher(ssl);

    return ossl_ssl_cipher_to_ary(cipher);
}

static VALUE
ossl_ssl_get_state(VALUE self)
{
    SSL *ssl;
    VALUE ret;

    Data_Get_Struct(self, SSL, ssl);
    if (!ssl) {
        rb_warning("SSL session is not started yet.");
        return Qnil;
    }
    ret = rb_str_new2(SSL_state_string(ssl));
    if (ruby_verbose) {
        rb_str_cat2(ret, ": ");
        rb_str_cat2(ret, SSL_state_string_long(ssl));
    }
    return ret;
}

void
Init_ossl_ssl()
{
    int i;

    ossl_ssl_ex_vcb_idx = SSL_get_ex_new_index(0, "ossl_ssl_ex_vcb_idx", NULL, NULL, NULL);

    mSSL = rb_define_module_under(mOSSL, "SSL");
    eSSLError = rb_define_class_under(mSSL, "SSLError", eOSSLError);

    /* class SSLContext */
    cSSLContext = rb_define_class_under(mSSL, "SSLContext", rb_cObject);
    rb_define_alloc_func(cSSLContext, ossl_sslctx_s_alloc);
    for(i = 0; i < numberof(ossl_sslctx_attrs); i++)
        rb_attr(cSSLContext, rb_intern(ossl_sslctx_attrs[i]), 1, 1, Qfalse);
    rb_define_method(cSSLContext, "initialize",  ossl_sslctx_initialize, -1);
    rb_define_method(cSSLContext, "ciphers",     ossl_sslctx_get_ciphers, 0);
    rb_define_method(cSSLContext, "ciphers=",    ossl_sslctx_set_ciphers, 1);

    /* class SSLSocket */
    cSSLSocket = rb_define_class_under(mSSL, "SSLSocket", rb_cObject);
    rb_define_alloc_func(cSSLSocket, ossl_ssl_s_alloc);
    for(i = 0; i < numberof(ossl_ssl_attrs); i++)
        rb_attr(cSSLSocket, rb_intern(ossl_ssl_attrs[i]), 1, 0, Qfalse);
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
    /* Not introduce constants included in OP_ALL such as...
     * ossl_ssl_def_const(OP_MICROSOFT_SESS_ID_BUG);
     * ossl_ssl_def_const(OP_NETSCAPE_CHALLENGE_BUG);
     * ossl_ssl_def_const(OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);
     * ossl_ssl_def_const(OP_SSLREF2_REUSE_CERT_TYPE_BUG);
     * ossl_ssl_def_const(OP_MICROSOFT_BIG_SSLV3_BUFFER);
     * ossl_ssl_def_const(OP_MSIE_SSLV2_RSA_PADDING);
     * ossl_ssl_def_const(OP_SSLEAY_080_CLIENT_DH_BUG);
     * ossl_ssl_def_const(OP_TLS_D5_BUG);
     * ossl_ssl_def_const(OP_TLS_BLOCK_PADDING_BUG);
     * ossl_ssl_def_const(OP_DONT_INSERT_EMPTY_FRAGMENTS);
     */
    ossl_ssl_def_const(OP_ALL);
    ossl_ssl_def_const(OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    /* ossl_ssl_def_const(OP_SINGLE_ECDH_USE); */
    ossl_ssl_def_const(OP_SINGLE_DH_USE);
    ossl_ssl_def_const(OP_EPHEMERAL_RSA);
    ossl_ssl_def_const(OP_CIPHER_SERVER_PREFERENCE);
    ossl_ssl_def_const(OP_TLS_ROLLBACK_BUG);
    ossl_ssl_def_const(OP_NO_SSLv2);
    ossl_ssl_def_const(OP_NO_SSLv3);
    ossl_ssl_def_const(OP_NO_TLSv1);
    ossl_ssl_def_const(OP_PKCS1_CHECK_1);
    ossl_ssl_def_const(OP_PKCS1_CHECK_2);
    ossl_ssl_def_const(OP_NETSCAPE_CA_DN_BUG);
    ossl_ssl_def_const(OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG);
}
