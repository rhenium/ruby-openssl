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

#define GetSSLCTX(obj, ctx) do {  \
    Check_Type(obj, cSSLContext); \
    ssl_ctx_setup(obj);           \
    Data_Get_Struct(obj, ssl_ctx_st, ctx); \
} while (0)

VALUE mSSL;
VALUE eSSLError;
VALUE cSSLContext;
VALUE cSSLSocket;

/*
 * SSLContext class
 */
#define ssl_ctx_set_method(o,v)      rb_iv_set((o),"@ssl_method",(v))
#define ssl_ctx_set_cert(o,v)        rb_iv_set((o),"@cert",(v))
#define ssl_ctx_set_cert_file(o,v)   rb_iv_set((o),"@cert_file",(v))
#define ssl_ctx_set_key(o,v)         rb_iv_set((o),"@key",(v))
#define ssl_ctx_set_key_file(o,v)    rb_iv_set((o),"@key_file",(v))
#define ssl_ctx_set_ca(o,v)          rb_iv_set((o),"@ca_cert",(v))
#define ssl_ctx_set_ca_file(o,v)     rb_iv_set((o),"@ca_file",(v))
#define ssl_ctx_set_ca_path(o,v)     rb_iv_set((o),"@ca_path",(v))
#define ssl_ctx_set_timeout(o,v)     rb_iv_set((o),"@timeout",(v))
#define ssl_ctx_set_verify_mode(o,v) rb_iv_set((o),"@verify_mode",(v))
#define ssl_ctx_set_verify_dep(o,v)  rb_iv_set((o),"@verify_depth",(v))
#define ssl_ctx_set_verify_cb(o,v)   rb_iv_set((o),"@verify_callback",(v))

#define ssl_ctx_get_method(o,v)      rb_iv_get((o),"@ssl_method",(v))
#define ssl_ctx_get_cert(o)          rb_iv_get((o),"@cert")
#define ssl_ctx_get_cert_file(o)     rb_iv_get((o),"@cert_file")
#define ssl_ctx_get_key(o)           rb_iv_get((o),"@key")
#define ssl_ctx_get_key_file(o)      rb_iv_get((o),"@key_file")
#define ssl_ctx_get_ca(o)            rb_iv_get((o),"@ca_cert")
#define ssl_ctx_get_ca_file(o)       rb_iv_get((o),"@ca_file")
#define ssl_ctx_get_ca_path(o)       rb_iv_get((o),"@ca_path")
#define ssl_ctx_get_timeout(o)       rb_iv_get((o),"@timeout")
#define ssl_ctx_get_verify_mode(o)   rb_iv_get((o),"@verify_mode")
#define ssl_ctx_get_verify_dep(o)    rb_iv_get((o),"@verify_depth")
#define ssl_ctx_get_verify_cb(o)     rb_iv_get((o),"@verify_callback")

static VALUE ssl_ctx_set_cert2(VALUE, VALUE);
static VALUE ssl_ctx_set_cert_file2(VALUE, VALUE);
static VALUE ssl_ctx_set_key2(VALUE, VALUE);
static VALUE ssl_ctx_set_key_file2(VALUE, VALUE);

typedef struct ssl_ctx_st_t{
    SSL_METHOD *method;
    SSL_CTX *ctx;
} ssl_ctx_st;

static char *ssl_ctx_attrs[] = {
    "cert", "cert_file", "key", "key_file", "ca_cert", "ca_file", "ca_path",
    "timeout", "verify_mode", "verify_depth", "verify_callback", "ssl_method",
}; 

#define OSSL_METHOD_ENTRY(name) { #name, name##_method }

typedef struct ssl_method_name_table_t {
    const char *name;
    SSL_METHOD *(*f)(void);
} ssl_method_name_table;

ssl_method_name_table ssl_method_tab[] = {
    OSSL_METHOD_ENTRY(TLSv1),
    OSSL_METHOD_ENTRY(TLSv1_server),
    OSSL_METHOD_ENTRY(TLSv1_client),
    OSSL_METHOD_ENTRY(SSLv2),
    OSSL_METHOD_ENTRY(SSLv2_server),
    OSSL_METHOD_ENTRY(SSLv2_client),
    OSSL_METHOD_ENTRY(SSLv3),
    OSSL_METHOD_ENTRY(SSLv3_server),
    OSSL_METHOD_ENTRY(SSLv3_client),
    OSSL_METHOD_ENTRY(SSLv23),
    OSSL_METHOD_ENTRY(SSLv23_server),
    OSSL_METHOD_ENTRY(SSLv23_client),
};

static void
ssl_ctx_free(ssl_ctx_st *p)
{
    SSL_CTX_free(p->ctx);
    p->ctx = NULL;
}

static VALUE
ssl_ctx_s_alloc(int argc, VALUE *argv, VALUE klass)
{
    ssl_ctx_st *p;
    return Data_Make_Struct(klass, ssl_ctx_st, 0, ssl_ctx_free, p);
}

static VALUE
ssl_ctx_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE ssl_method;
    ssl_ctx_st *p;
    int i;
    char *s;

    rb_scan_args(argc, argv, "01", &ssl_method);
    Data_Get_Struct(self, ssl_ctx_st, p);
    if(NIL_P(ssl_method)) ssl_method = rb_str_new2("SSLv23");
    s = StringValuePtr(ssl_method);
    for(i = 0; i < numberof(ssl_method_tab); i++){
	if(strcmp(ssl_method_tab[i].name, s) == 0){
	    p->method = ssl_method_tab[i].f();
            ssl_ctx_set_method(self, ssl_method);
	    break;
	}
    }
    if(p->method == NULL)
        rb_raise(rb_eArgError, "unknow SSL method `%s'.", s);

    return self;
}

/*
 * for rb_rescue in ssl_verify_callback
 * see below
 */
static VALUE
ssl_false(VALUE dummy)
{
    return Qfalse;
}

static int
ssl_verify_callback(int ok, X509_STORE_CTX *ctx)
{
    VALUE x509stc, args, ret = Qnil;

    /* the callback is passed by ssl_connect() or ssl_accept() */
    if (rb_block_given_p()){
	x509stc = ossl_x509store_new(ctx);
	rb_funcall(x509stc, rb_intern("protect"), 0, NULL);
	args = rb_ary_new2(2);
	rb_ary_store(args, 0, ok ? Qtrue : Qfalse);
	rb_ary_store(args, 2, x509stc);
	ret = rb_rescue(rb_yield, args, ssl_false, Qnil);

	if (ret == Qtrue) {
	    ok = 1;
	    X509_STORE_CTX_set_error(ctx, X509_V_OK);
	}
	else {
	    ok = 0;
	    if (X509_STORE_CTX_get_error(ctx) == X509_V_OK){
		/* no error, but the callback rejects */
		X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
	    }
	}
    }
    
    return ok;
}

static VALUE
ssl_ctx_setup(VALUE self)
{
    ssl_ctx_st *p = NULL;
    SSL_METHOD *meth;
    X509 *cert = NULL, *ca = NULL;
    EVP_PKEY *key = NULL;
    char *ca_path = NULL, *ca_file = NULL;
    int verify_mode;
    VALUE val;

    Data_Get_Struct(self, ssl_ctx_st, p);
    if(p->ctx) return Qfalse;

    if((p->ctx = SSL_CTX_new(p->method)) == NULL)
	ossl_raise(eSSLError, "SSL_CTX_new:");
    SSL_CTX_set_options(p->ctx, SSL_OP_ALL);

    /* private key may be bundled in certificate file. */
    val = ssl_get_cert(self);
    cert = NIL_P(val) ? NULL : GetX509CertPtr(val); /* NO DUP NEEDED */
    val = ssl_get_key(self);
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

    val = ssl_get_ca(self);
    ca = NIL_P(val) ? NULL : GetX509CertPtr(val); /* NO DUP NEEDED. */
    val = ssl_get_ca_file(self);
    ca_file = NIL_P(val) ? NULL : RSTRING(val)->ptr;
    val = ssl_get_ca_path(self);
    ca_path = NIL_P(val) ? NULL : RSTRING(val)->ptr;

    if (ca){
	if (!SSL_CTX_add_client_CA(p->ctx, ca)){
	    /* Copies X509_NAME => FREE it. */
	    ossl_raise(eSSLError, "");
	}
    }
    if ((!SSL_CTX_load_verify_locations(p->ctx, ca_file, ca_path) ||
	 !SSL_CTX_set_default_verify_paths(p->ctx))) {
	rb_warning("can't set verify locations");
    }

    val = ssl_get_verify_mode(self);
    verify_mode = NIL_P(val) ? SSL_VERIFY_NONE : NUM2INT(val);
    SSL_CTX_set_verify(p->ctx, verify_mode, ssl_verify_callback);

    val = ssl_get_timeout(self);
    if(!NIL_P(val)) SSL_CTX_set_timeout(p->ctx, NUM2LONG(val));

    val = ssl_get_verify_dep(self);
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
ssl_ctx_get_ciphers(VALUE self)
{
    ssl_ctx_st *p;
    STACK_OF(SSL_CIPHER) *ciphers;
    SSL_CIPHER *cipher;
    VALUE ary;
    int i;

    Data_Get_Struct(self, ssl_ctx_st, p);
    if(!p->ctx){
	rb_warning("SSL_CTX is not initialized.");
	return Qnil;
    }
    ciphers = p->ctx->cipher_list;
    ary = rb_ary_new();
    if(ciphers){
	for(i = 0; i < sk_num((STACK*)ciphers); i++){
	    cipher = (SSL_CIPHER*)sk_value((STACK*)ciphers, i);
	    rb_ary_push(ary, ssl_cipher_to_ary(cipher));
	}
    }
    return ary;
}

static VALUE
ssl_ctx_set_ciphers(VALUE self, VALUE v)
{
    ssl_ctx_st *p;
    VALUE str, elem;
    int i;

    Data_Get_Struct(self, ssl_ctx_st, p);
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
    } else str = rb_String(v);

    if (!SSL_CTX_set_cipher_list(p->ctx, RSTRING(str)->ptr)) {
	ossl_raise(eSSLError, "SSL_CTX_set_ciphers:");
    }
    return Qnil;
}

static VALUE
ssl_ctx_set_cert2(VALUE self, VALUE v)
{
    if(!NIL_P(v)) OSSL_Check_Kind(v, cX509Cert);
    ssl_set_cert(self, v);
    ssl_set_cert_file(self, Qnil);
    return v;
}

static VALUE
ssl_ctx_set_cert_file2(VALUE self, VALUE v)
{
    VALUE cert;
    cert = NIL_P(v) ? Qnil :ossl_x509_new_from_file(v);
    ssl_set_cert(self, cert);
    ssl_set_cert_file(self, v);
    return v;
}

static VALUE
ssl_ctx_set_key2(VALUE self, VALUE v)
{
    if(!NIL_P(v)) OSSL_Check_Kind(v, cPKey);
    ssl_set_key(self, v);
    ssl_set_key_file(self, Qnil);
    return v;
}

static VALUE
ssl_ctx_set_key_file2(VALUE self, VALUE v)
{
    VALUE key;
    key = NIL_P(v) ? Qnil : ossl_pkey_new_from_file(v);
    ssl_set_key(self, key);
    ssl_set_key_file(self, v);
    return v;
}

/*
 * SSLSocket class
 */
#define ssl_get_io(o)        rb_iv_get((o),"@io")
#define ssl_get_context(o)   rb_iv_get((o),"@context")

#define ssl_set_io(o,v)      rb_iv_set((o),"@io",(v))
#define ssl_set_context(o,v) rb_iv_set((o),"@context",(v))

typedef struct ssl_st_t{
    SSL *ssl;
} ssl_st;

static char *ssl_attrs[] = { "io" };

static void
ssl_shutdown(ssl_st *p)
{
    if(p->ssl){
	SSL_shutdown(p->ssl);
	SSL_clear(p->ssl);
    }
}

static void
ssl_free(ssl_st *p)
{
    ssl_shutdown(p);
    SSL_free(p->ssl);
    p->ssl = NULL;
    free(p);
}

static VALUE
ssl_setup(VALUE self)
{
    ssl_st *p;
    VALUE io, rctx;
    ssl_ctx_st *ctx;
    OpenFile *fptr;

    Data_Get_Struct(self, ssl_st, p);
    if(!p->ssl){
        GetSSLCTX(ssl_get_context(self), ctx);

	io = ssl_get_io(self);
	GetOpenFile(io, fptr);
	rb_io_check_readable(fptr);
	rb_io_check_writable(fptr);
	if((p->ssl = SSL_new(ctx->ctx)) == NULL)
	    ossl_raise(eSSLError, "SSL_new:");

	SSL_set_fd(p->ssl, fileno(fptr->f));
    }

    return Qtrue;
}

static VALUE
ssl_s_alloc(VALUE klass)
{
    ssl_st *p;
    return Data_Make_Struct(klass, ssl_st, 0, ssl_free, p);
}

static VALUE
ssl_initialize(VALUE self, VALUE ctx)
{
    Check_Type(ctx, cSSLContext);
    ssl_ctx_set_context(self, ctx);
    return self;
}

static VALUE
ssl_connect(VALUE self)
{
    ssl_st *p;

    Data_Get_Struct(self, ssl_st, p);
    ssl_ctx_setup(self);
    ssl_setup(self);

    if(SSL_connect(p->ssl) <= 0){
	ossl_raise(eSSLError, "SSL_connect:");
    }

    return self;
}

static VALUE
ssl_accept(VALUE self)
{
    ssl_st *p;

    Data_Get_Struct(self, ssl_st, p);
    ssl_ctx_setup(self);
    ssl_setup(self);

    if(SSL_accept(p->ssl) <= 0){
	ossl_raise(eSSLError, "SSL_accept:");
    }

    return self;
}

static VALUE
ssl_read(VALUE self, VALUE len)
{
    ssl_st *p;
    size_t ilen, nread = 0;
    VALUE str;
    OpenFile *fptr;

    Data_Get_Struct(self, ssl_st, p);
    ilen = NUM2INT(len);
    str = rb_str_new(0, ilen);

    if (p->ssl) {
	nread = SSL_read(p->ssl, RSTRING(str)->ptr, RSTRING(str)->len);
	if(nread < 0)
	    ossl_raise(eSSLError, "SSL_read:");
    }
    else {
	if(ruby_verbose) rb_warning("SSL session is not started yet.");
	GetOpenFile(ssl_get_io(self), fptr);
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
ssl_write(VALUE self, VALUE str)
{
    ssl_st *p;
    size_t nwrite = 0;
    OpenFile *fptr;
    FILE *fp;

    Data_Get_Struct(self, ssl_st, p);
    str = rb_String(str);

    if (p->ssl) {
	nwrite = SSL_write(p->ssl, RSTRING(str)->ptr, RSTRING(str)->len);
	if (nwrite <= 0)
	    ossl_raise(eSSLError, "SSL_write:");
    }
    else {
	if(ruby_verbose) rb_warning("SSL session is not started yet.");
	GetOpenFile(ssl_get_io(self), fptr);
	rb_io_check_writable(fptr);
	fp = GetWriteFile(fptr);
	nwrite = write(fileno(fp), RSTRING(str)->ptr, RSTRING(str)->len);
	if(nwrite < 0)
	    ossl_raise(eSSLError, "write:%s", strerror(errno));
    }

    return INT2NUM(nwrite);
}

static VALUE
ssl_close(VALUE self)
{
    ssl_st *p;

    Data_Get_Struct(self, ssl_st, p);
    ssl_shutdown(p);
    return Qnil;
}

static VALUE
ssl_get_certificate(VALUE self)
{
    ssl_st *p;
    X509 *cert = NULL;

    Data_Get_Struct(self, ssl_st, p);
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
ssl_get_peer_certificate(VALUE self)
{
    ssl_st *p;
    X509 *cert = NULL;
    VALUE obj;

    Data_Get_Struct(self, ssl_st, p);

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
ssl_get_cipher(VALUE self)
{
    ssl_st *p;
    SSL_CIPHER *cipher;

    Data_Get_Struct(self, ssl_st, p);
    if(!p->ssl){
	rb_warning("SSL session is not started yet.");
	return Qnil;
    }
    cipher = SSL_get_current_cipher(p->ssl);

    return ssl_cipher_to_ary(cipher);
}

static VALUE
ssl_get_state(VALUE self)
{
    ssl_st *p;
    VALUE ret;

    Data_Get_Struct(self, ssl_st, p);
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

    mSSL = rb_define_module_under(mOSSL, "SSL");

    /* class SSLError */
    eSSLError = rb_define_class_under(mSSL, "SSLError", eOSSLError);

    /* class SSLContext */
    cSSLContext = rb_define_class_under(mSSL, "SSLContext", rb_cObject);
    rb_define_singleton_method(cSSLContext, "allocate", ssl_ctx_s_alloc, -1);
    for(i = 0; i < numberof(ssl_ctx_attrs); i++)
        rb_attr(cSSLContext, rb_intern(ssl_ctx_attrs[i]), 1, 1, Qfalse);
    rb_define_method(cSSLContext, "initialize",  ssl_ctx_initialize, -1);
    rb_define_method(cSSLContext, "ciphers",     ssl_ctx_get_ciphers, 0);
    rb_define_method(cSSLContext, "ciphers=",    ssl_ctx_set_ciphers, 1);
    rb_define_method(cSSLContext, "cert=",       ssl_ctx_set_cert2, 1);
    rb_define_method(cSSLContext, "cert_file=",  ssl_ctx_set_cert_file2, 1);
    rb_define_method(cSSLContext, "key=",        ssl_ctx_set_key2, 1);
    rb_define_method(cSSLContext, "key_file=",   ssl_ctx_set_key_file2, 1);
    rb_define_method(cSSLContext, "setup",       ssl_ctx_setup, 0);

    /* class SSLSocket */
    cSSLSocket = rb_define_class_under(mSSL, "SSLSocket", rb_cObject);
    rb_define_singleton_method(cSSLSocket, "allocate", ssl_s_alloc, -1);
    for(i = 0; i < numberof(ssl_attrs); i++)
        rb_attr(cSSLSocket, rb_intern(ssl_attrs[i]), 1, 1, Qfalse);
    rb_define_alias(cSSLSocket, "to_io", "io");
    rb_define_method(cSSLSocket, "initialize",   ssl_initialize, 1);
    rb_define_method(cSSLSocket, "__connect__",  ssl_connect, 0);
    rb_define_method(cSSLSocket, "__accept__",   ssl_accept, 0);
    rb_define_method(cSSLSocket, "sysread",      ssl_read, 1);
    rb_define_method(cSSLSocket, "syswrite",     ssl_write, 1);
    rb_define_method(cSSLSocket, "sysclose",     ssl_close, 0);
    rb_define_method(cSSLSocket, "cert",         ssl_get_certificate, 0);
    rb_define_method(cSSLSocket, "peer_cert",    ssl_get_peer_certificate, 0);
    rb_define_method(cSSLSocket, "cipher",       ssl_get_cipher, 0);
    rb_define_method(cSSLSocket, "state",        ssl_get_state, 0);

#define ssl_def_const(x) rb_define_const(mSSL, #x, INT2FIX(SSL_##x))

    ssl_def_const(VERIFY_NONE);
    ssl_def_const(VERIFY_PEER);
    ssl_def_const(VERIFY_FAIL_IF_NO_PEER_CERT);
    ssl_def_const(VERIFY_CLIENT_ONCE);
}
