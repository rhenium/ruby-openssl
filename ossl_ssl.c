/*-
 * Copyright (c) 2000-2002 GOTOU YUUZOU <gotoyuzo@notwork.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $IPR: ssl.c,v 1.22 2001/09/21 17:35:51 gotoyuzo Exp $
 */
/*
 * $Id$
 * for 'OpenSSL for Ruby' project modified by Michal Rokos <m.rokos@sh.cvut.cz>
 */
#include "ossl.h"
#include <rubysig.h>
#include <rubyio.h>

#define numberof(ary) (sizeof(ary)/sizeof((ary)[0]))

#define ssl_get_io(o)            rb_ivar_get((o),rb_intern("@io"))
#define ssl_get_cert(o)          rb_ivar_get((o),rb_intern("@cert"))
#define ssl_get_cert_file(o)     rb_ivar_get((o),rb_intern("@cert_file"))
#define ssl_get_key(o)           rb_ivar_get((o),rb_intern("@key"))
#define ssl_get_key_file(o)      rb_ivar_get((o),rb_intern("@key_file"))
#define ssl_get_ca(o)            rb_ivar_get((o),rb_intern("@ca_cert"))
#define ssl_get_ca_file(o)       rb_ivar_get((o),rb_intern("@ca_file"))
#define ssl_get_ca_path(o)       rb_ivar_get((o),rb_intern("@ca_path"))
#define ssl_get_timeout(o)       rb_ivar_get((o),rb_intern("@timeout"))
#define ssl_get_verify_mode(o)   rb_ivar_get((o),rb_intern("@verify_mode"))
#define ssl_get_verify_dep(o)    rb_ivar_get((o),rb_intern("@verify_depth"))
#define ssl_get_verify_cb(o)     rb_ivar_get((o),rb_intern("@verify_callback"))

#define ssl_set_io(o,v)          rb_ivar_set((o),rb_intern("@io"),(v))
#define ssl_set_cert(o,v)        rb_ivar_set((o),rb_intern("@cert"),(v))
#define ssl_set_cert_file(o,v)   rb_ivar_set((o),rb_intern("@cert_file"),(v))
#define ssl_set_key(o,v)         rb_ivar_set((o),rb_intern("@key"),(v))
#define ssl_set_key_file(o,v)    rb_ivar_set((o),rb_intern("@key_file"),(v))
#define ssl_set_ca(o,v)          rb_ivar_set((o),rb_intern("@ca_cert"),(v))
#define ssl_set_ca_file(o,v)     rb_ivar_set((o),rb_intern("@ca_file"),(v))
#define ssl_set_ca_path(o,v)     rb_ivar_set((o),rb_intern("@ca_path"),(v))
#define ssl_set_timeout(o,v)     rb_ivar_set((o),rb_intern("@timeout"),(v))
#define ssl_set_verify_mode(o,v) rb_ivar_set((o),rb_intern("@verify_mode"),(v))
#define ssl_set_verify_dep(o,v)  rb_ivar_set((o),rb_intern("@verify_depth"),(v))
#define ssl_set_verify_cb(o,v)   rb_ivar_set((o),rb_intern("@verify_callback"),(v))

static VALUE ssl_set_cert2(VALUE, VALUE);
static VALUE ssl_set_cert_file2(VALUE, VALUE);
static VALUE ssl_set_key2(VALUE, VALUE);
static VALUE ssl_set_key_file2(VALUE, VALUE);

/*
 * Classes
 */
VALUE cSSLSocket;
VALUE eSSLError;

/*
 * List of instance vars
 */
char *ssl_attrs[] = {
  "ca_cert", "ca_file", "ca_path",
  "timeout", "verify_mode", "verify_depth", "verify_callback"
};

char *ssl_attr_readers[] = {
  "io", "cert", "cert_file", "key", "key_file"
};

/*
 * Struct
 */
typedef struct ssl_st_t{
    SSL     *ssl;
    SSL_CTX *ctx;
} ssl_st;

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
    SSL_CTX_free(p->ctx);
	p->ctx = NULL;
    free(p);
}

static VALUE ssl_verify_callback_proc;

static VALUE
ssl_call_callback_proc(VALUE args)
{
	VALUE proc, ok, x509stc;

	proc = rb_ary_entry(args, 0);
	ok = rb_ary_entry(args, 1);
	x509stc = rb_ary_entry(args, 2);

	return rb_funcall(proc, rb_intern("call"), 2, ok, x509stc);
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

static int MS_CALLBACK
ssl_verify_callback(int ok, X509_STORE_CTX *ctx)
{
	VALUE x509stc, args, ret = Qnil;

	if (!NIL_P(ssl_verify_callback_proc)) {
		x509stc = ossl_x509store_new(ctx);
		rb_funcall(x509stc, rb_intern("protect"), 0, NULL);
		args = rb_ary_new2(3);
		rb_ary_store(args, 0, ssl_verify_callback_proc);
		rb_ary_store(args, 1, ok ? Qtrue : Qfalse);
		rb_ary_store(args, 2, x509stc);
		ret = rb_rescue(ssl_call_callback_proc, args, ssl_false, Qnil);

		if (ret == Qtrue) {
			ok = 1;
			X509_STORE_CTX_set_error(ctx, X509_V_OK);
		} else {
			ok = 0;
			if (X509_STORE_CTX_get_error(ctx) == X509_V_OK)
				X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
		}
	}

	return ok;
}

static void
ssl_ctx_setup(VALUE self)
{
    ssl_st *p = NULL;
    X509 *cert = NULL, *ca = NULL;
    EVP_PKEY *key = NULL;
    char *ca_path = NULL, *ca_file = NULL;
    int verify_mode;
    VALUE val;

    Data_Get_Struct(self, ssl_st, p);

    /* private key may be bundled in certificate file. */
    val = ssl_get_cert(self);
    cert = NIL_P(val) ? NULL : ossl_x509_get_X509(val);
    val = ssl_get_key(self);
    key = NIL_P(val) ? NULL : ossl_pkey_get_EVP_PKEY(val);

    	if (cert && key) {
		if (!SSL_CTX_use_certificate(p->ctx, cert)) { /* Adds a ref => Safe to FREE */
			X509_free(cert);
			EVP_PKEY_free(key);
			OSSL_Raise(eSSLError, "SSL_CTX_use_certificate:");
		}
		if (!SSL_CTX_use_PrivateKey(p->ctx, key)) { /* Adds a ref => Safe to FREE */
			X509_free(cert);
			EVP_PKEY_free(key);
			OSSL_Raise(eSSLError, "SSL_CTX_use_PrivateKey:");
		}
		if (!SSL_CTX_check_private_key(p->ctx)) {
			X509_free(cert);
			EVP_PKEY_free(key);
			OSSL_Raise(eSSLError, "SSL_CTX_check_private_key:");
		}
	}

	/*
	 * Free cert, key (Used => Safe to FREE || Not used => Not needed)
	 */
	if (cert) X509_free(cert);
	if (key) EVP_PKEY_free(key);

	val = ssl_get_ca(self);
	ca = NIL_P(val) ? NULL : ossl_x509_get_X509(val);
	val = ssl_get_ca_file(self);
	ca_file = NIL_P(val) ? NULL : RSTRING(val)->ptr;
	val = ssl_get_ca_path(self);
	ca_path = NIL_P(val) ? NULL : RSTRING(val)->ptr;

	if (ca) {
		if (!SSL_CTX_add_client_CA(p->ctx, ca)) { /* Copies X509_NAME => FREE it. */
			X509_free(ca);
			OSSL_Raise(eSSLError, "");
		}
		X509_free(ca);
	}
	if ((!SSL_CTX_load_verify_locations(p->ctx, ca_file, ca_path) ||
			!SSL_CTX_set_default_verify_paths(p->ctx))) {
		OSSL_Warning("can't set verify locations");
	}

    val = ssl_get_verify_mode(self);
    verify_mode = NIL_P(val) ? SSL_VERIFY_NONE : NUM2INT(val);
    SSL_CTX_set_verify(p->ctx, verify_mode, ssl_verify_callback);

    val = ssl_get_timeout(self);
    if(!NIL_P(val)) SSL_CTX_set_timeout(p->ctx, NUM2LONG(val));

    val = ssl_get_verify_dep(self);
    if(!NIL_P(val)) SSL_CTX_set_verify_depth(p->ctx, NUM2LONG(val));
}

static void
ssl_setup(VALUE self)
{
    ssl_st *p;
    VALUE io;
    OpenFile *fptr;

    Data_Get_Struct(self, ssl_st, p);
    if(!p->ssl){
        io = ssl_get_io(self);
        GetOpenFile(io, fptr);
        rb_io_check_readable(fptr);
        rb_io_check_writable(fptr);
        if((p->ssl = SSL_new(p->ctx)) == NULL)
			OSSL_Raise(eSSLError, "SSL_new:");
	
        SSL_set_fd(p->ssl, fileno(fptr->f));
    }
}

static VALUE
ssl_s_new(int argc, VALUE *argv, VALUE klass)
{
    VALUE obj;
    ssl_st *p;

    obj = Data_Make_Struct(klass, ssl_st, 0, ssl_free, p);
    memset(p, 0, sizeof(ssl_st));
    if((p->ctx = SSL_CTX_new(SSLv23_method())) == NULL)
		OSSL_Raise(eSSLError, "SSL_CTX_new:");
    
    SSL_CTX_set_options(p->ctx, SSL_OP_ALL);

    rb_obj_call_init(obj, argc, argv);

    return obj;
}

static VALUE
ssl_initialize(int argc, VALUE *argv, VALUE self)
{
	VALUE io, key, cert;

	switch (rb_scan_args(argc, argv, "12", &io, &cert, &key)) {
		case 3:
			if (!NIL_P(key)){
				if(TYPE(key) == T_STRING) ssl_set_key_file2(self, key);
				else{
					OSSL_Check_Type(key, cPKey);
					ssl_set_key2(self, key);
				}
			}
			/* FALLTHROUGH */
		case 2:
			if (!NIL_P(cert)){
				if(TYPE(cert) == T_STRING) ssl_set_cert_file2(self, cert);
				else{
					OSSL_Check_Type(cert, cX509Certificate);
					ssl_set_cert2(self, cert);
				}
			}
			/* FALLTHROUGH */
		case 1:
			Check_Type(io, T_FILE);
			ssl_set_io(self, io);
	}

	return self;
}

static VALUE
ssl_connect(VALUE self)
{
    ssl_st *p;

    Data_Get_Struct(self, ssl_st, p);
    ssl_ctx_setup(self);
    ssl_setup(self);

    ssl_verify_callback_proc = ssl_get_verify_cb(self);
    if(SSL_connect(p->ssl) <= 0){
		OSSL_Raise(eSSLError, "SSL_connect:");
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

    ssl_verify_callback_proc = ssl_get_verify_cb(self);
    if(SSL_accept(p->ssl) <= 0){
		OSSL_Raise(eSSLError, "SSL_accept:");
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
			OSSL_Raise(eSSLError, "SSL_read:");
	} else {
		rb_warning("SSL session is not started yet.");

		GetOpenFile(ssl_get_io(self), fptr);
		rb_io_check_readable(fptr);

		TRAP_BEG;
		nread = read(fileno(fptr->f), RSTRING(str)->ptr, RSTRING(str)->len);
		TRAP_END;

		if(nread < 0)
			rb_raise(eSSLError, "read:%s", strerror(errno));
	}

	if(nread == 0)
		rb_raise(rb_eEOFError, "End of file reached");

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
	if(TYPE(str) != T_STRING)
        str = rb_obj_as_string(str);

	if (p->ssl) {
		nwrite = SSL_write(p->ssl, RSTRING(str)->ptr, RSTRING(str)->len);
		if (nwrite < 0)
			OSSL_Raise(eSSLError, "SSL_write:");
	} else {
		rb_warning("SSL session is not started yet.");

		GetOpenFile(ssl_get_io(self), fptr);
		rb_io_check_writable(fptr);
		fp = GetWriteFile(fptr);
		nwrite = write(fileno(fp), RSTRING(str)->ptr, RSTRING(str)->len);
		if(nwrite < 0)
			rb_raise(eSSLError, "write:%s", strerror(errno));
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
	if ((cert = SSL_get_certificate(p->ssl)) == NULL) return Qnil; /* NO DUPs => DON'T FREE. */

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

	if ((cert = SSL_get_peer_certificate(p->ssl)) == NULL) /* Adds a ref => Safe to FREE. */
		return Qnil;

	obj = ossl_x509_new(cert);
	X509_free(cert);

	return obj;
}

static VALUE
ssl_cipher_to_ary(SSL_CIPHER *cipher)
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
ssl_get_ciphers(VALUE self)
{
    ssl_st *p;
    STACK_OF(SSL_CIPHER) *ciphers;
    SSL_CIPHER *cipher;
    VALUE ary;
    int i;

    Data_Get_Struct(self, ssl_st, p);
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
ssl_set_ciphers(VALUE self, VALUE v)
{
    ssl_st *p;
    VALUE str, elem;
    int i;

    Data_Get_Struct(self, ssl_st, p);
    if(!p->ctx){
        rb_raise(eSSLError, "SSL_CTX is not initialized.");
        return Qnil;
    }

    if(TYPE(v) == T_STRING) str = v;
    else if(TYPE(v) == T_ARRAY){
        str = rb_str_new2("");
        for(i = 0; i < RARRAY(v)->len; i++){
            elem = rb_ary_entry(v, i);
            if(TYPE(elem) == T_ARRAY) elem = rb_ary_entry(elem, 0);
            elem = rb_obj_as_string(elem);
            rb_str_append(str, elem);
            if(i < RARRAY(v)->len-1) rb_str_cat2(str, ":");
        }
    }
    else str = rb_obj_as_string(v);

	if(!SSL_CTX_set_cipher_list(p->ctx, RSTRING(str)->ptr)) {
		OSSL_Raise(eSSLError, "SSL_CTX_set_ciphers:");
	}
	return Qnil;
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

static VALUE
ssl_set_cert2(VALUE self, VALUE v)
{
	if(!NIL_P(v)) OSSL_Check_Type(v, cX509Certificate);
	ssl_set_cert(self, v);
	ssl_set_cert_file(self, Qnil);
	return v;
}

static VALUE
ssl_set_cert_file2(VALUE self, VALUE v)
{
	VALUE cert;
	cert = NIL_P(v) ? Qnil :ossl_x509_new_from_file(v);
	ssl_set_cert(self, cert);
	ssl_set_cert_file(self, v);
	return v;
}

static VALUE
ssl_set_key2(VALUE self, VALUE v)
{
	if(!NIL_P(v)) OSSL_Check_Type(v, cPKey);
	ssl_set_key(self, v);
	ssl_set_key_file(self, Qnil);
	return v;
}

static VALUE
ssl_set_key_file2(VALUE self, VALUE v)
{
	VALUE key;
	key = NIL_P(v) ? Qnil : ossl_pkey_new_from_file(v);
	ssl_set_key(self, key);
	ssl_set_key_file(self, v);
	return v;
}

void
Init_ssl(VALUE module)
{
    int i;

    /* class SSLError */
    eSSLError = rb_define_class_under(module, "Error", rb_eStandardError);

    /* class SSLSocket */
    cSSLSocket = rb_define_class_under(module, "SSLSocket", rb_cObject);
    rb_define_singleton_method(cSSLSocket, "new", ssl_s_new, -1);
    rb_define_method(cSSLSocket, "initialize",   ssl_initialize, -1);
    rb_define_method(cSSLSocket, "__connect",    ssl_connect, 0);
    rb_define_method(cSSLSocket, "__accept",     ssl_accept, 0);
    rb_define_method(cSSLSocket, "sysread",      ssl_read, 1);
    rb_define_method(cSSLSocket, "syswrite",     ssl_write, 1);
    rb_define_method(cSSLSocket, "sysclose",     ssl_close, 0);
    rb_define_method(cSSLSocket, "cert",         ssl_get_certificate, 0);
    rb_define_method(cSSLSocket, "peer_cert",    ssl_get_peer_certificate, 0);
    rb_define_method(cSSLSocket, "cipher",       ssl_get_cipher, 0);
    rb_define_method(cSSLSocket, "ciphers",      ssl_get_ciphers, 0);
    rb_define_method(cSSLSocket, "ciphers=",     ssl_set_ciphers, 1);
    rb_define_method(cSSLSocket, "state",        ssl_get_state, 0);
    rb_define_method(cSSLSocket, "cert=",        ssl_set_cert2, 1);
    rb_define_method(cSSLSocket, "cert_file=",   ssl_set_cert_file2, 1);
    rb_define_method(cSSLSocket, "key=",         ssl_set_key2, 1);
    rb_define_method(cSSLSocket, "key_file=",    ssl_set_key_file2, 1);
    for(i = 0; i < numberof(ssl_attrs); i++)
        rb_attr(cSSLSocket, rb_intern(ssl_attrs[i]), 1, 1, Qfalse);
    for(i = 0; i < numberof(ssl_attr_readers); i++)
        rb_attr(cSSLSocket, rb_intern(ssl_attr_readers[i]), 1, 0, Qfalse);
    rb_define_alias(cSSLSocket, "to_io", "io");

#define ssl_def_const(x) rb_define_const(module, #x, INT2FIX(SSL_##x))

    ssl_def_const(VERIFY_NONE);
    ssl_def_const(VERIFY_PEER);
    ssl_def_const(VERIFY_FAIL_IF_NO_PEER_CERT);
    ssl_def_const(VERIFY_CLIENT_ONCE);
}

