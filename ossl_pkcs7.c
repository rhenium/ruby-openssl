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

#define WrapPKCS7(klass, obj, pkcs7) do { \
    if (!pkcs7) { \
	ossl_raise(rb_eRuntimeError, "PKCS7 wasn't initialized."); \
    } \
    obj = Data_Wrap_Struct(klass, 0, PKCS7_free, pkcs7); \
} while (0)
#define GetPKCS7(obj, pkcs7) do { \
    Data_Get_Struct(obj, PKCS7, pkcs7); \
    if (!pkcs7) { \
	ossl_raise(rb_eRuntimeError, "PKCS7 wasn't initialized."); \
    } \
} while (0)
#define SafeGetPKCS7(obj, pkcs7) do { \
    OSSL_Check_Kind(obj, cPKCS7); \
    GetPKCS7(obj, pkcs7); \
} while (0)

#define WrapPKCS7si(klass, obj, p7si) do { \
    if (!p7si) { \
	ossl_raise(rb_eRuntimeError, "PKCS7si wasn't initialized."); \
    } \
    obj = Data_Wrap_Struct(klass, 0, PKCS7_SIGNER_INFO_free, p7si); \
} while (0)
#define GetPKCS7si(obj, p7si) do { \
    Data_Get_Struct(obj, PKCS7_SIGNER_INFO, p7si); \
    if (!p7si) { \
	ossl_raise(rb_eRuntimeError, "PKCS7si wasn't initialized."); \
    } \
} while (0)
#define SafeGetPKCS7si(obj, p7si) do { \
    OSSL_Check_Kind(obj, cPKCS7Signer); \
    GetPKCS7si(obj, p7si); \
} while (0)

#define numberof(ary) (sizeof(ary)/sizeof(ary[0]))

#define ossl_pkcs7_set_data(o,v)       rb_iv_set((o), "@data", (v))
#define ossl_pkcs7_get_data(o)         rb_iv_get((o), "@data")
#define ossl_pkcs7_set_err_string(o,v) rb_iv_set((o), "@error_string", (v))
#define ossl_pkcs7_get_err_string(o)   rb_iv_get((o), "@error_string")

/* 
 * Classes
 */
VALUE mPKCS7;
VALUE cPKCS7;
VALUE cPKCS7Signer;
VALUE ePKCS7Error;

/*
 * Public
 * (MADE PRIVATE UNTIL SOMEBODY WILL NEED THEM)
 */
static VALUE
ossl_pkcs7si_new(PKCS7_SIGNER_INFO *p7si)
{
    PKCS7_SIGNER_INFO *pkcs7;
    VALUE obj;

    pkcs7 = p7si ? PKCS7_SIGNER_INFO_dup(p7si) : PKCS7_SIGNER_INFO_new();
    if (!pkcs7) ossl_raise(ePKCS7Error, "");
    WrapPKCS7si(cPKCS7Signer, obj, pkcs7);

    return obj;
}

static PKCS7_SIGNER_INFO *
DupPKCS7SignerPtr(VALUE obj)
{
    PKCS7_SIGNER_INFO *p7si, *pkcs7;
	
    SafeGetPKCS7si(obj, p7si);
    if (!(pkcs7 = PKCS7_SIGNER_INFO_dup(p7si))) {
	ossl_raise(ePKCS7Error, "");
    }

    return pkcs7;
}

/*
 * Private
 */
static VALUE
ossl_pkcs7_s_read_smime(VALUE klass, VALUE arg)
{
    BIO *in, *out;
    PKCS7 *pkcs7;
    VALUE ret, data;
    int status;

    in = ossl_obj2bio(arg);
    out = NULL;
    if((pkcs7 = SMIME_read_PKCS7(in, &out)) == NULL){
	BIO_free(in);
	BIO_free(out);
	ossl_raise(ePKCS7Error, NULL);
    }
    if(out) data = ossl_protect_membio2str(out, &status);
    else data = Qnil;
    BIO_free(in);
    BIO_free(out);
    if(status) rb_jump_tag(status);
    WrapPKCS7(cPKCS7, ret, pkcs7);
    ossl_pkcs7_set_data(ret, data);
    ossl_pkcs7_set_err_string(ret, Qnil);

    return ret;
}

static VALUE
ossl_pkcs7_s_write_smime(int argc, VALUE *argv, VALUE klass)
{
    VALUE pkcs7, data, flags;
    BIO *out;
    BIO *in;
    PKCS7 *p7;
    VALUE str;
    int flg, status;

    rb_scan_args(argc, argv, "12", &pkcs7, &data, &flags);
    SafeGetPKCS7(pkcs7, p7);
    flg = NIL_P(flags) ? 0 : NUM2INT(flags);
    if(NIL_P(data)) data = ossl_pkcs7_get_data(pkcs7);
    in = NIL_P(data) ? NULL : ossl_obj2bio(data);
    if(!(out = BIO_new(BIO_s_mem()))){
        BIO_free(in);
        ossl_raise(ePKCS7Error, NULL);
    }
    if(!SMIME_write_PKCS7(out, p7, in, flg)){
        BIO_free(out);
        BIO_free(in);
        ossl_raise(ePKCS7Error, NULL);
    }
    str = ossl_protect_membio2str(out, &status);
    BIO_free(in);
    BIO_free(out);
    if(status) rb_jump_tag(status);

    return str;
}

static VALUE
ossl_pkcs7_s_sign(int argc, VALUE *argv, VALUE klass)
{
    VALUE cert, key, data, certs, flags;
    X509 *x509;
    EVP_PKEY *pkey;
    BIO *in;
    STACK_OF(X509) *x509s;
    int flg, status;
    PKCS7 *pkcs7;
    VALUE ret;

    rb_scan_args(argc, argv, "32", &cert, &key, &data, &certs, &flags);
    x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
    pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
    flg = NIL_P(flags) ? 0 : NUM2INT(flags);
    in = ossl_obj2bio(data);
    if(NIL_P(certs)) x509s = NULL;
    else{
	x509s = ossl_protect_x509_ary2sk(certs, &status);
	if(status){
	    BIO_free(in);
	    rb_jump_tag(status);
	}
    }
    if(!(pkcs7 = PKCS7_sign(x509, pkey, x509s, in, flg))){
	BIO_free(in);
	sk_X509_pop_free(x509s, X509_free);
	ossl_raise(ePKCS7Error, NULL);
    }
    WrapPKCS7(cPKCS7, ret, pkcs7);
    ossl_pkcs7_set_data(ret, data);
    ossl_pkcs7_set_err_string(ret, Qnil);
    BIO_free(in);
    sk_X509_pop_free(x509s, X509_free);

    return ret;
}

static VALUE
ossl_pkcs7_s_encrypt(int argc, VALUE *argv, VALUE klass)
{
    VALUE certs, data, cipher, flags;
    STACK_OF(X509) *x509s;
    BIO *in;
    const EVP_CIPHER *ciph;
    int flg, status;
    VALUE ret;
    PKCS7 *p7;

    rb_scan_args(argc, argv, "31", &certs, &data, &cipher, &flags);
    ciph = GetCipherPtr(cipher); /* NO NEED TO DUP */
    in = ossl_obj2bio(data);
    x509s = ossl_protect_x509_ary2sk(certs, &status);
    if(status){
	BIO_free(in);
	rb_jump_tag(status);
    }
    if(!(p7 = PKCS7_encrypt(x509s, in, ciph, flg))){
	BIO_free(in);
	sk_X509_pop_free(x509s, X509_free);
	ossl_raise(ePKCS7Error, NULL);
    }
    WrapPKCS7(cPKCS7, ret, p7);
    ossl_pkcs7_set_data(ret, data);
    BIO_free(in);
    sk_X509_pop_free(x509s, X509_free);

    return ret;
}

static VALUE
ossl_pkcs7_alloc(VALUE klass)
{
    PKCS7 *pkcs7;
    VALUE obj;

    if (!(pkcs7 = PKCS7_new())) {
	ossl_raise(ePKCS7Error, "");
    }
    WrapPKCS7(klass, obj, pkcs7);
    
    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_pkcs7_alloc)

static VALUE
ossl_pkcs7_initialize(int argc, VALUE *argv, VALUE self)
{
    PKCS7 *pkcs7;
    BIO *in;
    VALUE s;

    if(rb_scan_args(argc, argv, "01", &s) == 0)
	return self;
    StringValue(s);
    if (!(in = BIO_new_mem_buf(RSTRING(s)->ptr, RSTRING(s)->len)))
	ossl_raise(ePKCS7Error, "");
    if (!PEM_read_bio_PKCS7(in, (PKCS7 **)&DATA_PTR(self), NULL, NULL)) {
	BIO_free(in);
	ossl_raise(ePKCS7Error, "");
    }
    BIO_free(in);
    ossl_pkcs7_set_data(self, Qnil);
    ossl_pkcs7_set_err_string(self, Qnil);

    return self;
}

static VALUE
ossl_pkcs7_copy(VALUE self, VALUE other)
{
    PKCS7 *a, *b, *pkcs7;

    rb_check_frozen(self);
    if (self == other) return self;

    GetPKCS7(self, a);
    SafeGetPKCS7(other, b);

    pkcs7 = PKCS7_dup(b);
    if (!pkcs7) {
	ossl_raise(ePKCS7Error, "");
    }
    DATA_PTR(self) = pkcs7;
    PKCS7_free(a);

    return self;
}

static int
ossl_pkcs7_sym2typeid(VALUE sym)
{
    int i, ret;
    char *s;

    static struct {
        const char *name;
        int nid;
    } p7_type_tab[] = {
        { "signed",             NID_pkcs7_signed },
        { "data",               NID_pkcs7_data },
        { "signedAndEnveloped", NID_pkcs7_signedAndEnveloped },
        { "enveloped",          NID_pkcs7_enveloped },
        { "encrypted",          NID_pkcs7_encrypted },
        { "digest",             NID_pkcs7_digest },
        { NULL,                 0 },
    };

    if(TYPE(sym) == T_SYMBOL) s = rb_id2name(SYM2ID(sym));
    else s = StringValuePtr(sym);
    for(i = 0; i < numberof(p7_type_tab); i++){
	if(p7_type_tab[i].name == NULL)
	    ossl_raise(ePKCS7Error, "unknown type \"%s\"", s);
	if(strcmp(p7_type_tab[i].name, s) == 0){
	    ret = p7_type_tab[i].nid;
	    break;
	}
    }

    return ret;
}

static VALUE
ossl_pkcs7_set_type(VALUE self, VALUE type)
{
    PKCS7 *p7;

    GetPKCS7(self, p7);
    if(!PKCS7_set_type(p7, ossl_pkcs7_sym2typeid(type)))
	ossl_raise(ePKCS7Error, NULL);

    return type;
}

static VALUE
ossl_pkcs7_get_type(VALUE self)
{
    PKCS7 *p7;

    GetPKCS7(self, p7);
    if(PKCS7_type_is_signed(p7))
	return ID2SYM(rb_intern("signed"));
    if(PKCS7_type_is_encrypted(p7))
	return ID2SYM(rb_intern("encrypted"));
    if(PKCS7_type_is_enveloped(p7))
	return ID2SYM(rb_intern("enveloped"));
    if(PKCS7_type_is_signedAndEnveloped(p7))
	return ID2SYM(rb_intern("signedAndEnveloped"));
    if(PKCS7_type_is_data(p7))
	return ID2SYM(rb_intern("data"));
    return Qnil;
}

static VALUE
ossl_pkcs7_set_detached(VALUE self, VALUE flag)
{
    PKCS7 *p7;

    GetPKCS7(self, p7);
    if(flag != Qtrue && flag != Qfalse)
	ossl_raise(ePKCS7Error, "must secify a boolean");
    if(!PKCS7_set_detached(p7, flag == Qtrue ? 1 : 0))
	ossl_raise(ePKCS7Error, NULL);

    return flag;
}

static VALUE
ossl_pkcs7_get_detached(VALUE self)
{
    PKCS7 *p7;
    GetPKCS7(self, p7);
    return PKCS7_get_detached(p7) ? Qtrue : Qfalse;
}

static VALUE
ossl_pkcs7_detached_p(VALUE self)
{
    PKCS7 *p7;
    GetPKCS7(self, p7);
    return PKCS7_is_detached(p7) ? Qtrue : Qfalse;
}

static VALUE
ossl_pkcs7_set_cipher(VALUE self, VALUE cipher)
{
    PKCS7 *pkcs7;

    GetPKCS7(self, pkcs7);
    if (!PKCS7_set_cipher(pkcs7, GetCipherPtr(cipher))) {
	ossl_raise(ePKCS7Error, "");
    }

    return cipher;
}

static VALUE
ossl_pkcs7_add_signer(VALUE self, VALUE signer)
{
    PKCS7 *pkcs7;
    PKCS7_SIGNER_INFO *p7si;

    GetPKCS7(self, pkcs7);
    p7si = DupPKCS7SignerPtr(signer); /* NEED TO DUP */
    if (!PKCS7_add_signer(pkcs7, p7si)) {
	PKCS7_SIGNER_INFO_free(p7si);
	ossl_raise(ePKCS7Error, "Could not add signer.");
    }
    if (PKCS7_type_is_signed(pkcs7)){
	PKCS7_add_signed_attribute(p7si, NID_pkcs9_contentType,
				   V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
    }

    return self;
}

static VALUE
ossl_pkcs7_get_signer(VALUE self)
{
    PKCS7 *pkcs7;
    STACK_OF(PKCS7_SIGNER_INFO) *sk;
    PKCS7_SIGNER_INFO *si;
    int num, i;
    VALUE ary;
    
    GetPKCS7(self, pkcs7);
    if (!(sk = PKCS7_get_signer_info(pkcs7))) {
	OSSL_Debug("OpenSSL::PKCS7#get_signer_info == NULL!");
	return rb_ary_new();
    }
    if ((num = sk_PKCS7_SIGNER_INFO_num(sk)) < 0) {
	ossl_raise(ePKCS7Error, "Negative number of signers!");
    }
    ary = rb_ary_new2(num);
    for (i=0; i<num; i++) {
	si = sk_PKCS7_SIGNER_INFO_value(sk, i);
	rb_ary_push(ary, ossl_pkcs7si_new(si));
    }

    return ary;
}

static VALUE
ossl_pkcs7_add_recipient(VALUE self, VALUE cert)
{
    PKCS7 *pkcs7;
    PKCS7_RECIP_INFO *ri;
    X509 *x509;
	
    GetPKCS7(self, pkcs7);
    x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
    if (!(ri = PKCS7_RECIP_INFO_new())) {
	ossl_raise(ePKCS7Error, "");
    }
    if (!PKCS7_RECIP_INFO_set(ri, x509)) {
	PKCS7_RECIP_INFO_free(ri);
	ossl_raise(ePKCS7Error, "");
    }
    if (!PKCS7_add_recipient_info(pkcs7, ri)) {
	PKCS7_RECIP_INFO_free(ri);
	ossl_raise(ePKCS7Error, "");
    }

    return self;
}

static VALUE
ossl_pkcs7_add_certificate(VALUE self, VALUE cert)
{
    PKCS7 *pkcs7;
    X509 *x509;

    GetPKCS7(self, pkcs7);
    x509 = GetX509CertPtr(cert);  /* NO NEED TO DUP */
    if (!PKCS7_add_certificate(pkcs7, x509)){
	ossl_raise(ePKCS7Error, "");
    }

    return self;
}

static VALUE
ossl_pkcs7_add_crl(VALUE self, VALUE crl)
{
    PKCS7 *pkcs7;
    X509_CRL *x509crl;

    GetPKCS7(self, pkcs7); /* NO DUP needed! */
    x509crl = GetX509CRLPtr(crl);
    if (!PKCS7_add_crl(pkcs7, x509crl)) {
	ossl_raise(ePKCS7Error, "");
    }

    return self;
}

static VALUE
ossl_pkcs7_verify(int argc, VALUE *argv, VALUE self)
{
    VALUE certs, store, indata, flags;
    STACK_OF(X509) *x509s;
    X509_STORE *x509st;
    int flg, ok, status;
    BIO *in, *out;
    PKCS7 *p7;
    VALUE ret, data;
    const char *msg;

    GetPKCS7(self, p7);
    rb_scan_args(argc, argv, "22", &certs, &store, &indata, &flags);
    x509st = GetX509StorePtr(store);
    flg = NIL_P(flags) ? 0 : NUM2INT(flags);
    if(NIL_P(indata)) indata = ossl_pkcs7_get_data(self);
    in = NIL_P(indata) ? NULL : ossl_obj2bio(indata);
    if(NIL_P(certs)) x509s = NULL;
    else{
	x509s = ossl_protect_x509_ary2sk(certs, &status);
	if(status){
	    BIO_free(in);
	    rb_jump_tag(status);
	}
    }
    if(!(out = BIO_new(BIO_s_mem()))){
	BIO_free(in);
	sk_X509_pop_free(x509s, X509_free);
	ossl_raise(ePKCS7Error, NULL);
    }
    ok = PKCS7_verify(p7, x509s, x509st, in, out, flg);
    msg = ERR_reason_error_string(ERR_get_error());
    ossl_pkcs7_set_err_string(self, msg ? rb_str_new2(msg) : Qnil);
    data = ossl_protect_membio2str(out, &status);
    ossl_pkcs7_set_data(self, data);
    BIO_free(in);
    BIO_free(out);
    sk_X509_pop_free(x509s, X509_free);
    if(status) rb_jump_tag(status);

    return (ok == 1) ? Qtrue : Qfalse;
}

static VALUE
ossl_pkcs7_decrypt(int argc, VALUE *argv, VALUE self)
{
    VALUE pkey, cert, flags;
    EVP_PKEY *key;
    X509 *x509;
    int flg;
    PKCS7 *p7;
    BIO *out;
    VALUE str;
    int status;

    rb_scan_args(argc, argv, "21", &pkey, &cert, &flags);
    GetPKCS7(self, p7);
    key = GetPrivPKeyPtr(pkey); /* NO NEED TO DUP */
    x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
    flg = NIL_P(flags) ? 0 : NUM2INT(flags);
    if(!(out = BIO_new(BIO_s_mem())))
	ossl_raise(ePKCS7Error, NULL);
    if(!PKCS7_decrypt(p7, key, x509, out, flg)){
	BIO_free(out);
	ossl_raise(ePKCS7Error, NULL);
    }
    str = ossl_protect_membio2str(out, &status);
    BIO_free(out);
    if(status) rb_jump_tag(status);

    return str;
}

static VALUE
ossl_pkcs7_add_data(VALUE self, VALUE data)
{
    PKCS7 *pkcs7;
    BIO *out, *in;
    char buf[4096];
    int len;

    in = out = NULL;
    GetPKCS7(self, pkcs7);
    if(PKCS7_type_is_signed(pkcs7)){
	if(!PKCS7_content_new(pkcs7, NID_pkcs7_data))
	    ossl_raise(ePKCS7Error, NULL);
    }
    in = ossl_obj2bio(data);
    if(!(out = PKCS7_dataInit(pkcs7, NULL))) goto err;
    for(;;){
	if((len = BIO_read(in, buf, sizeof(buf))) <= 0)
	    break;
	if(BIO_write(out, buf, len) != len)
	    goto err;
    }
    if(!PKCS7_dataFinal(pkcs7, out)) goto err;
    ossl_pkcs7_set_data(self, Qnil);
    
 err:
    BIO_free(out);
    BIO_free(in);
    if(ERR_peek_error()){
	ossl_raise(ePKCS7Error, NULL);
    }

    return data;
}

#if 0
static VALUE
ossl_pkcs7_data_verify(int argc, VALUE *argv, VALUE self)
{
    PKCS7 *pkcs7;
    BIO *bio, *data = NULL;
    char buf[1024 * 4];
    int i, result;
    STACK_OF(PKCS7_SIGNER_INFO) *sk;
    PKCS7_SIGNER_INFO *si;
    X509_STORE *store;
    X509_STORE_CTX ctx;
    VALUE x509store, detached;
	
    GetPKCS7(self, pkcs7);
    if (!PKCS7_type_is_signed(pkcs7)) {
	ossl_raise(ePKCS7Error, "Wrong content type - PKCS7 is not SIGNED");
    }
    rb_scan_args(argc, argv, "11", &x509store, &detached);
    store = GetX509StorePtr(x509store);
    if (!NIL_P(detached)) {
	StringValue(detached);
	data = BIO_new_mem_buf(RSTRING(detached)->ptr, RSTRING(detached)->len);
	if(!data){
	    ossl_raise(ePKCS7Error, "");
	}
    }
	
    if (PKCS7_get_detached(pkcs7)) {
	if (!data) {
	    ossl_raise(ePKCS7Error, "PKCS7 is detached, data needed!");
	}
	bio = PKCS7_dataInit(pkcs7, data);
    } else {
	bio = PKCS7_dataInit(pkcs7, NULL);
    }
    if (!bio) {
	if (data) {
	    BIO_free(data);
	}
	ossl_raise(ePKCS7Error, "");
    }

    /* We have to 'read' from bio to calculate digests etc. */
    for (;;) {
	i = BIO_read(bio, buf, sizeof(buf));
	if (i <= 0) break;
    }
    /* BIO_free(bio); - shall we? */

    if (!(sk = PKCS7_get_signer_info(pkcs7))) {
	ossl_raise(ePKCS7Error, "NO SIGNATURES ON THIS DATA");
    }
    for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++) {
	si = sk_PKCS7_SIGNER_INFO_value(sk, i);
	result = PKCS7_dataVerify(store, &ctx, bio, pkcs7, si);
	if (result <= 0) {
	    OSSL_Debug("result < 0! (%s)", OSSL_ErrMsg());
	    return Qfalse;
	}
	/* Yield signer info */
	if (rb_block_given_p()) {
	    rb_yield(ossl_pkcs7si_new(si));
	}
    }
    
    return Qtrue;
}

static VALUE
ossl_pkcs7_data_decode(VALUE self, VALUE key, VALUE cert)
{
    PKCS7 *pkcs7;
    EVP_PKEY *pkey;
    X509 *x509;
    BIO *bio;
    VALUE str;
    int status;
	
    GetPKCS7(self, pkcs7);
    pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
    x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
    if (!(bio = PKCS7_dataDecode(pkcs7, pkey, NULL, x509))) {
	X509_free(x509);
	ossl_raise(ePKCS7Error, NULL);
    }
    X509_free(x509);
    str = ossl_protect_membio2str(bio, &status);
    BIO_free(bio);
    if(status) rb_jump_tag(status);
    
    return str;
}
#endif

static VALUE
ossl_pkcs7_to_pem(VALUE self)
{
    PKCS7 *pkcs7;
    BIO *out;
    VALUE str;
    int status;
	
    GetPKCS7(self, pkcs7);
    if (!(out = BIO_new(BIO_s_mem()))) {
	ossl_raise(ePKCS7Error, "");
    }
    if (!PEM_write_bio_PKCS7(out, pkcs7)) {
	BIO_free(out);
	ossl_raise(ePKCS7Error, "");
    }
    str = ossl_protect_membio2str(out, &status);
    BIO_free(out);
    if(status) rb_jump_tag(status);
	
    return str;
}

/*
 * SIGNER INFO
 */
static VALUE
ossl_pkcs7si_alloc(VALUE klass)
{
    PKCS7_SIGNER_INFO *p7si;
    VALUE obj;

    if (!(p7si = PKCS7_SIGNER_INFO_new())) {
	ossl_raise(ePKCS7Error, "");
    }
    WrapPKCS7si(klass, obj, p7si);

    return obj;
}
DEFINE_ALLOC_WRAPPER(ossl_pkcs7si_alloc)

static VALUE
ossl_pkcs7si_initialize(VALUE self, VALUE cert, VALUE key, VALUE digest)
{
    PKCS7_SIGNER_INFO *p7si;
    EVP_PKEY *pkey;
    X509 *x509;
    const EVP_MD *md;

    GetPKCS7si(self, p7si);
    pkey = GetPrivPKeyPtr(key); /* NO NEED TO DUP */
    x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
    md = GetDigestPtr(digest);
    if (!(PKCS7_SIGNER_INFO_set(p7si, x509, pkey, md))) {
	ossl_raise(ePKCS7Error, "");
    }

    return self;
}

static VALUE
ossl_pkcs7si_get_name(VALUE self)
{
    PKCS7_SIGNER_INFO *p7si;

    GetPKCS7si(self, p7si);

    return ossl_x509name_new(p7si->issuer_and_serial->issuer);
}

static VALUE
ossl_pkcs7si_get_serial(VALUE self)
{
    PKCS7_SIGNER_INFO *p7si;

    GetPKCS7si(self, p7si);

    return asn1integer_to_num(p7si->issuer_and_serial->serial);
}

static VALUE
ossl_pkcs7si_get_signed_time(VALUE self)
{
    PKCS7_SIGNER_INFO *p7si;
    ASN1_TYPE *asn1obj;
	
    GetPKCS7si(self, p7si);
	
    if (!(asn1obj = PKCS7_get_signed_attribute(p7si, NID_pkcs9_signingTime))) {
	ossl_raise(ePKCS7Error, "");
    }
    if (asn1obj->type == V_ASN1_UTCTIME) {
	return asn1time_to_time(asn1obj->value.utctime);
    }
    /*
     * OR
     * ossl_raise(ePKCS7Error, "...");
     * ?
     */

    return Qnil;
}

/*
 * INIT
 */
void
Init_ossl_pkcs7()
{
    mPKCS7 = rb_define_module_under(mOSSL, "PKCS7");

    ePKCS7Error = rb_define_class_under(mPKCS7, "PKCS7Error", eOSSLError);

    cPKCS7 = rb_define_class_under(mPKCS7, "PKCS7", rb_cObject);
    rb_define_singleton_method(mPKCS7, "read_smime", ossl_pkcs7_s_read_smime, 1);
    rb_define_singleton_method(mPKCS7, "write_smime", ossl_pkcs7_s_write_smime, -1);
    rb_define_singleton_method(mPKCS7, "sign",  ossl_pkcs7_s_sign, -1);
    rb_define_singleton_method(mPKCS7, "encrypt", ossl_pkcs7_s_encrypt, -1);
    rb_attr(cPKCS7, rb_intern("data"), 1, 0, Qfalse);
    rb_attr(cPKCS7, rb_intern("error_string"), 1, 1, Qfalse);
    rb_define_alloc_func(cPKCS7, ossl_pkcs7_alloc);
    rb_define_copy_func(cPKCS7, ossl_pkcs7_copy);
    rb_define_method(cPKCS7, "initialize", ossl_pkcs7_initialize, -1);
    rb_define_method(cPKCS7, "type=", ossl_pkcs7_set_type, 1);
    rb_define_method(cPKCS7, "type", ossl_pkcs7_get_type, 0);
    rb_define_method(cPKCS7, "detached=", ossl_pkcs7_set_detached, 1);
    rb_define_method(cPKCS7, "detached", ossl_pkcs7_get_detached, 0);
    rb_define_method(cPKCS7, "detached?", ossl_pkcs7_detached_p, 0);
    rb_define_method(cPKCS7, "cipher=", ossl_pkcs7_set_cipher, 1);
    rb_define_method(cPKCS7, "add_signer", ossl_pkcs7_add_signer, 1);
    rb_define_method(cPKCS7, "signer", ossl_pkcs7_get_signer, 0);
    rb_define_method(cPKCS7, "add_recipient", ossl_pkcs7_add_recipient, 1);
    rb_define_method(cPKCS7, "add_certificate", ossl_pkcs7_add_certificate, 1);
    rb_define_method(cPKCS7, "add_crl", ossl_pkcs7_add_crl, 1);
    rb_define_method(cPKCS7, "add_data", ossl_pkcs7_add_data, 1);
    rb_define_alias(cPKCS7,  "data=", "add_data");
    rb_define_method(cPKCS7, "verify", ossl_pkcs7_verify, -1);
    rb_define_method(cPKCS7, "decrypt", ossl_pkcs7_decrypt, -1);
#if 0
    rb_define_method(cPKCS7, "verify_data", ossl_pkcs7_data_verify, -1);
    rb_define_method(cPKCS7, "decode_data", ossl_pkcs7_data_decode, 2);
#endif
    rb_define_method(cPKCS7, "to_pem", ossl_pkcs7_to_pem, 0);
    rb_define_alias(cPKCS7,  "to_s", "to_pem");

    cPKCS7Signer = rb_define_class_under(mPKCS7, "Signer", rb_cObject);
    rb_define_alloc_func(cPKCS7Signer, ossl_pkcs7si_alloc);
    rb_define_method(cPKCS7Signer, "initialize", ossl_pkcs7si_initialize,3);
    rb_define_method(cPKCS7Signer, "name", ossl_pkcs7si_get_name,0);
    rb_define_method(cPKCS7Signer, "serial", ossl_pkcs7si_get_serial,0);
    rb_define_method(cPKCS7Signer, "signed_time", ossl_pkcs7si_get_signed_time,0);

#define DefPKCS7Const(x) rb_define_const(mPKCS7, #x, INT2NUM(PKCS7_##x))

    DefPKCS7Const(TEXT);
    DefPKCS7Const(NOCERTS);
    DefPKCS7Const(NOSIGS);
    DefPKCS7Const(NOCHAIN);
    DefPKCS7Const(NOINTERN);
    DefPKCS7Const(NOVERIFY);
    DefPKCS7Const(DETACHED);
    DefPKCS7Const(BINARY);
    DefPKCS7Const(NOATTR);
    DefPKCS7Const(NOSMIMECAP);
}
