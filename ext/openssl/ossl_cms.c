/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2017 Ruby/OpenSSL Project Authors
 */
#include "ossl.h"
#include "ossl_cms_internal.h"

#ifndef OPENSSL_NO_CMS

VALUE cCMS, cCMSRecipientInfo;
VALUE eCMSError;
static ID id_content, id_parent_ref;

/*
 * CMS_ContentInfo structure
 */
void
cms_free(void *ptr)
{
    CMS_ContentInfo_free(ptr);
}

const rb_data_type_t ossl_cms_type = {
    "OpenSSL/CMS_ContentInfo",
    {
        0, cms_free
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};

static VALUE
cms_alloc(VALUE klass)
{
    return TypedData_Wrap_Struct(klass, &ossl_cms_type, 0);
}

/*
 * Returns if the CMS structure is finalized or not.
 */
int
ossl_cms_is_finalized(VALUE obj)
{
    return rb_attr_get(obj, id_content) == Qfalse;
}

/*
 * Set the content. The value will be passed to CMS_final().
 */
void
ossl_cms_set_content(VALUE obj, VALUE data)
{
    if (!NIL_P(data))
        StringValue(data);
    rb_ivar_set(obj, id_content, data);
}

/*
 * call-seq:
 *    CMS.read(encoded) -> CMS::*
 *
 * Creates a new instance of CMS. If a String is given, it will be read as
 * a DER or PEM representation of CMS structure.
 */
static VALUE
cms_s_read(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms;
    BIO *in, *in_cont = NULL;
    VALUE obj, arg, klass;
    int state;

    rb_scan_args(argc, argv, "1", &arg);
    arg = ossl_to_der_if_possible(arg);
    in = ossl_obj2bio(&arg);
    cms = d2i_CMS_bio(in, NULL);
    if (!cms) {
        OSSL_BIO_reset(in);
        cms = PEM_read_bio_CMS(in, NULL, NULL, NULL);
    }
    if (!cms) {
        OSSL_BIO_reset(in);
        cms = SMIME_read_CMS(in, &in_cont);
    }
    BIO_free(in);
    if (in_cont) {
        rb_warn("notimpl: SMIME with cleartext");
        BIO_free(in_cont);
    }
    if (!cms)
        ossl_raise(eCMSError, "could not parse CMS");

    switch (OBJ_obj2nid(CMS_get0_type(cms))) {
      case NID_pkcs7_data:	klass = cCMSData; break;
      case NID_pkcs7_signed:	klass = cCMSSignedData; break;
      case NID_pkcs7_enveloped:	klass = cCMSEnvelopedData; break;
      case NID_pkcs7_digest:	klass = cCMSDigestedData; break;
      case NID_pkcs7_encrypted:	klass = cCMSEncryptedData; break;
      default:			klass = cCMS; rb_warn("unknown CMS type");
    }
    obj = rb_protect(cms_alloc, klass, &state);
    if (state) {
        CMS_ContentInfo_free(cms);
        rb_jump_tag(state);
    }
    RTYPEDDATA_DATA(obj) = cms;
    /* Mark as finalized; see cms_final() */
    rb_ivar_set(obj, id_content, Qfalse);

    return obj;
}

static VALUE
cms_initialize_copy(VALUE self, VALUE other)
{
    CMS_ContentInfo *cms = GetCMS(other), *cms_new;

    rb_check_frozen(self);
    if (RTYPEDDATA_DATA(self))
        rb_raise(eCMSError, "CMS already initialized");
    cms_new = ASN1_item_dup(ASN1_ITEM_rptr(CMS_ContentInfo), cms);
    if (!cms_new)
        ossl_raise(eCMSError, "ASN1_item_dup");
    RTYPEDDATA_DATA(self) = cms_new;
    /* Mark as finalized; see cms_final() */
    rb_ivar_set(self, id_content, Qfalse);

    return self;
}

static VALUE
cms_export_raw(int argc, VALUE *argv, VALUE self,
               int (*stream_func)(BIO *, CMS_ContentInfo *, BIO *, int))
{
    CMS_ContentInfo *cms = GetCMS(self);
    VALUE in_v, out_v, flags_v;
    BIO *in = NULL, *out;
    int state, flags = 0;

    if (!ossl_cms_is_finalized(self))
        rb_raise(rb_eArgError, "CMS not finalized yet");

    rb_scan_args(argc, argv, "03", &out_v, &in_v, &flags_v);
    if (!NIL_P(flags_v))
        flags = NUM2UINT(flags_v);

    if (!NIL_P(out_v)) {
        out = ossl_obj2bio_writable(out_v);
    }
    else {
        out = BIO_new(BIO_s_mem());
        if (!out)
            ossl_raise(eCMSError, "BIO_new");
    }

    if (!NIL_P(in_v)) {
        in = (BIO *)rb_protect((VALUE(*)(VALUE))ossl_obj2bio, in_v, &state);
        if (state) {
            BIO_free(out);
            rb_jump_tag(state);
        }
    }

    if (!stream_func(out, cms, in, flags)) {
        BIO_free(in);
        BIO_free(out);
        ossl_raise(eCMSError, "can't export CMS");
    }
    BIO_free(in);

    if (!NIL_P(out_v)) {
        BIO_free(out);
        return out_v;
    }
    return ossl_membio2str(out);
}

/*
 * call-seq:
 *   cms.to_der -> aString
 */
static VALUE
cms_to_der(int argc, VALUE *argv, VALUE self)
{
    return cms_export_raw(argc, argv, self, i2d_CMS_bio_stream);
}

/*
 * call-seq:
 *   cms.to_pem(out = nil)            -> out | String
 *   cms.to_pem(out, data, flags = 0) -> out
 *
 * Outputs the data in PEM format to +out+ or a new String. +out+ must be an IO.
 */
static VALUE
cms_to_pem(int argc, VALUE *argv, VALUE self)
{
    return cms_export_raw(argc, argv, self, PEM_write_bio_CMS_stream);
}

/*
 * call-seq:
 *   cms.to_smime(out = nil) -> String | IO
 */
static VALUE
cms_to_smime(int argc, VALUE *argv, VALUE self)
{
    return cms_export_raw(argc, argv, self, SMIME_write_CMS);
}

/*
 * call-seq:
 *   cms.type -> string
 *
 * Returns the content type of the CMS structure. A type is represented in the
 * form of sn (short name).
 */
static VALUE
cms_get_type(VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    const ASN1_OBJECT *asn1obj;
    int nid;

    asn1obj = CMS_get0_type(cms);
    nid = OBJ_obj2nid(asn1obj);

    return rb_str_new2(OBJ_nid2sn(nid));
}

/*
 * call-seq:
 *   cms.detached = true | false
 *
 * Sets if the data should be detached or not.
 */
static VALUE
cms_set_detached(VALUE self, VALUE value)
{
    CMS_ContentInfo *cms = GetCMS(self);

    CMS_set_detached(cms, RTEST(value));

    return value;
}

/*
 * call-seq:
 *   cms.detached? -> true | false
 *
 * Returns true if the content type of the CMS structure is SignedData and also
 * the data is detached, false otherwise.
 */
static VALUE
cms_is_detached(VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);

    return CMS_is_detached(cms) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   cms.final(flags = 0) -> self
 *
 * Finalizes the CMS ContentInfo structure. Note #to_der, #to_pem and #to_smime
 * call this implicitly if the object is not finalized yet.
 *
 * TODO: convert flags to kwargs
 * TODO: Streaming input/output
 */
static VALUE
cms_final(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    VALUE data_v, flags_v;
    BIO *data;
    unsigned flags = 0;

    rb_scan_args(argc, argv, "01", &flags_v);
    rb_check_frozen(self);
    data_v = rb_attr_get(self, id_content);
    if (data_v == Qfalse)
        rb_raise(eCMSError, "CMS already finalized");

    if (!NIL_P(flags_v))
        flags = NUM2UINT(flags_v);
    data = ossl_obj2bio(&data_v);

    if (!CMS_final(cms, data, NULL, flags)) {
        BIO_free(data);
        ossl_raise(eCMSError, "CMS_final");
    }
    BIO_free(data);
    rb_ivar_set(self, id_content, Qfalse); /* mark as finalized */

    return self;
}

/*
 * call-seq:
 *   cms.content -> String | nil
 *
 * Returns the encapsulated content, or nil if the content is detached.
 *
 */
static VALUE
cms_get_content(VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    ASN1_OCTET_STRING **asn1string;

    asn1string = CMS_get0_content(cms);
    if (!asn1string)
        ossl_raise(eCMSError, "CMS_get0_content");

    /* detached */
    if (!*asn1string)
        return Qnil;

    /* not detached, but not read in */
    if ((*asn1string)->flags & ASN1_STRING_FLAG_CONT)
        return Qnil;

    return rb_str_new((char *)(*asn1string)->data, (*asn1string)->length);
}

/*
 * call-seq:
 *   cms.certificates -> aArray
 *
 * Returns all certificates included in the CMS structure.
 */
VALUE
ossl_cms_get_certificates(VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    STACK_OF(X509) *certs;
    VALUE ret;
    int state;

    certs = CMS_get1_certs(cms);
    if (!certs) {
        /* No certs or a malloc error occurs. There is no way to distinguish */
        return rb_ary_new();
    }

    ret = rb_protect((VALUE (*)(VALUE))ossl_x509_sk2ary, (VALUE)certs, &state);
    sk_X509_pop_free(certs, X509_free);
    if (state)
        rb_jump_tag(state);

    return ret;
}

/*
 * Document-method: OpenSSL::CMS::SignedData#add_certificate
 * Document-method: OpenSSL::CMS::EnvelopedData#add_certificate
 *
 * call-seq:
 *   cms.add_certificate(cert) -> self
 *
 * Adds a certificate to the CMS structure. The content type of the CMS structure
 * must be either SignedData or EnvelopedData.
 */
VALUE
ossl_cms_add_certificate(VALUE self, VALUE value)
{
    CMS_ContentInfo *cms = GetCMS(self);
    X509 *cert;

    cert = GetX509CertPtr(value);

    if (!CMS_add1_cert(cms, cert))
        ossl_raise(eCMSError, "CMS_add1_cert");

    return self;
}

/*
 * Document-method: OpenSSL::CMS::SignedData#crls
 * Document-method: OpenSSL::CMS::EnvelopedData#crls
 *
 * call-seq:
 *   cms.crls -> aArray
 *
 * Returns all CRLs in the CMS structure. The content type of the CMS structure
 * must be either SignedData or EnvelopedData.
 */
VALUE
ossl_cms_get_crls(VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    STACK_OF(X509_CRL) *crls;
    VALUE ret;
    int state;

    crls = CMS_get1_crls(cms);
    if (!crls) {
        /* The same as cms_get_certificates() */
        return rb_ary_new();
    }

    ret = rb_protect((VALUE (*)(VALUE))ossl_x509crl_sk2ary, (VALUE)crls, &state);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    if (state)
        rb_jump_tag(state);

    return ret;
}

/*
 * Document-method: OpenSSL::CMS::SignedData#add_crl
 * Document-method: OpenSSL::CMS::EnvelopedData#add_crl
 *
 * call-seq:
 *   cms.add_crl(crl) -> self
 *
 * Adds a CRL to the CMS structure. The content type of the CMS structure
 * must be either SignedData or EnvelopedData.
 */
VALUE
ossl_cms_add_crl(VALUE self, VALUE value)
{
    CMS_ContentInfo *cms = GetCMS(self);
    X509_CRL *crl;

    crl = GetX509CRLPtr(value);

    if (!CMS_add1_crl(cms, crl))
        ossl_raise(eCMSError, "CMS_add1_crl");

    return self;
}

/*
 * CMS_RecipientInfo structure
 */
const rb_data_type_t ossl_cms_ri_type = {
    "OpenSSL/CMS_RecipientInfo",
    {
        /* CMS_RecipientInfo is not free'd. */
        0, 0,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};

VALUE
ossl_cms_ri_new0(CMS_RecipientInfo *recipient_info, VALUE parent)
{
    VALUE obj;

    obj = TypedData_Wrap_Struct(cCMSRecipientInfo, &ossl_cms_ri_type, 0);
    rb_ivar_set(obj, id_parent_ref, parent);
    RTYPEDDATA_DATA(obj) = recipient_info;

    return obj;
}

/*
 * call-seq:
 *   recipient_info.type -> symbol
 *
 * TODO: symbol?
 */
static VALUE
ri_get_type(VALUE self)
{
    CMS_RecipientInfo *ri = GetCMSRecipientInfo(self);

    switch (CMS_RecipientInfo_type(ri)) {
      case CMS_RECIPINFO_TRANS:
        return ID2SYM(rb_intern("key_transport"));
      case CMS_RECIPINFO_AGREE:
        return ID2SYM(rb_intern("key_agreement"));
      case CMS_RECIPINFO_KEK:
        return ID2SYM(rb_intern("key_encryption_keys"));
      case CMS_RECIPINFO_PASS:
        return ID2SYM(rb_intern("password"));
      case CMS_RECIPINFO_OTHER:
        return ID2SYM(rb_intern("other"));
      default:
        rb_raise(eCMSError, "unknown RecipientInfo type");
    }
}

/*
 * call-seq:
 *   recipient_info.recipient_certificate
 */
static VALUE
ri_get_recip_cert(VALUE self)
{
    CMS_RecipientInfo *ri = GetCMSRecipientInfo(self);
    X509 *cert;

    switch (CMS_RecipientInfo_type(ri)) {
      case CMS_RECIPINFO_TRANS:
        if (!CMS_RecipientInfo_ktri_get0_algs(ri, NULL, &cert, NULL))
            ossl_raise(eCMSError, "CMS_RecipientInfo_ktri_get0_algs");
        break;
      default:
        rb_raise(eCMSError, "RecipientInfo does not have a certificate");
    }

    return ossl_x509_new(cert);
}

void
Init_ossl_cms(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
#endif

    id_content = rb_intern_const("content");
    id_parent_ref = rb_intern_const("parent_ref");

    /*
     * Document-class: OpenSSL::CMS
     *
     * Implementation of Cryptographic Message Syntax (CMS) as specified in
     * RFC 5652. It is a syntax for data protection. The syntax allows multiple
     * forms of encapsulation; digitally signed, enveloped, digested, encrypted,
     * and authenticated message content. It also allows arbitrary attributes.
     *
     * CMS defines six content types:
     *
     * data::
     *   Indended to contain arbitrary octet strings. This is usually
     *   encapsulated in the signed-data, enveloped-data, digested-data,
     *   encrypted-data, or authenticated-data.
     * signed-data::
     *   Consists of a content of any type and any number of signatures.
     * enveloped-data::
     *   Consists of an encrypted content of any type and encrypted
     *   content-encryption for one or more recipients.
     * digested-data::
     *   Consists of a content of any type and a message digest of the content.
     * encrypted-data::
     *   Consists of an encrypted content of any type. Unline the enveloped-data
     *   content type, encrypted-data has neither recipients nor encrypted
     *   content-encryption keys. So keys must be managed by other means.
     * authenticated-data::
     *   Consists of a content of any type, a message authentication code (MAC),
     *   and encrypted authentication keys for one or more recipients.
     *   (not implemented)
     *
     * === Streaming IO
     *
     * OpenSSL::CMS supports streaming IO. Streaming IO allows encrypting a
     * large data that can't be handled on-memory.
     */
    cCMS = rb_define_class_under(mOSSL, "CMS", rb_cObject);
    eCMSError = rb_define_class_under(cCMS, "CMSError", eOSSLError);
    rb_define_alloc_func(cCMS, cms_alloc);
    rb_define_method(cCMS, "initialize_copy", cms_initialize_copy, 1);
    rb_define_singleton_method(cCMS, "read", cms_s_read, -1);
    rb_define_method(cCMS, "type", cms_get_type, 0);
    rb_define_method(cCMS, "to_der", cms_to_der, -1);
    rb_define_method(cCMS, "to_pem", cms_to_pem, -1);
    rb_define_method(cCMS, "to_smime", cms_to_smime, -1);

    rb_define_method(cCMS, "detached=", cms_set_detached, 1);
    rb_define_method(cCMS, "detached?", cms_is_detached, 0);
    rb_define_method(cCMS, "final", cms_final, -1);
    rb_define_method(cCMS, "content", cms_get_content, 0);

    /*
     * Document-class: OpenSSL::CMS::RecipientInfo
     */
    cCMSRecipientInfo = rb_define_class_under(cCMS, "RecipientInfo", rb_cObject);
    rb_undef_alloc_func(cCMSRecipientInfo);
    rb_define_method(cCMSRecipientInfo, "type", ri_get_type, 0);
    rb_define_method(cCMSRecipientInfo, "recipient_certificate", ri_get_recip_cert, 0);

    rb_define_const(cCMS, "TEXT", UINT2NUM(CMS_TEXT));
    rb_define_const(cCMS, "NOCERTS", UINT2NUM(CMS_NOCERTS));
    rb_define_const(cCMS, "NO_CONTENT_VERIFY", UINT2NUM(CMS_NO_CONTENT_VERIFY));
    rb_define_const(cCMS, "NO_ATTR_VERIFY", UINT2NUM(CMS_NO_ATTR_VERIFY));
    rb_define_const(cCMS, "NOSIGS", UINT2NUM(CMS_NOSIGS));
    rb_define_const(cCMS, "NOINTERN", UINT2NUM(CMS_NOINTERN));
    rb_define_const(cCMS, "NO_SIGNER_CERT_VERIFY", UINT2NUM(CMS_NO_SIGNER_CERT_VERIFY));
    rb_define_const(cCMS, "NOVERIFY", UINT2NUM(CMS_NOVERIFY));
    rb_define_const(cCMS, "DETACHED", UINT2NUM(CMS_DETACHED));
    rb_define_const(cCMS, "BINARY", UINT2NUM(CMS_BINARY));
    rb_define_const(cCMS, "NOATTR", UINT2NUM(CMS_NOATTR));
    rb_define_const(cCMS, "NOSMIMECAP", UINT2NUM(CMS_NOSMIMECAP));
    rb_define_const(cCMS, "NOOLDMIMETYPE", UINT2NUM(CMS_NOOLDMIMETYPE));
    rb_define_const(cCMS, "CRLFEOL", UINT2NUM(CMS_CRLFEOL));
    rb_define_const(cCMS, "STREAM", UINT2NUM(CMS_STREAM));
    rb_define_const(cCMS, "NOCRL", UINT2NUM(CMS_NOCRL));
    rb_define_const(cCMS, "REUSE_DIGEST", UINT2NUM(CMS_REUSE_DIGEST));
    rb_define_const(cCMS, "USE_KEYID", UINT2NUM(CMS_USE_KEYID));
    rb_define_const(cCMS, "DEBUG_DECRYPT", UINT2NUM(CMS_DEBUG_DECRYPT));
#if defined(CMS_KEY_PARAM)
    rb_define_const(cCMS, "KEY_PARAM", UINT2NUM(CMS_KEY_PARAM));
#endif
#if defined(CMS_ASCIICRLF)
    rb_define_const(cCMS, "ASCIICRLF", UINT2NUM(CMS_ASCIICRLF));
#endif

    Init_ossl_cms_data();
    Init_ossl_cms_signed_data();
    Init_ossl_cms_enveloped_data();
    Init_ossl_cms_digested_data();
    Init_ossl_cms_encrypted_data();
    /* authenticated-data not implemented */
}
#endif
