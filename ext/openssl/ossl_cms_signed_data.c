/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2017 Ruby/OpenSSL Project Authors
 */
#include "ossl.h"
#include "ossl_cms_internal.h"

#ifndef OPENSSL_NO_CMS
VALUE cCMSSignedData;
static VALUE cCMSSignerInfo;
static ID id_parent_ref, id_digest, id_flags;

static VALUE si_new0(CMS_SignerInfo *, VALUE);

/*
 * call-seq:
 *    CMS::SignedData.new(data)
 *
 * Creates a new CMS structure with signed-data content type.
 */
static VALUE
signed_data_initialize(VALUE self, VALUE data)
{
    CMS_ContentInfo *cms;

    if (GetCMS0(self))
        rb_raise(eCMSError, "CMS already initialized");

    cms = CMS_ContentInfo_new();
    if (!cms)
        ossl_raise(eCMSError, "CMS_ContentInfo_new");
    if (!CMS_SignedData_init(cms)) {
        CMS_ContentInfo_free(cms);
        ossl_raise(eCMSError, "CMS_SignedData_init");
    }
    RTYPEDDATA_DATA(self) = cms;
    ossl_cms_set_content(self, data);
    return self;
}

/*
 * call-seq:
 *    cms.signers -> Array of CMS::SignerInfo
 *
 * Retrieves all SignerInfo structures included in the CMS structure.
 *
 * The returned SignerInfo structures cannot be modified.
 */
static VALUE
signed_data_get_signers(VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    STACK_OF(CMS_SignerInfo) *signer_infos;
    int i, num;
    VALUE ary;

    signer_infos = CMS_get0_SignerInfos(cms);
    if (!signer_infos)
        ossl_raise(eCMSError, "CMS_get0_SignerInfos");
    num = sk_CMS_SignerInfo_num(signer_infos);
    ary = rb_ary_new_capa(num);
    for (i = 0; i < num; i++) {
        CMS_SignerInfo *si = sk_CMS_SignerInfo_value(signer_infos, i);
        rb_ary_push(ary, si_new0(si, self));
    }
    return ary;
}

/*
 * call-seq:
 *    cms.add_signer(cert, key, digest, flags = 0) -> CMS::SignerInfo
 *
 * Adds a signer with certificate _cert_ and private key _key_, using the
 * message digest algorithm _digest_. This returns a new instance of
 * OpenSSL::CMS::SignerInfo. It can be modified to set additional attributes
 * before the CMS structure is finalized.
 *
 * This should be used when CMS.sign is not appropriate, such as when multiple
 * signers or custom attributes are needed.
 *
 * cert::
 *   OpenSSL::X509::Certificate. The certificate of the signer.
 * key::
 *   OpenSSL::PKey::PKey. The private key corresponding to the certificate.
 * digest::
 *   String or nil. The digest algorithm to be used for the signature.
 * flags::
 *   Integer. The flags for CMS_add1_signer(3) OR'ed together of:
 *
 *    - OpenSSL::CMS::REUSE_DIGEST
 *    - OpenSSL::CMS::NOCERTS
 *    - OpenSSL::CMS::NOATTR
 *    - OpenSSL::CMS::NOSMIMECAP
 *    - OpenSSL::CMS::USE_KEYID
 *
 * Example:
 *   cert = OpenSSL::X509::Certificate.new(File.read("certificate.pem"))
 *   key = OpenSSL::PKey.read(File.read("private-key.pem"))
 *
 *   cms = OpenSSL::CMS::SignedData.new(data)
 *   signer_info = cms.add_signer(cert, key, "SHA256")
 *   signer_info.signed_attributes = [
 *     OpenSSL::X509::Attribute.new("signingTime", OpenSSL::ASN1::Set.new([
 *       OpenSSL::ASN1::UTCTime.new(Time.utc(2021, 3, 31, 22, 22, 23)),
 *     ])
 *   ]
 *   File.write("signed.pem", cms.to_pem) # cms.to_pem implies cms.final
 *
 * Added in version 3.0. See also the man page CMS_add1_signer(3).
 */
static VALUE
signed_data_add_signer(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    VALUE cert, key, digest, flags_v;
    X509 *x509;
    EVP_PKEY *pkey;
    const EVP_MD *md;
    unsigned flags;
    CMS_SignerInfo *si;

    rb_scan_args(argc, argv, "31", &cert, &key, &digest, &flags_v);
    x509 = GetX509CertPtr(cert);
    pkey = GetPrivPKeyPtr(key);
    md = !NIL_P(digest) ? ossl_evp_get_digestbyname(digest) : NULL;
    flags = !NIL_P(flags_v) ? NUM2UINT(flags_v) : 0;

    si = CMS_add1_signer(cms, x509, pkey, md, flags);
    if (!si)
        ossl_raise(eCMSError, "CMS_add1_signer");

    return si_new0(si, self);
}

/*
 * call-seq:
 *    cms.verify(store, certs = [], flags: 0) -> true | false
 *
 * Verifies all the signatures in the CMS structure are valid.
 *
 * See CMS_verify(3) for possible values of +flags+.
 *
 * TODO: indata/outdata
 */
static VALUE
signed_data_verify(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *cms = GetCMS(self);
    X509_STORE *store;
    STACK_OF(X509) *certs = NULL;
    /* BIO *indata, *outdata; */
    unsigned flags = 0;
    VALUE store_v, certs_v, opts, flags_v;
    int ret;

    rb_scan_args(argc, argv, "11:", &store_v, &certs_v, &opts);
    rb_get_kwargs(opts, &id_flags, 0, 1, &flags_v);
    store = GetX509StorePtr(store_v);
    if (!NIL_P(certs_v))
        certs = ossl_x509_ary2sk(certs_v);
    if (flags_v != Qundef)
        flags = NUM2UINT(flags_v);

    ret = CMS_verify(cms, certs, store, NULL, NULL, flags);
    sk_X509_pop_free(certs, X509_free);
    if (!ret) {
        /* error or failure; how to distinguish? */
        ossl_clear_error();
        return Qfalse;
    }

    return Qtrue;
}


/*
 * OpenSSL::CMS::SignerInfo wraps CMS_SignerInfo. Since a CMS_SignerInfo is
 * always linked with a CMS_ContentInfo, we can't free it independently:
 * keep a reference of OpenSSL::CMS in CMS::SignerInfo.
 */
static const rb_data_type_t ossl_cms_si_type = {
    "OpenSSL/CMS_SignerInfo",
    {
        0, 0,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};

static inline CMS_SignerInfo *
GetCMSSignerInfo(VALUE obj)
{
    CMS_SignerInfo *si;
    TypedData_Get_Struct(obj, CMS_SignerInfo, &ossl_cms_si_type, si);
    if (!si)
        rb_raise(eCMSError, "CMSSignerInfo not initialized");
    return si;
}

static VALUE
si_new0(CMS_SignerInfo *signer_info, VALUE parent)
{
    VALUE obj;

    obj = TypedData_Wrap_Struct(cCMSSignerInfo, &ossl_cms_si_type, 0);
    rb_ivar_set(obj, id_parent_ref, parent);
    RTYPEDDATA_DATA(obj) = signer_info;

    return obj;
}

static void
si_check_modify(VALUE self)
{
    VALUE parent;

    rb_check_frozen(self);
    parent = rb_attr_get(self, id_parent_ref);
    if (ossl_cms_is_finalized(parent))
        rb_raise(eCMSError, "CMS structure is already finalized");
}

/*
 * call-seq:
 *    signer_info.subject_key_identifier -> String | nil
 *
 * Returns the subject key identifier of the signer certificate, or nil if the
 * structure uses the issuer's name and serial number instead.
 */
static VALUE
si_get_subject_key_identifier(VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    ASN1_OCTET_STRING *keyid = NULL;

    if (!CMS_SignerInfo_get0_signer_id(si, &keyid, NULL, NULL))
        ossl_raise(eCMSError, "CMS_SignerInfo_get0_signer_id");
    if (!keyid)
        return Qnil;

    return asn1str_to_str(keyid);
}

/*
 * call-seq:
 *    signer_info.issuer -> X509::Name | nil
 *
 * Returns the distinguished name of the issuer of the signer, or nil if the
 * structure uses a subject key identifier instead.
 */
static VALUE
si_get_issuer(VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    X509_NAME *name = NULL;

    if (!CMS_SignerInfo_get0_signer_id(si, NULL, &name, NULL))
        ossl_raise(eCMSError, "CMS_SignerInfo_get0_signer_id");
    if (!name)
        return Qnil;

    return ossl_x509name_new(name);
}

/*
 * call-seq:
 *    signer_info.serial -> Integer | nil
 *
 * Returns the serial number of the signer certificate, or nil if the structure
 * uses a subject key identifier instead.
 */
static VALUE
si_get_serial(VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    ASN1_INTEGER *asn1int = NULL;

    if (!CMS_SignerInfo_get0_signer_id(si, NULL, NULL, &asn1int))
        ossl_raise(eCMSError, "CMS_SignerInfo_get0_signer_id");
    if (!asn1int)
        return Qnil;

    return asn1integer_to_num(asn1int);
}

/*
 * call-seq:
 *    signer_info.signed_attributes -> Array of X509::Attribute
 *
 * Returns all the signed attributes in the SignerInfo structure.
 *
 * Modification of the returned X509::Attribute objects has no effect.
 */
static VALUE
si_get_signed_attributes(VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    int i, num = CMS_signed_get_attr_count(si);
    VALUE ary;

    if (num <= 0)
        return rb_ary_new();
    ary = rb_ary_new_capa(num);
    for (i = 0; i < num; i++)
        rb_ary_push(ary, ossl_x509attr_new(CMS_signed_get_attr(si, i)));

    return ary;
}

/*
 * call-seq:
 *    signer_info.signed_attributes = attrs
 *
 * Replace the signed attributes set by +attrs+. +attrs+ must be an Array of
 * X509::Attribute.
 */
static VALUE
si_set_signed_attributes(VALUE self, VALUE ary)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    X509_ATTRIBUTE **attrs;
    long i;
    int num;
    VALUE tmp;

    si_check_modify(self);
    Check_Type(ary, T_ARRAY);
    attrs = ALLOCV_N(X509_ATTRIBUTE *, tmp, RARRAY_LEN(ary));
    for (i = 0; i < RARRAY_LEN(ary); i++)
        attrs[i] = GetX509AttrPtr(RARRAY_AREF(ary, i));

    num = CMS_signed_get_attr_count(si);
    while (num > 0)
        X509_ATTRIBUTE_free(CMS_signed_delete_attr(si, --num));

    for (i = 0; i < RARRAY_LEN(ary); i++) {
        if (!CMS_signed_add1_attr(si, attrs[i]))
            ossl_raise(eCMSError, "CMS_signed_add1_attr");
    }
    ALLOCV_END(tmp);

    return ary;
}

/*
 * call-seq:
 *    signer_info.unsigned_attributes -> Array of X509::Attribute
 *
 * Returns all unsigned attributes in the SignerInfo strucuture.
 *
 * Modification of the returned X509::Attribute objects has no effect.
 */
static VALUE
si_get_unsigned_attributes(VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    int i, num = CMS_unsigned_get_attr_count(si);
    VALUE ary;

    if (num <= 0)
        return rb_ary_new();
    ary = rb_ary_new_capa(num);
    for (i = 0; i < num; i++)
        rb_ary_push(ary, ossl_x509attr_new(CMS_unsigned_get_attr(si, i)));

    return ary;
}

/*
 * call-seq:
 *    signer_info.unsigned_attributes = attrs
 *
 * Replace the unsigned attributes set by +attrs+. +attrs+ must be an Array of
 * X509::Attribute.
 */
static VALUE
si_set_unsigned_attributes(VALUE self, VALUE ary)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    X509_ATTRIBUTE **attrs;
    long i;
    int num;
    VALUE tmp;

    si_check_modify(self);
    Check_Type(ary, T_ARRAY);
    attrs = ALLOCV_N(X509_ATTRIBUTE *, tmp, RARRAY_LEN(ary));
    for (i = 0; i < RARRAY_LEN(ary); i++)
        attrs[i] = GetX509AttrPtr(RARRAY_AREF(ary, i));

    num = CMS_unsigned_get_attr_count(si);
    while (num > 0)
        X509_ATTRIBUTE_free(CMS_unsigned_delete_attr(si, --num));

    for (i = 0; i < RARRAY_LEN(ary); i++) {
        if (!CMS_unsigned_add1_attr(si, attrs[i]))
            ossl_raise(eCMSError, "CMS_unsigned_add1_attr");
    }
    ALLOCV_END(tmp);

    return ary;
}

/*
 * call-seq:
 *    signer_info.digest_algorithm -> String
 *
 * Returns the name of the message digest algorithm.
 */
static VALUE
si_get_digest_algorithm(VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    X509_ALGOR *algo;

    CMS_SignerInfo_get0_algs(si, NULL, NULL, &algo, NULL);
    if (!algo)
        return Qnil;

    return ossl_asn1obj_to_str(algo->algorithm);
}

/*
 * call-seq:
 *    signer_info.signature_algorithm -> String
 *
 * Returns the name of the signature algorithm.
 */
static VALUE
si_get_signature_algorithm(VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    X509_ALGOR *algo;

    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &algo);
    if (!algo)
        return Qnil;

    return ossl_asn1obj_to_str(algo->algorithm);
}

/*
 * call-seq:
 *    signer_info.sign -> self
 *    signer_info.sign(cert, key, digest: nil) -> self
 *
 * Explicitly signs the SignerInfo structure. This requires the private key to
 * be kept in the structure, i.e. not loaded from DER/PEM.
 *
 * TODO: ???
 */
static VALUE
si_sign(int argc, VALUE *argv, VALUE self)
{
    CMS_SignerInfo *si = GetCMSSignerInfo(self);
    VALUE cert_v, key_v, opts;
    X509 *x509;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx;

    rb_scan_args(argc, argv, "2:", &cert_v, &key_v, &opts);
    pkey = GetPrivPKeyPtr(key_v);
    x509 = X509_dup(GetX509CertPtr(cert_v)); /* FIXME: DupX509CertPtr? upref? */
    if (!x509)
        ossl_raise(eCMSError, "X509_dup");
    if (!X509_set_pubkey(x509, pkey)) {
        X509_free(x509);
        ossl_raise(eCMSError, "X509_set_pubkey");
    }

    pctx = CMS_SignerInfo_get0_pkey_ctx(si);
    if (pctx)
        abort();
    CMS_SignerInfo_set1_signer_cert(si, x509);
    X509_free(x509);
    /* FIXME: digest */
    if (!CMS_SignerInfo_sign(si))
        ossl_raise(eCMSError, "CMS_SignerInfo_sign");

    return self;
}

void
Init_ossl_cms_signed_data(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
    cCMS = rb_define_class_under(mOSSL, "CMS", rb_cObject);
    eCMSError = rb_define_class_under(cCMS, "CMSError", eOSSLError);
#endif

    /*
     * Document-class: OpenSSL::CMS::SignedData
     *
     * Provides access to CMS structure with signed-data content type.
     * The signed-data content type is used to encapsulate a digitally signed
     * data. It can also contain X.509 certificates and CRLs additionally.
     *
     * The typical usage of signed-data content type. The structure has one
     * signer's digital signature
     *
     *   cert = OpenSSL::X509::Certificate.new(File.open("..."))
     *   pkey = OpenSSL::PKey.read(File.open("..."))
     *   data = "the content string"
     *   cms = OpenSSL::CMS.sign(cert, pkey, data)
     */
    cCMSSignedData = rb_define_class_under(cCMS, "SignedData", cCMS);
    rb_define_method(cCMSSignedData, "initialize", signed_data_initialize, 1);
    rb_define_method(cCMSSignedData, "signers", signed_data_get_signers, 0);
    rb_define_method(cCMSSignedData, "add_signer", signed_data_add_signer, -1);
    rb_define_method(cCMSSignedData, "verify", signed_data_verify, -1);

    rb_define_method(cCMSSignedData, "certificates", ossl_cms_get_certificates, 0);
    rb_define_method(cCMSSignedData, "add_certificate", ossl_cms_add_certificate, 1);
    rb_define_method(cCMSSignedData, "crls", ossl_cms_get_crls, 0);
    rb_define_method(cCMSSignedData, "add_crl", ossl_cms_add_crl, 1);
    /* TODO: ESS? */

    /*
     * Document-class: OpenSSL::CMS::SignerInfo
     */
    cCMSSignerInfo = rb_define_class_under(cCMS, "SignerInfo", rb_cObject);
    rb_undef_alloc_func(cCMSSignerInfo);
    rb_define_method(cCMSSignerInfo, "subject_key_identifier", si_get_subject_key_identifier, 0);
    rb_define_method(cCMSSignerInfo, "issuer", si_get_issuer, 0);
    rb_define_method(cCMSSignerInfo, "serial", si_get_serial, 0);
    rb_define_method(cCMSSignerInfo, "signed_attributes", si_get_signed_attributes, 0);
    rb_define_method(cCMSSignerInfo, "signed_attributes=", si_set_signed_attributes, 1);
    rb_define_method(cCMSSignerInfo, "unsigned_attributes", si_get_unsigned_attributes, 0);
    rb_define_method(cCMSSignerInfo, "unsigned_attributes=", si_set_unsigned_attributes, 1);
    rb_define_method(cCMSSignerInfo, "digest_algorithm", si_get_digest_algorithm, 0);
    rb_define_method(cCMSSignerInfo, "signature_algorithm", si_get_signature_algorithm, 0);

    rb_define_method(cCMSSignerInfo, "sign", si_sign, -1);


    id_parent_ref = rb_intern_const("parent_ref");
    id_digest = rb_intern_const("digest");
    id_flags = rb_intern_const("flags");
}
#endif
