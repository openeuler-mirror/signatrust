use crate::util::attributes;
use crate::util::attributes::PkeyHashAlgo;
use crate::util::error::{Error, Result};
use crate::util::options;
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::hash::hash;
use openssl::pkey;
use openssl::x509;
use openssl_sys::{
    ASN1_INTEGER_free, ASN1_OBJECT_free, BIO_free_all, BIO_get_mem_data, BIO_new, BIO_new_mem_buf,
    BIO_s_mem, CMS_ContentInfo, CMS_ContentInfo_free, CMS_sign, ERR_clear_error,
    ERR_peek_last_error, EVP_MD_type, EVP_PKEY_CTX_set_rsa_padding, OBJ_nid2obj, OBJ_txt2obj,
    X509_ALGOR_free, ASN1_BOOLEAN, ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OBJECT,
    ASN1_OCTET_STRING, BIO, CMS_BINARY, CMS_DETACHED, CMS_KEY_PARAM, CMS_NOSMIMECAP, CMS_PARTIAL,
    EVP_MD, EVP_PKEY, EVP_PKEY_CTX, GENERAL_NAME, RSA_PKCS1_PSS_PADDING, V_ASN1_NULL,
    V_ASN1_SEQUENCE, X509, X509_ALGOR, X509_CRL,
};
use rand::rngs::OsRng;
use rand::Rng;
use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use std::ptr;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

const TIMESTAMP_OID: &str = "1.2.840.113549.1.9.16.1.4";
const SM2_DEFAULT_ID: &[u8] = b"1234567812345678";
const USER_DEFINE_OID: &str = "1.2.3.4.1";
// GM/T 0010: outer ContentInfo.contentType for all SM2 signed messages
const SM2_CONTENT_TYPE_OID: &str = "1.2.156.10197.6.1.4.2.2";
// GM/T 0010: inner encapContentInfo.eContentType for SM2 signed data (not used for timestamp)
const SM2_ECONTENT_TYPE_OID: &str = "1.2.156.10197.6.1.4.2.1";

#[repr(C)]
pub struct CMS_SignerInfo {
    cert: *mut X509,
    pkey: *mut EVP_PKEY,
    md: *const EVP_MD,
    sig: *mut u8,
    siglen: i32,
}

#[repr(C)]
pub struct TS_MSG_IMPRINT {
    algo: *mut X509_ALGOR,
    hash: *mut ASN1_OCTET_STRING,
}

#[repr(C)]
pub struct TS_REQ {
    version: *mut ASN1_INTEGER,
    tst: *mut TS_MSG_IMPRINT,
    policy_id: *mut ASN1_OBJECT,
    nonce: *mut ASN1_INTEGER,
    cert_req: *mut ASN1_BOOLEAN,
    extensions: *mut c_void,
}

#[repr(C)]
pub struct TS_TST_INFO {
    version: *mut ASN1_INTEGER,
    policy_id: *mut ASN1_OBJECT,
    tst: *mut TS_MSG_IMPRINT,
    serial: *mut ASN1_INTEGER,
    time: *mut ASN1_GENERALIZEDTIME,
    accuracy: *mut c_void,
    ordering: *mut ASN1_BOOLEAN,
    nonce: *mut ASN1_INTEGER,
    tsa: *mut GENERAL_NAME,
    extensions: *mut c_void,
}

extern "C" {
    pub fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER;
    pub fn ASN1_INTEGER_set_uint64(a: *mut ASN1_INTEGER, r: u64) -> i32;
    pub fn ASN1_GENERALIZEDTIME_new() -> *mut ASN1_GENERALIZEDTIME;
    pub fn ASN1_GENERALIZEDTIME_free(time: *mut ASN1_GENERALIZEDTIME);
    pub fn ASN1_GENERALIZEDTIME_set(
        s: *mut ASN1_GENERALIZEDTIME,
        t: i64,
    ) -> *mut ASN1_GENERALIZEDTIME;
    pub fn ASN1_STRING_data(octet_str: *mut c_void) -> *const u8;
    pub fn ASN1_STRING_length(octet_str: *mut c_void) -> i32;
    pub fn CMS_final_digest(
        cms: *mut CMS_ContentInfo,
        md: *const c_uchar,
        mdlen: c_uint,
        dcont: *mut BIO,
        flags: c_uint,
    ) -> c_int;
    pub fn CMS_final(
        cms: *mut CMS_ContentInfo,
        bio: *mut BIO,
        dcont: *mut BIO,
        flags: c_uint,
    ) -> c_int;
    pub fn CMS_add1_signer(
        cms: *mut CMS_ContentInfo,
        cert: *mut X509,
        pkey: *mut EVP_PKEY,
        md: *const EVP_MD,
        flags: u32,
    ) -> *mut CMS_SignerInfo;
    pub fn CMS_unsigned_add1_attr_by_NID(
        si: *mut CMS_SignerInfo,
        nid: i32,
        attr_type: i32,
        bytes: *const c_void,
        len: i32,
    ) -> i32;
    pub fn CMS_get0_SignerInfos(cms: *mut CMS_ContentInfo) -> *mut c_void;
    pub fn CMS_add1_crl(cms: *mut CMS_ContentInfo, crl: *mut X509_CRL) -> c_int;
    pub fn CMS_SignerInfo_get0_signature(si: *mut c_void) -> *mut c_void;
    pub fn CMS_SignerInfo_get0_pkey_ctx(si: *mut CMS_SignerInfo) -> *mut EVP_PKEY_CTX;
    pub fn CMS_set1_eContentType(cms: *mut CMS_ContentInfo, oid: *mut ASN1_OBJECT) -> i32;
    pub fn i2d_CMS_bio(out: *mut BIO, cms: *mut CMS_ContentInfo) -> c_int;
    pub fn i2d_CMS_ContentInfo(cms: *mut CMS_ContentInfo, out: *mut *mut u8) -> c_int;
    pub fn d2i_CMS_ContentInfo(
        out: *mut *mut CMS_ContentInfo,
        pp: *mut *const u8,
        length: c_int,
    ) -> *mut CMS_ContentInfo;
    pub fn OPENSSL_sk_num(stack: *const c_void) -> i32;
    pub fn OPENSSL_sk_value(stack: *const c_void, idx: i32) -> *mut c_void;
    pub fn free(ptr: *mut c_void);
    pub fn EVP_PKEY_is_a(key: *const EVP_PKEY, name: *const c_char) -> c_int;
    pub fn EVP_PKEY_CTX_set1_id(ctx: *mut EVP_PKEY_CTX, id: *const c_void, id_len: c_int) -> c_int;

    pub fn TS_REQ_new() -> *mut TS_REQ;
    pub fn TS_REQ_free(req: *mut TS_REQ);
    pub fn TS_REQ_set_version(req: *mut TS_REQ, version: i32) -> i32;
    pub fn TS_MSG_IMPRINT_new() -> *mut TS_MSG_IMPRINT;
    pub fn TS_MSG_IMPRINT_free(imprint: *mut TS_MSG_IMPRINT);
    pub fn TS_MSG_IMPRINT_dup(imprint: *mut TS_MSG_IMPRINT) -> *mut TS_MSG_IMPRINT;
    pub fn TS_MSG_IMPRINT_set_algo(imprint: *mut TS_MSG_IMPRINT, algo: *mut X509_ALGOR) -> i32;
    pub fn TS_MSG_IMPRINT_set_msg(imprint: *mut TS_MSG_IMPRINT, msg: *const u8, len: i32) -> i32;
    pub fn TS_REQ_set_msg_imprint(req: *mut TS_REQ, imprint: *mut TS_MSG_IMPRINT) -> i32;
    pub fn TS_REQ_get_msg_imprint(req: *mut TS_REQ) -> *mut TS_MSG_IMPRINT;
    pub fn TS_REQ_set_cert_req(req: *mut TS_REQ, cert_req: i32) -> i32;

    pub fn TS_TST_INFO_free(info: *mut TS_TST_INFO);
    pub fn TS_TST_INFO_new() -> *mut TS_TST_INFO;
    pub fn TS_TST_INFO_set_version(tst: *mut TS_TST_INFO, version: i32) -> i32;
    pub fn TS_TST_INFO_set_policy_id(tst: *mut TS_TST_INFO, policy: *mut ASN1_OBJECT) -> i32;
    pub fn TS_TST_INFO_set_msg_imprint(tst: *mut TS_TST_INFO, msg: *mut TS_MSG_IMPRINT) -> i32;
    pub fn TS_TST_INFO_set_serial(tst: *mut TS_TST_INFO, serial: *mut ASN1_INTEGER) -> i32;
    pub fn TS_TST_INFO_set_time(tst: *mut TS_TST_INFO, gen_time: *mut ASN1_GENERALIZEDTIME) -> i32;
    pub fn TS_TST_INFO_set_ordering(tst: *mut TS_TST_INFO, ordering: i32) -> i32;
    pub fn TS_TST_INFO_set_tsa(tst: *mut TS_TST_INFO, tsa_name: *mut GENERAL_NAME) -> i32;
    pub fn i2d_TS_TST_INFO(tst: *mut TS_TST_INFO, out: *mut *mut u8) -> i32;

    pub fn X509_ALGOR_new() -> *mut X509_ALGOR;
    pub fn X509_ALGOR_set0(
        alg: *mut X509_ALGOR,
        obj: *mut ASN1_OBJECT,
        algo_type: i32,
        val: *mut c_void,
    ) -> i32;
    pub fn PEM_read_bio_X509_CRL(
        bp: *mut BIO,
        x: *mut *mut X509_CRL,
        cb: *mut c_void,
        u: *mut c_void,
    ) -> *mut X509_CRL;
    pub fn X509_CRL_free(crl: *mut X509_CRL);
    pub fn PEM_read_bio_X509(
        bp: *mut BIO,
        x: *mut *mut X509,
        cb: *mut c_void,
        u: *mut c_void,
    ) -> *mut X509;
    pub fn X509_free(cert: *mut X509);
    pub fn CMS_add1_cert(cms: *mut CMS_ContentInfo, cert: *mut X509) -> c_int;
}

struct BioGuard(*mut BIO);
impl Drop for BioGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { BIO_free_all(self.0) };
        }
    }
}

struct CmsGuard(*mut CMS_ContentInfo);
impl Drop for CmsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CMS_ContentInfo_free(self.0) };
        }
    }
}

struct Asn1ObjGuard(*mut ASN1_OBJECT);
impl Drop for Asn1ObjGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ASN1_OBJECT_free(self.0) };
        }
    }
}

struct DerGuard(*mut u8);
impl Drop for DerGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { free(self.0 as *mut c_void) };
        }
    }
}

struct TsGuard(*mut TS_REQ);
impl Drop for TsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { TS_REQ_free(self.0) };
        }
    }
}

struct MsgImprintGuard(*mut TS_MSG_IMPRINT);
impl Drop for MsgImprintGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { TS_MSG_IMPRINT_free(self.0) };
        }
    }
}

struct AlgoGuard(*mut X509_ALGOR);
impl Drop for AlgoGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { X509_ALGOR_free(self.0) };
        }
    }
}

struct TstGuard(*mut TS_TST_INFO);
impl Drop for TstGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { TS_TST_INFO_free(self.0) };
        }
    }
}

struct Asn1IntGuard(*mut ASN1_INTEGER);
impl Drop for Asn1IntGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ASN1_INTEGER_free(self.0) };
        }
    }
}

struct GenTimeGuard(*mut ASN1_GENERALIZEDTIME);
impl Drop for GenTimeGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ASN1_GENERALIZEDTIME_free(self.0) };
        }
    }
}

trait CmsSignHandler {
    // 签名前调用：设置 padding 或主签名 eContentType
    unsafe fn pre_sign_main(
        &self,
        cms: *mut CMS_ContentInfo,
        pk_ctx: *mut EVP_PKEY_CTX,
    ) -> Result<()>;
    // 签名前调用：设置 padding（时间戳，eContentType 固定为 TIMESTAMP_OID，不在此设置）
    unsafe fn pre_sign_timestamp(&self, pk_ctx: *mut EVP_PKEY_CTX) -> Result<()>;
    // 签名序列化后调用：对 DER 字节做 OID 替换（仅替换外层 contentType）
    fn patch_der(&self, der: Vec<u8>) -> Result<Vec<u8>>;
}

struct RsaSignHandler;
impl CmsSignHandler for RsaSignHandler {
    unsafe fn pre_sign_main(
        &self,
        _cms: *mut CMS_ContentInfo,
        pk_ctx: *mut EVP_PKEY_CTX,
    ) -> Result<()> {
        EVP_PKEY_CTX_set_rsa_padding(pk_ctx, RSA_PKCS1_PSS_PADDING);
        Ok(())
    }
    unsafe fn pre_sign_timestamp(&self, pk_ctx: *mut EVP_PKEY_CTX) -> Result<()> {
        EVP_PKEY_CTX_set_rsa_padding(pk_ctx, RSA_PKCS1_PSS_PADDING);
        Ok(())
    }
    fn patch_der(&self, der: Vec<u8>) -> Result<Vec<u8>> {
        Ok(der)
    }
}

struct Sm2SignHandler;
impl CmsSignHandler for Sm2SignHandler {
    unsafe fn pre_sign_main(
        &self,
        cms: *mut CMS_ContentInfo,
        pk_ctx: *mut EVP_PKEY_CTX,
    ) -> Result<()> {
        if EVP_PKEY_CTX_set1_id(
            pk_ctx,
            SM2_DEFAULT_ID.as_ptr() as *const c_void,
            SM2_DEFAULT_ID.len() as c_int,
        ) != 1
        {
            return Err(Error::InvalidArgumentError(
                "EVP_PKEY_CTX_set1_id failed".to_string(),
            ));
        }
        // 设置内层 eContentType（参与签名，必须在 CMS_final_digest 之前）
        let oid_cstr = CString::new(SM2_ECONTENT_TYPE_OID)
            .map_err(|_| Error::InvalidArgumentError("invalid SM2 eContentType OID".to_string()))?;
        let oid = OBJ_txt2obj(oid_cstr.as_ptr(), 1);
        if oid.is_null() {
            return Err(Error::InvalidArgumentError(
                "OBJ_txt2obj for SM2 eContentType OID failed".to_string(),
            ));
        }
        let _oid_guard = Asn1ObjGuard(oid);
        if CMS_set1_eContentType(cms, oid) != 1 {
            return Err(Error::InvalidArgumentError(
                "CMS_set1_eContentType failed".to_string(),
            ));
        }
        Ok(())
    }
    unsafe fn pre_sign_timestamp(&self, pk_ctx: *mut EVP_PKEY_CTX) -> Result<()> {
        if EVP_PKEY_CTX_set1_id(
            pk_ctx,
            SM2_DEFAULT_ID.as_ptr() as *const c_void,
            SM2_DEFAULT_ID.len() as c_int,
        ) != 1
        {
            return Err(Error::InvalidArgumentError(
                "EVP_PKEY_CTX_set1_id failed".to_string(),
            ));
        }
        Ok(())
    }
    fn patch_der(&self, der: Vec<u8>) -> Result<Vec<u8>> {
        patch_outer_content_type(der)
    }
}

fn cms_sign_handler(key_type: &str) -> Box<dyn CmsSignHandler> {
    match key_type {
        "sm2" => Box::new(Sm2SignHandler),
        "rsa" => Box::new(RsaSignHandler),
        other => {
            log::warn!(
                "unknown key_type '{}', falling back to RsaSignHandler",
                other
            );
            Box::new(RsaSignHandler)
        }
    }
}

// Returns the byte offset of the first child element inside a DER SEQUENCE,
// i.e. 1 (tag) + length-of-length-field bytes.
fn der_seq_header_len(buf: &[u8]) -> Result<usize> {
    if buf.len() < 2 {
        return Err(Error::InvalidArgumentError(
            "DER buffer too short".to_string(),
        ));
    }
    Ok(match buf[1] {
        n if n < 0x80 => 2,
        0x81 => 3,
        0x82 => 4,
        0x83 => 5,
        other => {
            return Err(Error::InvalidArgumentError(format!(
                "Unsupported DER length byte: 0x{:02X}",
                other
            )))
        }
    })
}

// Encodes a DER length value into bytes (supports up to 3-byte length, i.e. <= 0xFFFFFF).
fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else if len <= 0xFF_FFFF {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else {
        panic!(
            "DER length {} exceeds 3-byte encoding limit (0xFFFFFF)",
            len
        );
    }
}

// Replaces the outer ContentInfo.contentType OID (pkcs7-signedData) with SM2_CONTENT_TYPE_OID
// and rebuilds the root SEQUENCE header with a correctly re-encoded length field.
// The inner eContentType was already set correctly via CMS_set1_eContentType before signing.
fn patch_outer_content_type(der: Vec<u8>) -> Result<Vec<u8>> {
    const OLD_OID: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];
    const NEW_OID: &[u8] = &[
        0x06, 0x0A, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x06, 0x01, 0x04, 0x02, 0x02,
    ];

    if der.is_empty() || der[0] != 0x30 {
        return Err(Error::InvalidArgumentError(
            "DER does not start with SEQUENCE tag".to_string(),
        ));
    }
    let oid_start = der_seq_header_len(&der)?;

    // If the OID at the expected position is not pkcs7-signedData, it is unexpected.
    if der.len() < oid_start + OLD_OID.len()
        || &der[oid_start..oid_start + OLD_OID.len()] != OLD_OID
    {
        return Err(Error::InvalidArgumentError(
            "patch_outer_content_type: expected pkcs7-signedData OID not found".to_string(),
        ));
    }

    // Everything after the old OID (the rest of the SEQUENCE contents).
    let tail = &der[oid_start + OLD_OID.len()..];

    // Rebuild: 0x30 + correctly encoded length + NEW_OID + tail.
    let inner_len = NEW_OID.len() + tail.len();
    let len_bytes = der_encode_length(inner_len);
    let mut out = Vec::with_capacity(1 + len_bytes.len() + inner_len);
    out.push(0x30);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(NEW_OID);
    out.extend_from_slice(tail);
    Ok(out)
}

fn generate_cms_with_hash(
    cert: &x509::X509Ref,
    pkey: &pkey::PKey<pkey::Private>,
    digest: &[u8],
    options: &HashMap<String, String>,
    attributes: &HashMap<String, String>,
    handler: &dyn CmsSignHandler,
) -> Result<*mut CMS_ContentInfo> {
    unsafe {
        // step1. generate cms structure
        let data_bio = BIO_new_mem_buf(
            digest.as_ptr() as *const c_void,
            digest
                .len()
                .try_into()
                .map_err(|_| Error::InvalidArgumentError("digest too large".to_string()))?,
        );
        let _data_bio_guard = BioGuard(data_bio);
        let flags = CMS_DETACHED | CMS_BINARY | CMS_PARTIAL | CMS_NOSMIMECAP | CMS_KEY_PARAM;
        let cms: *mut CMS_ContentInfo = CMS_sign(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            data_bio,
            flags,
        );
        if cms.is_null() {
            return Err(Error::InvalidArgumentError(
                "CMS_sign (partial) failed".to_string(),
            ));
        }
        let mut cms_guard = CmsGuard(cms);
        // step2. specify the hash algorithm used, certificates, CRL and encryption
        let digest_algo = attributes.get(attributes::DIGEST_ALGO).ok_or_else(|| {
            Error::InvalidArgumentError("missing digest algorithm attribute".to_string())
        })?;
        let md = PkeyHashAlgo::get_openssl_c_digest_algo(digest_algo);
        let si = CMS_add1_signer(cms, cert.as_ptr(), pkey.as_ptr(), md, flags);
        if si.is_null() {
            return Err(Error::InvalidArgumentError(
                "CMS_add1_signer failed".to_string(),
            ));
        }
        if let Some(crl_data) = options.get(options::CRL).filter(|s| !s.is_empty()) {
            let crl_bio = BIO_new_mem_buf(
                crl_data.as_ptr() as *const c_void,
                crl_data
                    .len()
                    .try_into()
                    .map_err(|_| Error::InvalidArgumentError("crl data too large".to_string()))?,
            );
            if crl_bio.is_null() {
                return Err(Error::InvalidArgumentError(
                    "BIO_new_mem_buf for CRL failed".to_string(),
                ));
            }
            let _crl_bio_guard = BioGuard(crl_bio);
            loop {
                let crl = PEM_read_bio_X509_CRL(
                    crl_bio,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                if crl.is_null() {
                    break;
                }
                let add_ret = CMS_add1_crl(cms, crl);
                X509_CRL_free(crl);
                if add_ret != 1 {
                    return Err(Error::InvalidArgumentError(
                        "CMS_add1_crl failed".to_string(),
                    ));
                }
            }
        }
        if let Some(ca_data) = options.get(options::CA).filter(|s| !s.is_empty()) {
            let ca_bio = BIO_new_mem_buf(
                ca_data.as_ptr() as *const c_void,
                ca_data
                    .len()
                    .try_into()
                    .map_err(|_| Error::InvalidArgumentError("ca data too large".to_string()))?,
            );
            if ca_bio.is_null() {
                return Err(Error::InvalidArgumentError(
                    "BIO_new_mem_buf for CA failed".to_string(),
                ));
            }
            let _ca_bio_guard = BioGuard(ca_bio);
            loop {
                let cert =
                    PEM_read_bio_X509(ca_bio, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
                if cert.is_null() {
                    break;
                }
                let add_ret = CMS_add1_cert(cms, cert);
                X509_free(cert);
                if add_ret != 1 {
                    return Err(Error::InvalidArgumentError(
                        "CMS_add1_cert failed".to_string(),
                    ));
                }
            }
        }
        let pk_ctx = CMS_SignerInfo_get0_pkey_ctx(si);
        if pk_ctx.is_null() {
            return Err(Error::InvalidArgumentError(
                "CMS_SignerInfo_get0_pkey_ctx failed".to_string(),
            ));
        }
        handler.pre_sign_main(cms, pk_ctx)?;
        // step3. generate signature
        let ret = CMS_final_digest(
            cms,
            digest.as_ptr(),
            digest.len() as u32,
            ptr::null_mut(),
            flags,
        );
        if ret != 1 {
            return Err(Error::InvalidArgumentError(
                "CMS_final_digest failed".to_string(),
            ));
        }
        let cms_ptr = cms_guard.0;
        cms_guard.0 = ptr::null_mut();
        Ok(cms_ptr)
    }
}

fn generate_timestamp_req(
    cms: *mut CMS_ContentInfo,
    attributes: &HashMap<String, String>,
) -> Result<*mut TS_REQ> {
    unsafe {
        // step1. get signature from cms
        let signatures = CMS_get0_SignerInfos(cms);
        if signatures.is_null() {
            return Err(Error::RemoteSignError(
                "CMS_get0_SignerInfos failed".to_string(),
            ));
        }

        let count = OPENSSL_sk_num(signatures);
        if count <= 0 {
            return Err(Error::RemoteSignError("no signer in CMS".to_string()));
        }

        let si = OPENSSL_sk_value(signatures, 0);
        if si.is_null() {
            return Err(Error::RemoteSignError(
                "OPENSSL_sk_value returned null signer".to_string(),
            ));
        }

        let signature = CMS_SignerInfo_get0_signature(si);
        if signature.is_null() {
            return Err(Error::RemoteSignError(
                "CMS_SignerInfo_get0_signature failed".to_string(),
            ));
        }
        let data_len = ASN1_STRING_length(signature);
        let data_ptr = ASN1_STRING_data(signature);
        if data_len <= 0 || data_ptr.is_null() {
            return Err(Error::RemoteSignError(
                "invalid signature ASN1 string".to_string(),
            ));
        }

        let data: &[u8] = std::slice::from_raw_parts(data_ptr, data_len.try_into().unwrap());
        let digest_algo = PkeyHashAlgo::get_digest_algo_from_attributes(&attributes);
        let digest = hash(digest_algo, &data)?;

        // step2. generate ts_req from signature
        let ts_req = TS_REQ_new();
        let mut ts_guard = TsGuard(ts_req);

        if TS_REQ_set_version(ts_req, 1) != 1 {
            return Err(Error::RemoteSignError(
                "TS_REQ_set_version failed".to_string(),
            ));
        }

        let msg_imprint = TS_MSG_IMPRINT_new();
        let _msg_guard = MsgImprintGuard(msg_imprint);
        let algo = X509_ALGOR_new();
        let _algo_guard = AlgoGuard(algo);

        let digest_algo = attributes.get(attributes::DIGEST_ALGO).ok_or_else(|| {
            Error::RemoteSignError("missing digest algorithm attribute".to_string())
        })?;

        let md = PkeyHashAlgo::get_openssl_c_digest_algo(digest_algo);
        let nid = EVP_MD_type(md);
        let obj = OBJ_nid2obj(nid);
        X509_ALGOR_set0(algo, obj, V_ASN1_NULL, ptr::null_mut());

        if TS_MSG_IMPRINT_set_algo(msg_imprint, algo) != 1 {
            return Err(Error::RemoteSignError(
                "TS_MSG_IMPRINT_set_algo failed".to_string(),
            ));
        }

        if TS_MSG_IMPRINT_set_msg(
            msg_imprint,
            digest.to_vec().as_ptr(),
            digest.len().try_into().unwrap(),
        ) != 1
        {
            return Err(Error::RemoteSignError(
                "TS_MSG_IMPRINT_set_msg failed".to_string(),
            ));
        }

        if TS_REQ_set_msg_imprint(ts_req, msg_imprint) != 1 {
            return Err(Error::RemoteSignError(
                "TS_REQ_set_msg_imprint failed".to_string(),
            ));
        }

        let ts_ptr = ts_guard.0;
        ts_guard.0 = ptr::null_mut();
        Ok(ts_ptr)
    }
}

fn generate_timestamp_tst(req: *mut TS_REQ, tsa_cert: &x509::X509Ref) -> Result<*mut TS_TST_INFO> {
    let _ = tsa_cert;
    if req.is_null() {
        return Err(Error::RemoteSignError("TS_REQ is null".to_string()));
    }

    unsafe {
        // step1. crete tst_info structure
        let tst = TS_TST_INFO_new();
        let mut tst_guard = TstGuard(tst);
        if TS_TST_INFO_set_version(tst, 1) != 1 {
            return Err(Error::RemoteSignError(
                "TS_TST_INFO_set_version failed".to_string(),
            ));
        }

        let policy_str = CString::new(USER_DEFINE_OID)
            .map_err(|_| Error::RemoteSignError("invalid policy OID".to_string()))?;
        let policy = OBJ_txt2obj(policy_str.as_ptr(), 1);
        let _policy_guard = Asn1ObjGuard(policy);

        // step2. set attributes of tst_info
        if TS_TST_INFO_set_policy_id(tst, policy) != 1 {
            return Err(Error::RemoteSignError(
                "TS_TST_INFO_set_policy_id failed".to_string(),
            ));
        }

        let msg_imprint = TS_REQ_get_msg_imprint(req);
        if msg_imprint.is_null() {
            return Err(Error::RemoteSignError(
                "TS_REQ_get_msg_imprint failed".to_string(),
            ));
        }

        let msg_imprint_copy = TS_MSG_IMPRINT_dup(msg_imprint);
        if msg_imprint_copy.is_null() {
            return Err(Error::RemoteSignError(
                "TS_MSG_IMPRINT_dup failed".to_string(),
            ));
        }

        if TS_TST_INFO_set_msg_imprint(tst, msg_imprint_copy) != 1 {
            return Err(Error::RemoteSignError(
                "TS_TST_INFO_set_msg_imprint failed".to_string(),
            ));
        }

        let serial = ASN1_INTEGER_new();
        let _serial_guard = Asn1IntGuard(serial);

        let random = OsRng.gen();

        if ASN1_INTEGER_set_uint64(serial, random) != 1 {
            return Err(Error::RemoteSignError(
                "ASN1_INTEGER_set_uint64 failed".to_string(),
            ));
        }

        if TS_TST_INFO_set_serial(tst, serial) != 1 {
            return Err(Error::RemoteSignError(
                "TS_TST_INFO_set_serial failed".to_string(),
            ));
        }

        let gen_time = ASN1_GENERALIZEDTIME_new();
        let _gen_time_guard = GenTimeGuard(gen_time);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::RemoteSignError("system time before UNIX_EPOCH".to_string()))?
            .as_secs() as i64;

        if ASN1_GENERALIZEDTIME_set(gen_time, now).is_null() {
            return Err(Error::RemoteSignError(
                "ASN1_GENERALIZEDTIME_set failed".to_string(),
            ));
        }

        if TS_TST_INFO_set_time(tst, gen_time) != 1 {
            return Err(Error::RemoteSignError(
                "TS_TST_INFO_set_time failed".to_string(),
            ));
        }

        if TS_TST_INFO_set_ordering(tst, 1) != 1 {
            return Err(Error::RemoteSignError(
                "TS_TST_INFO_set_ordering failed".to_string(),
            ));
        }

        let tst_ptr = tst_guard.0;
        tst_guard.0 = ptr::null_mut();
        Ok(tst_ptr)
    }
}

fn generate_timestamp_signature(
    tsa_cert: &x509::X509Ref,
    tsa_key: &pkey::PKey<pkey::Private>,
    tst_info: *mut TS_TST_INFO,
    attributes: &HashMap<String, String>,
    handler: &dyn CmsSignHandler,
) -> Result<*mut CMS_ContentInfo> {
    if tst_info.is_null() {
        return Err(Error::InvalidArgumentError(
            "TS_TST_INFO is null".to_string(),
        ));
    }

    unsafe {
        // step1. get stream of tst_info
        let len: c_int = i2d_TS_TST_INFO(tst_info, ptr::null_mut());
        if len <= 0 {
            return Err(Error::InvalidArgumentError(
                "i2d_TS_TST_INFO (size calc) failed".to_string(),
            ));
        }
        let mut tst_der: *mut u8 = ptr::null_mut();
        i2d_TS_TST_INFO(tst_info, &mut tst_der);
        let _tst_der = DerGuard(tst_der);
        // step2. generate cms structure
        let content = BIO_new_mem_buf(tst_der as *const c_void, len);
        if content.is_null() {
            return Err(Error::InvalidArgumentError(
                "BIO_new_mem_buf failed".to_string(),
            ));
        }
        let _bio_guard = BioGuard(content);
        let flags = CMS_BINARY | CMS_PARTIAL | CMS_KEY_PARAM | CMS_NOSMIMECAP;
        let cms = CMS_sign(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
        );
        if cms.is_null() {
            return Err(Error::InvalidArgumentError(
                "CMS_sign (partial) failed".to_string(),
            ));
        }
        let mut cms_guard = CmsGuard(cms);
        // step3. specify the hash algorithm used and padding algorithm
        let digest_algo = attributes.get(attributes::DIGEST_ALGO).ok_or_else(|| {
            Error::InvalidArgumentError("missing digest algorithm attribute".to_string())
        })?;

        let md = PkeyHashAlgo::get_openssl_c_digest_algo(digest_algo);
        let si: *mut CMS_SignerInfo =
            CMS_add1_signer(cms, tsa_cert.as_ptr(), tsa_key.as_ptr(), md, flags);
        if si.is_null() {
            return Err(Error::InvalidArgumentError(
                "CMS_add1_signer failed".to_string(),
            ));
        }

        let pctx: *mut EVP_PKEY_CTX = CMS_SignerInfo_get0_pkey_ctx(si);
        if pctx.is_null() {
            return Err(Error::InvalidArgumentError(
                "CMS_SignerInfo_get0_pkey_ctx failed".to_string(),
            ));
        }
        handler.pre_sign_timestamp(pctx)?;
        // step4. specify the eContentType (always TIMESTAMP_OID, regardless of key type)
        let oid_str = CString::new(TIMESTAMP_OID)
            .map_err(|_| Error::RemoteSignError("invalid OID".to_string()))?;
        let tst_oid: *mut ASN1_OBJECT = OBJ_txt2obj(oid_str.as_ptr(), 1);
        if tst_oid.is_null() {
            return Err(Error::InvalidArgumentError(
                "OBJ_txt2obj failed".to_string(),
            ));
        }
        let _oid_guard = Asn1ObjGuard(tst_oid);
        if CMS_set1_eContentType(cms, tst_oid) != 1 {
            return Err(Error::InvalidArgumentError(
                "CMS_set1_eContentType failed".to_string(),
            ));
        }
        // step5. generate cms signature
        if CMS_final(cms, content, ptr::null_mut(), flags) != 1 {
            return Err(Error::InvalidArgumentError("CMS_final failed".to_string()));
        }
        let cms_ptr = cms_guard.0;
        cms_guard.0 = ptr::null_mut();
        Ok(cms_ptr)
    }
}

fn attach_timestamp_to_cms(
    cms: *mut CMS_ContentInfo,
    ts_token: *mut CMS_ContentInfo,
    key_type: &str,
) -> Result<()> {
    unsafe {
        // step1. get cms signer info
        let signers = CMS_get0_SignerInfos(cms);
        let signer_info = OPENSSL_sk_value(signers, 0);
        if signer_info.is_null() {
            return Err(Error::InvalidArgumentError(
                "Failed to get SignerInfo from CMS.".to_string(),
            ));
        }
        // step2. serialize timestamp token with OID patching applied
        let ts_der = CmsPlugin::cms_to_vec(ts_token, key_type)?;
        // step3. attach timestamp to cms
        let nid = 225;
        let result = CMS_unsigned_add1_attr_by_NID(
            signer_info as *mut CMS_SignerInfo,
            nid,
            V_ASN1_SEQUENCE,
            ts_der.as_ptr() as *mut _,
            ts_der.len() as c_int,
        );

        if result != 1 {
            return Err(Error::InvalidArgumentError(
                "Failed to add timestamp token to CMS.".to_string(),
            ));
        }
        Ok(())
    }
}

pub struct CmsContext<'a> {
    certificate: &'a x509::X509Ref,
    private_key: &'a pkey::PKey<pkey::Private>,
    content: &'a [u8],
    options: &'a HashMap<String, String>,
    pub sign_key_attributes: &'a HashMap<String, String>,
    pub cms: *mut CMS_ContentInfo,

    // timpstamp
    ts_req: *mut TS_REQ,
    tst_info: *mut TS_TST_INFO,
    timestamp: *mut CMS_ContentInfo,
    timestamp_key_attributes: &'a HashMap<String, String>,
    tsa_cert_pem: &'a [u8],
    tsa_key_pem: &'a [u8],
    tsa_cert: Option<x509::X509>,
    tsa_key: Option<pkey::PKey<pkey::Private>>,
}

impl<'a> CmsContext<'a> {
    pub fn new(
        certificate: &'a x509::X509Ref,
        private_key: &'a pkey::PKey<pkey::Private>,
        content: &'a [u8],
        options: &'a HashMap<String, String>,
        sign_key_attributes: &'a HashMap<String, String>,
        timestamp_key_attributes: &'a HashMap<String, String>,
        tsa_cert_pem: &'a [u8],
        tsa_key_pem: &'a [u8],
    ) -> Self {
        Self {
            certificate,
            private_key,
            content,
            options,
            sign_key_attributes,
            cms: std::ptr::null_mut(),
            ts_req: std::ptr::null_mut(),
            tst_info: std::ptr::null_mut(),
            timestamp: std::ptr::null_mut(),
            timestamp_key_attributes,
            tsa_cert_pem,
            tsa_key_pem,
            tsa_cert: None,
            tsa_key: None,
        }
    }
}

pub type Step<'a> = &'a dyn Fn(&mut CmsContext) -> Result<()>;
pub struct CmsPlugin;
impl CmsPlugin {
    pub fn run_steps(ctx: &mut CmsContext, steps: &[Step]) -> Result<()> {
        for (_idx, step) in steps.iter().enumerate() {
            step(ctx)?;
        }
        Ok(())
    }

    pub fn step_generate_cms(ctx: &mut CmsContext) -> Result<()> {
        let key_type = ctx
            .sign_key_attributes
            .get("key_type")
            .map(|s| s.as_str())
            .unwrap_or("");
        let handler = cms_sign_handler(key_type);
        let cms = generate_cms_with_hash(
            ctx.certificate,
            ctx.private_key,
            ctx.content,
            ctx.options,
            ctx.sign_key_attributes,
            handler.as_ref(),
        )?;
        ctx.cms = cms;
        Ok(())
    }

    pub fn step_generate_ts_req(ctx: &mut CmsContext) -> Result<()> {
        let ts_req = generate_timestamp_req(ctx.cms, ctx.sign_key_attributes)?;
        ctx.ts_req = ts_req;
        Ok(())
    }

    pub fn step_load_tsa_cert_key(ctx: &mut CmsContext) -> Result<()> {
        let cert = x509::X509::from_pem(ctx.tsa_cert_pem)
            .map_err(|_e| Error::RemoteSignError("load tsa certificate failed".to_string()))?;
        let key = pkey::PKey::private_key_from_pem(ctx.tsa_key_pem)
            .map_err(|_e| Error::RemoteSignError("load tsa private key failed".to_string()))?;

        ctx.tsa_cert = Some(cert);
        ctx.tsa_key = Some(key);
        Ok(())
    }

    pub fn step_generate_tst_info(ctx: &mut CmsContext) -> Result<()> {
        let tsa_cert = ctx
            .tsa_cert
            .as_ref()
            .ok_or_else(|| Error::RemoteSignError("tsa_cert not loaded".to_string()))?;
        let tst_info = generate_timestamp_tst(ctx.ts_req, tsa_cert)?;
        ctx.tst_info = tst_info;
        Ok(())
    }

    pub fn step_generate_timestamp_token(ctx: &mut CmsContext) -> Result<()> {
        let tsa_cert = ctx
            .tsa_cert
            .as_ref()
            .ok_or_else(|| Error::RemoteSignError("tsa_cert not loaded".to_string()))?;
        let tsa_key = ctx
            .tsa_key
            .as_ref()
            .ok_or_else(|| Error::RemoteSignError("tsa_key not loaded".to_string()))?;
        let tsa_key_type = ctx
            .timestamp_key_attributes
            .get("key_type")
            .map(|s| s.as_str())
            .unwrap_or("");
        let handler = cms_sign_handler(tsa_key_type);
        let timestamp = generate_timestamp_signature(
            tsa_cert,
            tsa_key,
            ctx.tst_info,
            ctx.timestamp_key_attributes,
            handler.as_ref(),
        )?;
        ctx.timestamp = timestamp;
        Ok(())
    }

    pub fn step_attach_timestamp(ctx: &mut CmsContext) -> Result<()> {
        let key_type = ctx
            .timestamp_key_attributes
            .get("key_type")
            .map(|s| s.as_str())
            .unwrap_or("");
        attach_timestamp_to_cms(ctx.cms, ctx.timestamp, key_type)?;
        Ok(())
    }

    pub fn cms_to_vec(cms: *mut CMS_ContentInfo, key_type: &str) -> Result<Vec<u8>> {
        struct BioGuard(*mut openssl_sys::BIO);
        impl Drop for BioGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { openssl_sys::BIO_free_all(self.0) };
                }
            }
        }
        let buf = unsafe {
            let out_bio = BIO_new(BIO_s_mem());
            let _guard = BioGuard(out_bio);
            if i2d_CMS_bio(out_bio, cms) != 1 {
                return Err(Error::InvalidArgumentError(
                    "i2d_CMS_bio failed".to_string(),
                ));
            }

            let mut ptr: *mut c_char = ptr::null_mut();
            let len = BIO_get_mem_data(out_bio, &mut ptr) as usize;
            if len == 0 || ptr.is_null() {
                return Err(Error::InvalidArgumentError(
                    "BIO_get_mem_data got empty buffer".to_string(),
                ));
            }

            let data_ptr = ptr as *const u8;
            slice::from_raw_parts(data_ptr, len).to_vec()
        };
        cms_sign_handler(key_type).patch_der(buf)
    }
}

#[cfg(test)]
const SM2_CRT: &str = "-----BEGIN CERTIFICATE-----
MIIB1DCCAXoCFGfoVD/6iDpHYUbmTA0+LH/b4tfuMAoGCCqBHM9VAYN1MGwxCzAJ
BgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRIw
EAYDVQQKDAlNeUNvbXBhbnkxDzANBgNVBAsMBlJvb3RDQTEUMBIGA1UEAwwLU00y
IFJvb3QgQ0EwHhcNMjUxMTAzMDgxODEyWhcNMzUxMTAxMDgxODEyWjBsMQswCQYD
VQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamluZzESMBAG
A1UECgwJTXlDb21wYW55MQ8wDQYDVQQLDAZSb290Q0ExFDASBgNVBAMMC1NNMiBS
b290IENBMFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABNYo1OwvitLruiU3oRAc
uaLSplc2Vrj19z2oPicvx8hn3fQLYlqKrKcFvKOWllL3ByQVcMJ4HmRylmOrk24q
4xYwCgYIKoEcz1UBg3UDSAAwRQIhAMnIl0Em/3b8hhR9Ly/FGlt3q2IN1EHLg64+
JGLqK0DFAiAULqROgRSmSWpJgMzU8KMoPfDM7CJ5/NCnDqI3oM9uTw==
-----END CERTIFICATE-----";
#[cfg(test)]
const SM2_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIDUaoPl+RCqHV/Un
qWcBnNWXVAOM7BMiiPWQFFotA1h0oUQDQgAE1ijU7C+K0uu6JTehEBy5otKmVzZW
uPX3Pag+Jy/HyGfd9AtiWoqspwW8o5aWUvcHJBVwwngeZHKWY6uTbirjFg==
-----END PRIVATE KEY-----";
#[cfg(test)]
const RSA_CRT: &str = "-----BEGIN CERTIFICATE-----
MIIDYTCCAkkCFElnH8LftfLwEwPJRQ3i0hF0XQl4MA0GCSqGSIb3DQEBCwUAMG0x
CzAJBgNVBAYTAkNOMQ0wCwYDVQQIDAR0ZXN0MQ0wCwYDVQQHDAR0ZXN0MQ0wCwYD
VQQKDAR0ZXN0MQ0wCwYDVQQLDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MRMwEQYJKoZI
hvcNAQkBFgR0ZXN0MB4XDTI1MTEwMzA3MDkyM1oXDTM1MTEwMTA3MDkyM1owbTEL
MAkGA1UEBhMCQ04xDTALBgNVBAgMBHRlc3QxDTALBgNVBAcMBHRlc3QxDTALBgNV
BAoMBHRlc3QxDTALBgNVBAsMBHRlc3QxDTALBgNVBAMMBHRlc3QxEzARBgkqhkiG
9w0BCQEWBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRFYHs
vLSybVatQSyKjNFkoiKpYvy8eD2SwJtUhX1aXgNi2JVV8YKf7ok0NxXQKFovhlP0
rB7NOFbPw9DYceS9UG6M/PgyhhxAAP/oY8Sr7+Kyz1uf85Q/gGM0wzA27OdgBhGe
BLv6Xg5MDSgXGAScnHTgTP4Ibt9b6xqV3jlw4dPYmaVnD24hBj1afsimgCEN2Iic
vE3cxFBd6zxTSQdU7tcrPlspAS1rmL5E0opIavE8RTOLnjlcFZH1Hcyl89V1u0vn
pRFllrTOtIKX7Px1yTlNXd6G1iaQgwzdLh8N1NxTgeFRwTOjW9cjeGbsfQwERdY6
4bBhaTQVBraR0FqjAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGNwWCzbVFD1bgST
lGXMSiCqi9H1UaQxJ4goq742qtoyCKkDEY+7289GmFPWufbK366kZBj52ibEMm7w
4Tp9jVnlf9amkSC15JdBLeHuDT8QRNWMwj+PgVHhcBt+9thwYTiM/mQoxCBJeFiS
vPDWEQxY9/OAh7lkZb+ZWrBxdz7wMa4UiBcfzpmT15vYkG0CvoLQPe73PDIszeF7
utx8jfSPlUWhLtZ72qcwNeh5QNPr4dclAPIf+mxkipS0QiuWLMmBOLg0AXIi7YeG
2E8IAhEIhpya/SkDBvGiju/8bp5r9x9OdOe61NGuqj86IqLoNWA3/bd03klZq1RA
WD1O4V0=
-----END CERTIFICATE-----";
#[cfg(test)]
const RSA_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDRFYHsvLSybVat
QSyKjNFkoiKpYvy8eD2SwJtUhX1aXgNi2JVV8YKf7ok0NxXQKFovhlP0rB7NOFbP
w9DYceS9UG6M/PgyhhxAAP/oY8Sr7+Kyz1uf85Q/gGM0wzA27OdgBhGeBLv6Xg5M
DSgXGAScnHTgTP4Ibt9b6xqV3jlw4dPYmaVnD24hBj1afsimgCEN2IicvE3cxFBd
6zxTSQdU7tcrPlspAS1rmL5E0opIavE8RTOLnjlcFZH1Hcyl89V1u0vnpRFllrTO
tIKX7Px1yTlNXd6G1iaQgwzdLh8N1NxTgeFRwTOjW9cjeGbsfQwERdY64bBhaTQV
BraR0FqjAgMBAAECggEAHm3CDAlF8Pu+/sBP8lVeegYArmSEwgxrxZ+jW4XWlvVn
X8DZMaSlgo9tchHG6mryU8f5uvo7vK6DhSw13keWZxjoEJEWXAqu3NUTE/1FF6gg
oYOnuDEeX67YgUrGNGV+TOLFOJlEHu1bqPoh3gPgU/Hkg+pLRECX4CGTVmv83G5g
c/tPT0HMOdXeKpJTzmepLN1QFSnrRbIT1D5uzx4VurVgM+eKXcWN8y2hfZkyeaG7
ZBW4efepN8gJRysVVAmNQGorMfp6gs26WRS8Se4OyiUthlRy47y1RDNO1mZl8jb/
im2X5BNiKocnLd08/oFozufrax7RqVoDnFhk0XhYTQKBgQDZOGYjT2IklXW2XAN+
9FMRk1LDPAJ4S8H1ITTO8K3AqgQJrE+4TJQSNuecq/wOHi1mTChlIdPkoMIWJHEa
vdQgKE4R/2UxLbnpS2uIwtk7UbOFBBicR3Fn/1eB4eFBr97Wv/Pw/8KngGkRANmL
aYnCEsssBvr0IL3Ri+um9C38pQKBgQD2aUGUBAJHMpFmS4gl0mqyjT1X6NoRIHnA
SZNZjsMREqBATrF8fj6+Cm8TptbL0rwheSOc+hugNW4XBOjt9qppe8TVxTj10lq1
Yi34DCdJ1qoPd7Nn/UKsv1jd0tvW0J7dKBcsq8lHzG7TOVa38iFzVO9WD62doKV0
RHl3ziFvpwKBgH3z/v2AfUb7RwsbpYdKwpQRWc8ND92TB/9MZuOLmSR7MOYu/Pa/
qKg7H+evrfK9utNzW4TwrX4HXSMbtF2uLr8Kv+Idth5jBkbpTYw6d123DSIW8vJD
VtXXsHUGdefxw4PAQAHBO6yGf+W1GW+GHbPj091OmttN1OMZf+YJ9lRlAoGAOey4
W8Etf+slPvTWhn2WU27cUsQMLyaBOHCTUOQ8etD0Funo0ykiOq5dOjNoHvXk/8Fo
W8h3ogutW3/t+bKYkL9loBMCttbCOA1iXQMOYU8zHvu2kuV4PP+mNk8RGshj7/0y
pW+km1o1WzYJaqhisKfwszxwRbOz8Ub/fuhX99UCgYEAjNSTN7iShFW5jQM8L5Pm
BlBogxETPW4TtTgI1xyFHfAY3ZYj+HO9vXLAmuwO6acgDzCSm7h+bfqOLSNPP5Ii
MnUQOZ522LfVOBzi42Hm3aobR4jex/X+3O+NJTi+UtTtfSNBeagkTdh6xORV8XOz
yQO9OpVlZivvOX7n6gjX1jM=
-----END PRIVATE KEY-----";

#[test]
fn test_generate_cms_with_rsa() {
    let cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let options = HashMap::new();

    let result = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &RsaSignHandler,
    );
    assert!(result.is_ok(), "CMS generation failed: {:?}", result.err());
}
#[test]
fn test_generate_cms_with_sm2_cert() {
    let cert = x509::X509::from_pem(SM2_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(SM2_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sm3".to_string());
    let options = HashMap::new();

    let result = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &Sm2SignHandler,
    );
    assert!(result.is_ok(), "CMS generation failed: {:?}", result.err());
}
#[test]
fn test_generate_cms_with_incorret_alg() {
    let cert = x509::X509::from_pem(SM2_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(SM2_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let options = HashMap::new();

    let result = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &Sm2SignHandler,
    );
    assert!(
        result.is_err(),
        "Expected error due to use incorret digest algorithm"
    );
}
#[test]
fn test_generate_timestamp_req() {
    let cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let options = HashMap::new();

    let cms = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &RsaSignHandler,
    )
    .expect("CMS generation failed");
    let ts_req = generate_timestamp_req(cms, &attributes);
    assert!(
        ts_req.is_ok(),
        "Timestamp request generation failed: {:?}",
        ts_req.err()
    );
}

#[test]
fn test_generate_timestamp_tst() {
    let cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let options = HashMap::new();

    let cms = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &RsaSignHandler,
    )
    .expect("CMS generation failed");
    let ts_req = generate_timestamp_req(cms, &attributes).expect("Failed to generate TS request");
    let tst_info = generate_timestamp_tst(ts_req, &cert).expect("TST info generation failed");
    assert!(!tst_info.is_null(), "TST info is null");
}

#[test]
fn test_generate_timestamp_signature() {
    let cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let options = HashMap::new();

    let cms = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &RsaSignHandler,
    )
    .expect("CMS generation failed");
    let ts_req = generate_timestamp_req(cms, &attributes).expect("Failed to generate TS request");
    let tst_info = generate_timestamp_tst(ts_req, &cert).expect("TST info generation failed");

    let tsa_cert = x509::X509::from_pem(SM2_CRT.as_bytes()).expect("Failed to load certificate");
    let tsa_pkey =
        pkey::PKey::private_key_from_pem(SM2_KEY.as_bytes()).expect("Failed to load private key");
    let mut tsa_pattributes = HashMap::new();
    tsa_pattributes.insert(attributes::DIGEST_ALGO.to_string(), "sm3".to_string());

    let tst = generate_timestamp_signature(
        &tsa_cert,
        &tsa_pkey,
        tst_info,
        &tsa_pattributes,
        &Sm2SignHandler,
    )
    .expect("TST generation failed");
    assert!(!tst.is_null(), "TST is null");
}

#[test]
fn test_attach_timestamp_to_cms() {
    let cert = x509::X509::from_pem(SM2_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(SM2_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sm3".to_string());
    let options = HashMap::new();

    let cms = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &Sm2SignHandler,
    )
    .expect("CMS generation failed");
    let ts_req = generate_timestamp_req(cms, &attributes).expect("Failed to generate TS request");
    let tst_info = generate_timestamp_tst(ts_req, &cert).expect("TST info generation failed");

    let tsa_cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let tsa_pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let mut tsa_pattributes = HashMap::new();
    tsa_pattributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());

    let tst = generate_timestamp_signature(
        &tsa_cert,
        &tsa_pkey,
        tst_info,
        &tsa_pattributes,
        &RsaSignHandler,
    )
    .expect("TST generation failed");
    attach_timestamp_to_cms(cms, tst, "rsa").expect("CMS Attach Timestamp failed");
}

#[cfg(test)]
const TEST_CRL1: &str = "-----BEGIN X509 CRL-----
MIIBaTBTAgEBMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRlc3RDQRcNMjYw
NTE1MDc0OTUyWhcNMjcwNTE1MDc0OTUyWqAOMAwwCgYDVR0UBAMCAQEwDQYJKoZI
hvcNAQELBQADggEBAJYVYGbT5pEx7kNCVxpf2m78Ds5TmfiwhvgvExb8Urb4yXxN
DhPmIKRCX9cOx5yIuF71b5xHMGauB8LNnn3b075pKIvCEbO/wiiAoenuZett471B
A7fQjVXa6Oq+MSC08Lit+5v18jGgYsViNU1nn4R3JcgbTqinZ1vgdVn+gPvwveFG
vhnR2+rGROGJSHKdC7+oEZgES3hnOk7KWF9NFx9a4MFg2t7l71YVJfDs6i2cIqbO
59uv05k5pneLJKbwcBihyqbs9HwSl8/E8J5o1x+oA0XM5Go+iyo4hlWTW3UOFhsW
YwpEaeUO3QmduMOpB+O6ww7f2QekWHDhyaohJik=
-----END X509 CRL-----";

#[cfg(test)]
const TEST_CRL2: &str = "-----BEGIN X509 CRL-----
MIIBajBUAgEBMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMMB1Rlc3RDQTIXDTI2
MDUxNTA3NTAwNVoXDTI3MDUxNTA3NTAwNVqgDjAMMAoGA1UdFAQDAgEBMA0GCSqG
SIb3DQEBCwUAA4IBAQC7smj0pZd0wErMIGsshL5trDZhGS1UhJojxOk39xkcMG/x
Vj3bziMSvJz0pP348Z0GgnCjYtYSM6GeTeX14i4CL72gu33B8foMtFAoiwc3+z+7
MaUnjHrtO71zuVYaaLt6CsNHLHQrR0tPShN5hGkXXDOO2vIAEuczlRzbb+QYYO2u
JsUUuil2N3FxqUWrFCdHTfOYqitSrwQ2CPumVrz4HVNdJsM5yKjGGC4oPhCG/wSQ
QwU3GfIi4LQjqPxKQtjotKlIG2Bqzqz2vQZYZinJQhiRk5GB2kgBDiBtjqhDE9U3
M0tldIMcAm/bwR3ahmMr8FFYnStbdcZhLPdt80FU
-----END X509 CRL-----";

#[test]
fn test_generate_cms_with_single_crl() {
    let cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let mut options = HashMap::new();
    options.insert(options::CRL.to_string(), TEST_CRL1.to_string());

    let result = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &RsaSignHandler,
    );
    assert!(
        result.is_ok(),
        "CMS with single CRL failed: {:?}",
        result.err()
    );
}

#[test]
fn test_generate_cms_with_multiple_crls() {
    let cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let mut options = HashMap::new();
    // 两个 CRL 块拼接在同一个字符串中
    let multi_crl = format!("{}\n{}", TEST_CRL1, TEST_CRL2);
    options.insert(options::CRL.to_string(), multi_crl);

    let result = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &RsaSignHandler,
    );
    assert!(
        result.is_ok(),
        "CMS with multiple CRLs failed: {:?}",
        result.err()
    );
}

#[test]
fn test_generate_cms_with_empty_crl() {
    let cert = x509::X509::from_pem(RSA_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(RSA_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sha256".to_string());
    let mut options = HashMap::new();
    options.insert(options::CRL.to_string(), String::new());

    let result = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &options,
        &attributes,
        &RsaSignHandler,
    );
    assert!(
        result.is_ok(),
        "CMS with empty CRL option failed: {:?}",
        result.err()
    );
}

#[test]
fn test_sm2_cms_der_oids() {
    // SM2_CONTENT_TYPE_OID (1.2.156.10197.6.1.4.2.2) - outer contentType
    const SM2_CONTENT_TYPE_BYTES: &[u8] = &[
        0x06, 0x0A, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x06, 0x01, 0x04, 0x02, 0x02,
    ];
    // SM2_ECONTENT_TYPE_OID (1.2.156.10197.6.1.4.2.1) - inner eContentType
    const SM2_ECONTENT_TYPE_BYTES: &[u8] = &[
        0x06, 0x0A, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x06, 0x01, 0x04, 0x02, 0x01,
    ];
    // pkcs7-signedData OID - must NOT appear in SM2 output
    const PKCS7_SIGNED_DATA_BYTES: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];

    let cert = x509::X509::from_pem(SM2_CRT.as_bytes()).expect("Failed to load certificate");
    let pkey =
        pkey::PKey::private_key_from_pem(SM2_KEY.as_bytes()).expect("Failed to load private key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sm3".to_string());

    let cms_ptr = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &HashMap::new(),
        &attributes,
        &Sm2SignHandler,
    )
    .expect("SM2 CMS generation failed");

    let der = CmsPlugin::cms_to_vec(cms_ptr, "sm2").expect("cms_to_vec failed");

    // Outer contentType must be SM2_CONTENT_TYPE_OID at the start of the DER
    assert_eq!(der[0], 0x30, "DER must start with SEQUENCE tag");
    let oid_start = der_seq_header_len(&der).expect("unexpected length encoding");
    assert_eq!(
        &der[oid_start..oid_start + SM2_CONTENT_TYPE_BYTES.len()],
        SM2_CONTENT_TYPE_BYTES,
        "outer contentType must be SM2_CONTENT_TYPE_OID"
    );

    // Inner eContentType must be SM2_ECONTENT_TYPE_OID somewhere in the DER
    let has_econtent = der
        .windows(SM2_ECONTENT_TYPE_BYTES.len())
        .any(|w| w == SM2_ECONTENT_TYPE_BYTES);
    assert!(
        has_econtent,
        "inner eContentType must be SM2_ECONTENT_TYPE_OID"
    );

    // pkcs7-signedData OID must NOT appear anywhere in the SM2 DER output
    let has_pkcs7 = der
        .windows(PKCS7_SIGNED_DATA_BYTES.len())
        .any(|w| w == PKCS7_SIGNED_DATA_BYTES);
    assert!(
        !has_pkcs7,
        "pkcs7-signedData OID must not appear in SM2 CMS output"
    );

    unsafe { CMS_ContentInfo_free(cms_ptr) };
}

#[test]
fn test_sm2_cms_timestamp_der_oids() {
    // SM2_CONTENT_TYPE_OID - must appear as outer contentType of both main CMS and embedded timestamp
    const SM2_CONTENT_TYPE_BYTES: &[u8] = &[
        0x06, 0x0A, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x06, 0x01, 0x04, 0x02, 0x02,
    ];
    const PKCS7_SIGNED_DATA_BYTES: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];

    let cert = x509::X509::from_pem(SM2_CRT.as_bytes()).expect("load SM2 cert");
    let pkey = pkey::PKey::private_key_from_pem(SM2_KEY.as_bytes()).expect("load SM2 key");
    let tsa_cert = x509::X509::from_pem(SM2_CRT.as_bytes()).expect("load SM2 (TSA) cert");
    let tsa_pkey =
        pkey::PKey::private_key_from_pem(SM2_KEY.as_bytes()).expect("load SM2 (TSA) key");
    let content = b"test content";

    let mut attributes = HashMap::new();
    attributes.insert(attributes::DIGEST_ALGO.to_string(), "sm3".to_string());
    let mut tsa_attributes = HashMap::new();
    tsa_attributes.insert(attributes::DIGEST_ALGO.to_string(), "sm3".to_string());

    // Build main SM2 CMS
    let cms = generate_cms_with_hash(
        &cert,
        &pkey,
        content,
        &HashMap::new(),
        &attributes,
        &Sm2SignHandler,
    )
    .expect("SM2 CMS generation failed");

    // Build timestamp token (outer contentType must still be SM2_CONTENT_TYPE_OID)
    let ts_req = generate_timestamp_req(cms, &attributes).expect("ts_req failed");
    let tst_info = generate_timestamp_tst(ts_req, &tsa_cert).expect("tst_info failed");
    let ts_token = generate_timestamp_signature(
        &tsa_cert,
        &tsa_pkey,
        tst_info,
        &tsa_attributes,
        &Sm2SignHandler,
    )
    .expect("timestamp signature failed");

    attach_timestamp_to_cms(cms, ts_token, "sm2").expect("attach timestamp failed");

    let der = CmsPlugin::cms_to_vec(cms, "sm2").expect("cms_to_vec failed");

    // Outer contentType of main CMS must be SM2_CONTENT_TYPE_OID
    assert_eq!(der[0], 0x30, "DER must start with SEQUENCE");
    let oid_start = der_seq_header_len(&der).expect("unexpected length encoding");
    assert_eq!(
        &der[oid_start..oid_start + SM2_CONTENT_TYPE_BYTES.len()],
        SM2_CONTENT_TYPE_BYTES,
        "main CMS outer contentType must be SM2_CONTENT_TYPE_OID"
    );

    // pkcs7-signedData OID must not appear anywhere (main CMS or embedded timestamp)
    let has_pkcs7 = der
        .windows(PKCS7_SIGNED_DATA_BYTES.len())
        .any(|w| w == PKCS7_SIGNED_DATA_BYTES);
    assert!(
        !has_pkcs7,
        "pkcs7-signedData OID must not appear in SM2 CMS+timestamp output"
    );

    // SM2_CONTENT_TYPE_OID must appear at least twice: once for main CMS, once for timestamp token
    let count = der
        .windows(SM2_CONTENT_TYPE_BYTES.len())
        .filter(|w| *w == SM2_CONTENT_TYPE_BYTES)
        .count();
    assert!(
        count >= 2,
        "SM2_CONTENT_TYPE_OID should appear at least twice (main + timestamp), found {}",
        count
    );

    // round-trip: re-parse the patched DER to verify structural correctness
    unsafe {
        let ptr = der.as_ptr();
        let reparsed = d2i_CMS_ContentInfo(
            std::ptr::null_mut(),
            &mut (ptr as *const u8),
            der.len() as c_int,
        );
        assert!(
            !reparsed.is_null(),
            "d2i_CMS_ContentInfo failed on patched SM2 DER"
        );
        CMS_ContentInfo_free(reparsed);
    }

    unsafe { CMS_ContentInfo_free(cms) };
}

// Builds a minimal fake DER SEQUENCE whose inner content is exactly `inner_len` bytes of zeros,
// preceded by the pkcs7-signedData OID, so patch_outer_content_type has something to replace.
#[cfg(test)]
fn make_fake_der(inner_len: usize) -> Vec<u8> {
    const OLD_OID: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];
    let payload_len = OLD_OID.len() + inner_len;
    let len_bytes = der_encode_length(payload_len);
    let mut buf = Vec::with_capacity(1 + len_bytes.len() + payload_len);
    buf.push(0x30);
    buf.extend_from_slice(&len_bytes);
    buf.extend_from_slice(OLD_OID);
    buf.extend_from_slice(&vec![0u8; inner_len]);
    buf
}

#[test]
fn test_patch_outer_content_type_length_boundaries() {
    const OLD_OID_LEN: usize = 11;
    const NEW_OID_LEN: usize = 12;
    // delta = NEW_OID_LEN - OLD_OID_LEN = 1; after patch inner_len grows by 1.
    // We pick inner_len values so the total SEQUENCE content crosses length-encoding boundaries:
    //   short form top: content == 0x7F  → after patch: 0x80 (needs 0x81 prefix)
    //   0xFF boundary:  content == 0xFF  → after patch: 0x100 (needs 0x82 prefix)
    let cases: &[usize] = &[
        0x7F - OLD_OID_LEN,  // total content before patch = 0x7F, after = 0x80
        0xFF - OLD_OID_LEN,  // total content before patch = 0xFF, after = 0x100
        0x80 - OLD_OID_LEN,  // already in 0x81 range before patch
        0x100 - OLD_OID_LEN, // already in 0x82 range before patch
    ];

    for &inner_len in cases {
        let fake = make_fake_der(inner_len);
        let patched = patch_outer_content_type(fake).expect("patch failed");

        // Tag must still be SEQUENCE
        assert_eq!(patched[0], 0x30, "inner_len={}: tag not 0x30", inner_len);

        // Parse the patched length field and verify it matches the actual body length.
        let header_len = der_seq_header_len(&patched).expect("header_len failed");
        let encoded_content_len = match patched[1] {
            n if n < 0x80 => n as usize,
            0x81 => patched[2] as usize,
            0x82 => ((patched[2] as usize) << 8) | patched[3] as usize,
            0x83 => {
                ((patched[2] as usize) << 16) | ((patched[3] as usize) << 8) | patched[4] as usize
            }
            other => panic!("unexpected length byte 0x{:02X}", other),
        };
        let actual_body_len = patched.len() - header_len;
        assert_eq!(
            encoded_content_len, actual_body_len,
            "inner_len={}: encoded length {} != actual body {}",
            inner_len, encoded_content_len, actual_body_len
        );

        // New OID must appear right after the header.
        const NEW_OID: &[u8] = &[
            0x06, 0x0A, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x06, 0x01, 0x04, 0x02, 0x02,
        ];
        assert_eq!(
            &patched[header_len..header_len + NEW_OID_LEN],
            NEW_OID,
            "inner_len={}: new OID not at expected position",
            inner_len
        );
    }
}
