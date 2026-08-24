use super::error::{Error, Result};
use std::fmt::{Display, Formatter, Result as fmtResult};
use std::str::FromStr;

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignType {
    Cms,          // signed method for a CMS signed data
    KernelCms,    // signed method for a kernel CMS signed data
    Authenticode, // signed method for signing EFI image using authenticode spec
    PKCS7,        // signed method for a pkcs7 signed data
    RsaHash,      // signed method for a ima eam using rsa hash
}

impl Display for SignType {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            SignType::Cms => write!(f, "cms"),
            SignType::KernelCms => write!(f, "kernel-cms"),
            SignType::Authenticode => write!(f, "authenticode"),
            SignType::PKCS7 => write!(f, "pkcs7"),
            SignType::RsaHash => write!(f, "rsahash"),
        }
    }
}

impl FromStr for SignType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cms" => Ok(SignType::Cms),
            "kernel-cms" => Ok(SignType::KernelCms),
            "authenticode" => Ok(SignType::Authenticode),
            "pkcs7" => Ok(SignType::PKCS7),
            "rsahash" => Ok(SignType::RsaHash),
            _ => Err(Error::ParameterError("Invalid sign_type param".to_string())),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    Rpm,
    Generic,
    KernelModule,
    EfiImage,
    ImaEvm,
    P7s,
}

impl Display for FileType {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            FileType::Rpm => write!(f, "rpm"),
            FileType::Generic => write!(f, "generic"),
            FileType::KernelModule => write!(f, "ko"),
            FileType::EfiImage => write!(f, "efi"),
            FileType::ImaEvm => write!(f, "ima"),
            FileType::P7s => write!(f, "p7s"),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum KeyType {
    Pgp,
    X509,
    X509EE,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            KeyType::Pgp => write!(f, "pgp"),
            KeyType::X509EE => write!(f, "x509ee"),
            //client can use 'x509' to specify a x509 key type for the purpose of simplicity.
            KeyType::X509 => write!(f, "x509ee"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== SignType ==========

    #[test]
    fn test_sign_type_display() {
        assert_eq!(format!("{}", SignType::Cms), "cms");
        assert_eq!(format!("{}", SignType::KernelCms), "kernel-cms");
        assert_eq!(format!("{}", SignType::Authenticode), "authenticode");
        assert_eq!(format!("{}", SignType::PKCS7), "pkcs7");
        assert_eq!(format!("{}", SignType::RsaHash), "rsahash");
    }

    #[test]
    fn test_sign_type_from_str_valid() {
        assert_eq!(SignType::from_str("cms").unwrap(), SignType::Cms);
        assert_eq!(
            SignType::from_str("kernel-cms").unwrap(),
            SignType::KernelCms
        );
        assert_eq!(
            SignType::from_str("authenticode").unwrap(),
            SignType::Authenticode
        );
        assert_eq!(SignType::from_str("pkcs7").unwrap(), SignType::PKCS7);
        assert_eq!(SignType::from_str("rsahash").unwrap(), SignType::RsaHash);
    }

    #[test]
    fn test_sign_type_from_str_invalid() {
        assert!(SignType::from_str("unknown").is_err());
    }

    #[test]
    fn test_sign_type_roundtrip() {
        for st in &[
            SignType::Cms,
            SignType::KernelCms,
            SignType::Authenticode,
            SignType::PKCS7,
            SignType::RsaHash,
        ] {
            let s = format!("{}", st);
            let parsed = SignType::from_str(&s).unwrap();
            assert_eq!(*st, parsed);
        }
    }

    // ========== FileType ==========

    #[test]
    fn test_file_type_display() {
        assert_eq!(format!("{}", FileType::Rpm), "rpm");
        assert_eq!(format!("{}", FileType::Generic), "generic");
        assert_eq!(format!("{}", FileType::KernelModule), "ko");
        assert_eq!(format!("{}", FileType::EfiImage), "efi");
        assert_eq!(format!("{}", FileType::ImaEvm), "ima");
        assert_eq!(format!("{}", FileType::P7s), "p7s");
    }

    // ========== KeyType ==========

    #[test]
    fn test_key_type_display() {
        assert_eq!(format!("{}", KeyType::Pgp), "pgp");
        assert_eq!(format!("{}", KeyType::X509EE), "x509ee");
        assert_eq!(format!("{}", KeyType::X509), "x509ee");
    }
}
