use serde::{Deserialize, Serialize};
/// The KeypairType enum is used to allow handling multiple different
/// types of keypairs being stored in a configuration file in a dependency
/// free manner
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KeypairType {
    /// indicates this keypair type is a file stored at the given path
    FileBased { value: String },
    /// indicates this keypair type is an encoded private key.
    /// the actual encoding method will depend on the library
    /// using this template, but is likely to be hex encoded
    Private { value: String },
    /// indicates this keypair is a hardware wallet
    Hardware { value: String },
}

impl KeypairType {
    pub fn is_hw(&self) -> bool {
        matches!(self, Self::Hardware { .. })
    }
    pub fn is_file_based(&self) -> bool {
        matches!(self, Self::FileBased { .. })
    }
    pub fn is_private_key(&self) -> bool {
        matches!(self, Self::Private { .. })
    }
    pub fn contents(&self) -> String {
        match self {
            Self::FileBased { value } => value.clone(),
            Self::Hardware { value } => value.clone(),
            Self::Private { value } => value.clone(),
        }
    }
}

impl Default for KeypairType {
    fn default() -> Self {
        Self::Private {
            value: "replaceme".to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_keypair_type() {
        let default_keypair = KeypairType::default();
        assert!(default_keypair.is_private_key());
        assert!(!default_keypair.is_file_based());
        assert!(!default_keypair.is_hw());
        assert_eq!(&default_keypair.contents(), "replaceme");
        let file_keypair = KeypairType::FileBased {
            value: "foobar".to_string(),
        };
        assert!(file_keypair.is_file_based());
        assert!(!(file_keypair.is_private_key()));
        assert!(!file_keypair.is_hw());
        assert_eq!(&file_keypair.contents(), "foobar");
        let hw_keypair = KeypairType::Hardware {
            value: "chad".to_string(),
        };
        assert!(!hw_keypair.is_private_key());
        assert!(!hw_keypair.is_file_based());
        assert!(hw_keypair.is_hw());
        assert_eq!(&hw_keypair.contents(), "chad");
    }
}
