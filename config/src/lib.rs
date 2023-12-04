//! a bare bones configuration file template with minimal dependencies
//! suitable for customization to a variety of needs

use keypair::KeypairType;
use {
    anyhow::{Context, Result},
    serde::{Deserialize, Serialize},
};

pub mod keypair;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Configuration {
    pub keypair: keypair::KeypairType,
}

impl Configuration {
    pub fn new(keypair_type: &str) -> Self {
        let kp = if keypair_type.eq_ignore_ascii_case("hardware")
            || keypair_type.eq_ignore_ascii_case("hw")
        {
            KeypairType::Hardware {
                value: "replaceme".to_string(),
            }
        } else if keypair_type.eq_ignore_ascii_case("file")
            || keypair_type.eq_ignore_ascii_case("file_base")
        {
            KeypairType::FileBased {
                value: "replaceme".to_string(),
            }
        } else {
            log::warn!("invalid key type {keypair_type} using private key as default");
            KeypairType::Private {
                value: "replaceme".to_string(),
            }
        };
        Self {
            keypair: kp,
            ..Default::default()
        }
    }
    pub fn save(&self, file_path: &str) -> Result<()> {
        let file_path = if !(file_path.ends_with(".yaml") || file_path.ends_with(".yml")) {
            format!("{file_path}.yaml")
        } else {
            file_path.to_string()
        };
        std::fs::write(file_path, serde_yaml::to_string(self)?).with_context(|| SAVE_FAILURE)?;
        Ok(())
    }
    pub fn load(file_path: &str) -> Result<Self> {
        serde_yaml::from_str(&std::fs::read_to_string(file_path).with_context(|| LOAD_FAILURE)?)
            .with_context(|| DESERIALIZE_FAILURE)
    }
}

const SAVE_FAILURE: &str = "failed to save file";
const LOAD_FAILURE: &str = "failed to load file";
const DESERIALIZE_FAILURE: &str = "failed to deserialize";

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_config() {
        let conf_pk = Configuration::default();
        let conf_fh = Configuration::new("file");
        let conf_hw = Configuration::new("hardware");

        conf_pk.save("conf_pk.yaml").unwrap();
        conf_fh.save("conf_fh.yaml").unwrap();
        conf_hw.save("conf_hw.yaml").unwrap();

        let got_conf_pk = Configuration::load("conf_pk.yaml").unwrap();
        let got_conf_fh = Configuration::load("conf_fh.yaml").unwrap();
        let got_conf_hw = Configuration::load("conf_hw.yaml").unwrap();

        let conf_pk_str = serde_yaml::to_string(&conf_pk).unwrap();
        let conf_fh_str = serde_yaml::to_string(&conf_fh).unwrap();
        let conf_hw_str = serde_yaml::to_string(&conf_hw).unwrap();

        let got_conf_pk_str = serde_yaml::to_string(&got_conf_pk).unwrap();
        let got_conf_fh_str = serde_yaml::to_string(&got_conf_fh).unwrap();
        let got_conf_hw_str = serde_yaml::to_string(&got_conf_hw).unwrap();

        assert_eq!(conf_pk_str, got_conf_pk_str);
        assert_eq!(conf_fh_str, got_conf_fh_str);
        assert_eq!(conf_hw_str, got_conf_hw_str);

        std::fs::remove_file("conf_pk.yaml").unwrap();
        std::fs::remove_file("conf_fh.yaml").unwrap();
        std::fs::remove_file("conf_hw.yaml").unwrap();
    }
}
