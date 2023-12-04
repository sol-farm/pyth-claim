use serde::{Serialize, Deserialize};

/// base url component for fetching token amount and claim proof
pub const URL: &str = "https://airdrop.pyth.network/api/grant/v1/amount_and_proof";

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub amount: String,
    pub proof: String,
}


pub fn format_url(
    ecosystem: &str,
    identity: &str
) -> String {
    format!("{URL}?ecosystem={ecosystem}&identity={identity}")
}


pub async fn get_claim_proof(
    ecosystem: &str,
    identity: &str
) -> anyhow::Result<Root> {
    let client = reqwest::Client::new();
    let req = client.get(format_url(ecosystem, identity)).build()?;
    Ok(client.execute(req).await?.json().await?)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_format_url() {
        assert_eq!(
            "https://airdrop.pyth.network/api/grant/v1/amount_and_proof?ecosystem=kekchain&identity=l33tm0d3",
            format_url("kekchain", "l33tm0d3")
        );
    }
}