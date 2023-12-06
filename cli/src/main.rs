use proof_api::{format_url, get_claim_proof};
use pythnet_sdk::{accumulators::merkle::MerklePath, hashers::Hasher};
use solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig};
use solana_sdk::{signature::{read_keypair_file, Keypair}, signer::Signer, pubkey::PubkeyError, instruction::{Instruction, AccountMeta}, transaction::Transaction};
use token_dispenser::{SolanaHasher, get_receipt_pda, ClaimInfo, Identity, get_config_pda};
use std::str::FromStr;
use {
    anyhow::{anyhow, Result},
    clap::{Arg, ArgMatches, Command},
    config::Configuration,
};
use anchor_lang::{InstructionData, ToAccountMetas, AnchorSerialize, AccountDeserialize};
mod proof_api;

#[tokio::main]
pub async fn main() -> Result<()> {
    let matches = Command::new("rust-starter")
        .arg(config_flag())
        .arg(debug_flag())
        .subcommands(vec![Command::new("config")
            .about("configuration management commands")
            .subcommands(vec![Command::new("new")
                .aliases(["gen", "generate"])
                .about("create and save a new configuration file")
                .arg(keypair_type_flag())])])
        .subcommand(
            Command::new("claim")
            .about("claim some tokens fam")
            .arg(
                Arg::new("rpc-url")
                .long("rpc-url")
                .help("rpc endpoint to use")
            )
            .arg(
                Arg::new("keypair")
                .long("keypair")
                .help("keypair to use for claiming")
            )
            .arg(
                Arg::new("ecosystem")
                .long("ecosystem")
                .help("ecosystem to claim tokens for")
                .default_value("solana")
            )
        )
        .get_matches();

    let conf_path = matches.get_one::<String>("config").unwrap();
    let debug_log = matches.get_flag("debug");

    utils::init_logger(debug_log);

    process_matches(&matches, conf_path).await?;

    Ok(())
}

async fn process_matches(matches: &ArgMatches, conf_path: &str) -> Result<()> {
    match matches.subcommand() {
        Some(("config", c)) => match c.subcommand() {
            Some(("new", n)) => {
                let cfg = Configuration::new(n.get_one::<String>("keypair-type").unwrap());
                Ok(cfg.save(conf_path)?)
            }
            _ => Err(anyhow!("{INVALID_COMMAND}")),
        },
        Some(("claim", c)) => {
            let rpc = c.get_one::<String>("rpc-url").unwrap();
            let keypair = c.get_one::<String>("keypair").unwrap();
            let ecosystem = c.get_one::<String>("ecosystem").unwrap();
            let rpc = RpcClient::new(rpc.clone());
            let keypair = match read_keypair_file(keypair) {
                Ok(kp) => kp,
                Err(_) => {
                    let kp_data = tokio::fs::read_to_string(keypair).await?;
                    let kp_data = kp_data.trim_end_matches("\n");
                    Keypair::from_base58_string(kp_data)
                }
            };
            log::info!("retrieving proof");
            let proof = get_claim_proof(ecosystem, &keypair.pubkey().to_string()).await?;
            log::info!("{} claiming {} tokens", keypair.pubkey(),proof.amount);
            log::info!("proof {}", proof.proof);

            let decoded_proof = hex::decode(proof.proof.clone())?;

            let inclusion_proof = decoded_proof.chunks(20).filter_map(|chk| {
                let chk: [u8; 20] = chk.try_into().ok()?;
                Some(chk)
            }).collect::<Vec<_>>();

            let inclusion_proof = MerklePath::<SolanaHasher>::new(
                inclusion_proof
            );
            let claim_info = ClaimInfo {
                identity: Identity::Solana { pubkey: token_dispenser::ecosystems::ed25519::Ed25519Pubkey::from(
                    keypair.pubkey()
                )  },
                amount: u64::from_str(&proof.amount).unwrap(),
            };
            let claim_certificate = token_dispenser::ClaimCertificate {
                amount: proof.amount.parse()?,
                proof_of_identity: token_dispenser::IdentityCertificate::Solana {},
                proof_of_inclusion: inclusion_proof
            };
            let ix_data = token_dispenser::instruction::Claim {
                claim_certificate: claim_certificate
            };
            let pyth_mint = solana_sdk::pubkey::Pubkey::from_str("HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3").unwrap();
            let accounts = token_dispenser::accounts::Claim::populate(
                keypair.pubkey(),
                keypair.pubkey(),
                pyth_mint,
                spl_associated_token_account::get_associated_token_address(
                    &keypair.pubkey(),
                    &pyth_mint
                ),
                solana_sdk::pubkey::Pubkey::from_str("9aDZy2BkW84u667ZMcFJS5evABPDnvvF48tdqsidLGfh").unwrap(),
            );

            let mut accounts = accounts.to_account_metas(None);
            accounts.push(AccountMeta::new(
                get_receipt_pda(&claim_info.try_to_vec()?).0,
                false
            ));
            let ix_data = ix_data.data();
            let ix = Instruction {
                program_id: solana_sdk::pubkey::Pubkey::from_str("EXxqB6XPLczReFcZyigfbdowB6WGYtnkLYC4XZ2ae9ch").unwrap(),
                accounts: accounts,
                data: ix_data
            };
            let mut tx = Transaction::new_with_payer(
                &[ix],
                Some(&keypair.pubkey())
            );
            tx.sign(&vec![&keypair], rpc.get_latest_blockhash().await?);
            let sig = match rpc.send_transaction_with_config(
                &tx,
                RpcSendTransactionConfig {
                    skip_preflight: true,
                    ..Default::default()
                }
            ).await {
                Ok(sig) => sig,
                Err(err) => return Err(anyhow!("failed to send transaction {err:#?}"))
            };
            log::info!("sent transaction {sig}");


            Ok(())
        }
        _ => Err(anyhow!("{INVALID_COMMAND}")),
    }
}

fn config_flag() -> Arg {
    Arg::new("config")
        .long("config")
        .help("path to the configuration file")
        .default_value("config.yaml")
}

fn keypair_type_flag() -> Arg {
    Arg::new("keypair-type")
        .long("keypair-type")
        .help("type of keypair we are using")
        .required(true)
}

fn debug_flag() -> Arg {
    Arg::new("debug")
        .long("debug")
        .help("enable debug logging")
        .action(clap::ArgAction::SetTrue)
        .required(false)
}

const INVALID_COMMAND: &str = "invalid command, try running --help";


fn hashv(data: &[u8]) -> [u8; 20] {
    let bytes = solana_sdk::keccak::hashv(
        &[data]
    );
    let mut hash = [0_u8; 20];
    hash.copy_from_slice(&bytes.as_ref()[0..20]);
    hash
}