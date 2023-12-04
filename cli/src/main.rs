use {
    anyhow::{anyhow, Result},
    clap::{Arg, ArgMatches, Command},
    config::Configuration,
};

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
