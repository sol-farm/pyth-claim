pub use tracing;

// initializes a logger using json formatted logs
pub fn init_logger(debug: bool) {
    tracing_subscriber::fmt()
        .with_max_level(if debug {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .json()
        .init();
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_logger() {
        std::thread::spawn(|| {
            init_logger(true);
            log::info!("info log");
            log::debug!("debug log");
        })
        .join()
        .unwrap();
    }
}
