//! Standalone mailbox binary entrypoint.

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);
    let host = std::env::var("MAILBOX_BIND").unwrap_or_else(|_| "127.0.0.1".into());
    let addr = frostwall_mailbox::parse_listen_addr(&host, port).unwrap_or_else(|e| {
        eprintln!("frostwall-mailbox: {e}");
        std::process::exit(1);
    });

    tracing::info!("frostwall-mailbox listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind mailbox listener");
    frostwall_mailbox::run(listener).await;
}
