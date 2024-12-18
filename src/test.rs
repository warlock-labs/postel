#[cfg(test)]
pub(crate) mod helper {
    use once_cell::sync::Lazy;

    #[allow(dead_code)]
    pub(crate) static RUSTLS: Lazy<()> = Lazy::new(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
}
