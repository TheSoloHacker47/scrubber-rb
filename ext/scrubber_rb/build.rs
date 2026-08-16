fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Exposes the `ruby_lt_3_2` / `ruby_gte_3_1` style cfgs and, more
    // importantly, the link flags the extension needs on each platform.
    let _ = rb_sys_env::activate()?;
    Ok(())
}
