extern crate winresource;

use {
    std::{
        env,
        io,
    },
    winresource::WindowsResource,
};

fn main() -> io::Result<()> {
        // Compile the resource script
        if env::var_os("CARGO_CFG_WINDOWS").is_some() {
            let _ = WindowsResource::new()
                // This path can be absolute, or relative to your crate root.
                .set_icon("assets\\app.ico")
                .compile();
        }
    Ok(())
}