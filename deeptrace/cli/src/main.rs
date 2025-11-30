use clap::Parser;
use core::*;

#[derive(Parser)]
struct Opts {
    #[arg(long)]
    ui: bool,

    #[arg(short, long, default_value = "en0")]
    iface: String,
}


fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    if opts.ui {
        println!("Starting UI...");
        ui::start_ui();
        return Ok(());
    }

    let mut cap = capture::LiveCapture::open(&opts.iface)
        .expect("cannot open network interface");

    println!("Listening on default interface... Ctrl+C to exit.\n");

    loop {
        if let Some(data) = cap.next() {
            println!("{}", hex_dump(&data));
        }
    }

    // Ok(())
}
