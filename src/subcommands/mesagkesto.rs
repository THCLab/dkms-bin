use clap::Subcommand;

use crate::{mesagkesto, CliError};

#[derive(Subcommand)]
pub enum MesagkestoCommands {
    Exchange {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        content: String,
        #[arg(short, long)]
        receiver: String,
    },
    Query {
        #[arg(short, long)]
        alias: String,
    },
}

pub async fn process_mesagkesto_command(command: MesagkestoCommands) -> Result<(), CliError> {
    match command {
        MesagkestoCommands::Exchange {
            content,
            receiver,
            alias,
        } => {
            println!(
                "{}",
                mesagkesto::handle_exchange(&alias, &content, &receiver)?
            );
        }
        MesagkestoCommands::Query { alias } => {
            let qry = mesagkesto::handle_pull(&alias)?;
            println!("{}", qry);
        }
    };
    Ok(())
}
