use clap::CommandFactory;

use crate::Cli;

pub const HELP_TEMPLATE: &str = "\
{name} {version}

{about}

{usage-heading} {usage}

\x1b[4m\x1b[1mCommands:\x1b[0m\x1b[0m

{commands}

";

pub fn generate_help_text() -> &'static str {
    let cmd = Cli::command();

    let mut help_text = String::from("");

    // Iterate over top-level subcommands
    for subcommand in cmd.get_subcommands() {
        let name = subcommand.get_name();
        let about = subcommand.get_about().unwrap_or_default();
        // Add top-level subcommand info
        help_text.push_str(&format!("  \x1b[1m{:<12}\x1b[0m {}\n", name, about));

        // Check for nested subcommands
        for nested in subcommand.get_subcommands() {
            let nested_name = nested.get_name();
            let nested_about = nested.get_about().unwrap_or_default();

            // Add nested subcommand info
            help_text.push_str(&format!(
                "    \x1b[1m{:<10}\x1b[0m {}\n",
                nested_name, nested_about
            ));
        }
        help_text.push_str("\n");
    }

    // Make help_text a static string by leaking it (safe for help text)
    Box::leak(help_text.into_boxed_str())
}
