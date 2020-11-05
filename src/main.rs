use std::error::Error;

mod args;
use args::{Args, Command};
mod database;
use database::Database;
mod charset;
mod commands;
use commands::{bruteforce, gen_htable, use_htable};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();
    match args.command {
        Command::AddUser(args) => Database::with(|db| {
            db.records
                .insert(args.username.clone(), md5::compute(args.password).to_vec());
            println!("User {} added to database", args.username);
            Ok(())
        }),
        Command::ListUsers(_) => Database::with(|db| {
            println!("Users:");
            for k in db.records.keys() {
                println!("  - {}", k);
            }
            Ok(())
        }),
        Command::Auth(args) => Database::with(|db| {
            let entered = md5::compute(args.password);
            match db.records.get(&args.username) {
                Some(stored) if stored == entered.as_ref() => {
                    println!("Authentication successful!");
                }
                Some(_) => {
                    println!("Bad password.");
                }
                None => {
                    println!("No such user.");
                }
            }
            Ok(())
        }),
        Command::BruteForce(_) => bruteforce(),
        Command::GenHTable(_) => gen_htable(),
        Command::UseHTable(_) => use_htable(),
    }?;

    Ok(())
}
