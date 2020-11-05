use argh::FromArgs;

/// Experiment with passwords.
#[derive(FromArgs)]
pub struct Args {
    #[argh(subcommand)]
    pub command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum Command {
    AddUser(AddUser),
    ListUsers(ListUsers),
    Auth(Auth),
    BruteForce(BruteForce),
    GenHTable(GenHTable),
    UseHTable(UseHTable),
}

#[derive(FromArgs)]
/// Add a user to the database
#[argh(subcommand, name = "add-user")]
pub struct AddUser {
    #[argh(positional)]
    pub username: String,

    #[argh(positional)]
    pub password: String,
}

#[derive(FromArgs)]
/// List users
#[argh(subcommand, name = "list-users")]
pub struct ListUsers {}

#[derive(FromArgs)]
/// Authenticate as a user
#[argh(subcommand, name = "auth")]
pub struct Auth {
    #[argh(positional)]
    pub username: String,

    #[argh(positional)]
    pub password: String,
}

#[derive(FromArgs)]
/// Authenticate as a user
#[argh(subcommand, name = "bruteforce")]
pub struct BruteForce {}

#[derive(FromArgs)]
/// Generate a hash table
#[argh(subcommand, name = "gen-htable")]
pub struct GenHTable {}

#[derive(FromArgs)]
/// Use a hash table
#[argh(subcommand, name = "use-htable")]
pub struct UseHTable {}
