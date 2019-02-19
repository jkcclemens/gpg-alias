use clap::{App, Arg};

pub fn app<'a, 'b>() -> App<'a, 'b> {
  App::new(clap::crate_name!())
    .version(clap::crate_version!())
    .about(clap::crate_description!())
    .author(clap::crate_authors!())
    .help_message("prints help information")
    .version_message("prints version information")
    .version_short("v")

    .arg(Arg::with_name("sign-all")
      .short("s")
      .long("sign-all")
      .help("check for any unsigned aliases, sign them, then exit"))

    .arg(Arg::with_name("recipients")
      .short("r")
      .long("recipients")
      .help("prefixes each alias with `-r ` for use on the command line"))

    .arg(Arg::with_name("alias")
      .help("alias to print")
      .multiple(true)
      .required_unless("sign-all"))
}
