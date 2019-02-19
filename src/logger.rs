use log::Level;
use ansi_term::Colour;

pub fn set_up_logger() -> Result<(), fern::InitError> {
  fern::Dispatch::new()
    .format(|out, message, record| {
      out.finish(format_args!(
        "[{}] {}",
        coloured_level(record.level()),
        message,
      ))
    })
    .filter(|meta| meta.target().starts_with("gpg_alias"))
    .level(log::LevelFilter::Info)
    .chain(std::io::stderr())
    .apply()?;
  Ok(())
}

fn coloured_level(level: Level) -> ansi_term::ANSIGenericString<'static, str> {
  match level {
    Level::Trace => Colour::Fixed(243).paint("TRACE"),
    Level::Debug => ansi_term::ANSIGenericString::from("DEBUG"),
    Level::Info => Colour::Blue.paint("INFO"),
    Level::Warn => Colour::Yellow.paint("WARN"),
    Level::Error => Colour::Red.paint("ERROR"),
  }
}
