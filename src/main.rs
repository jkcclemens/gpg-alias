#[macro_use] extern crate log;

use gpgme::{Context, Protocol, SignatureSummary, results::Signature};
use serde_derive::Deserialize;

use std::{
  collections::HashMap,
  fs::{File, OpenOptions},
  path::PathBuf,
  io::{Read, Write},
};

mod logger;
mod cli;

const DEFAULT_CONFIG: &str = include_str!("../config.example.toml");

fn main() {
  std::process::exit(inner());
}

fn inner() -> i32 {
  gpgme::init();

  if let Err(e) = logger::set_up_logger() {
    eprintln!("could not set up logger: {}", e);
    return 1;
  }

  let matches = self::cli::app().get_matches();
  let aliases: Vec<&str> = matches.values_of("alias").expect("required clap argument").collect();
  debug!("aliases requested: {:?}", aliases);

  let config_dir = match dirs::config_dir() {
    Some(c) => c.join("gpg-alias"),
    None => {
      error!("could not find a config directory");
      return 1;
    },
  };

  if let Err(e) = std::fs::create_dir_all(&config_dir) {
    error!("could not create {}: {}", config_dir.to_string_lossy(), e);
    return 1;
  }

  let config_path = config_dir.join("gpg-alias.toml");
  let config_existed = config_path.exists();
  let mut config_file = match OpenOptions::new()
    .write(true)
    .read(true)
    .create(true)
    .open(&config_path)
  {
    Ok(f) => f,
    Err(e) => {
      error!("could not open {}: {}", config_path.to_string_lossy(), e);
      return 1;
    },
  };
  if !config_existed {
    if let Err(e) = config_file.write_all(DEFAULT_CONFIG.as_bytes()) {
      error!("could not write default config: {}", e);
      return 1;
    }
  }
  let config_file = match std::fs::read_to_string(&config_path) {
    Ok(s) => s,
    Err(e) => {
      error!("could not read {}: {}", config_path.to_string_lossy(), e);
      return 1;
    },
  };

  let config: Config = match toml::from_str(&config_file) {
    Ok(c) => c,
    Err(e) => {
      error!("could not parse config file: {}", e);
      return 1;
    },
  };

  trace!("{:?}", config);

  for (i, alias) in aliases.iter().enumerate() {
    debug!("{} - {}", i, alias);

    let key_id = match config.aliases.get(*alias) {
      Some(k) => k,
      None => {
        error!("no such alias found");
        return 1;
      },
    };

    if config.signing.enabled {
      if let Err(exit) = check_signature(&config, alias, &key_id) {
        return exit;
      }
    }

    if matches.is_present("recipients") {
      print!("-r {}", key_id);

      if i < aliases.len() - 1 {
        print!(" ");
      }
    } else {
      println!("{}", key_id);
    }
  }

  if matches.is_present("recipients") {
    if let Err(_) = std::io::stdout().flush() {
      error!("could not flush stdout");
      return 1;
    }
  }

  0
}

#[derive(Debug, Deserialize)]
struct Config {
  signing: Signing,
  aliases: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct Signing {
  enabled: bool,
  key: String,
}

fn check_signature(config: &Config, alias: &str, id: &str) -> Result<bool, i32> {
  let data_dir = match dirs::data_dir() {
    Some(d) => d,
    None => {
      error!("could not find data dir");
      return Err(1);
    },
  };

  let data_dir = data_dir.join("gpg-alias");
  if let Err(e) = std::fs::create_dir_all(&data_dir) {
    error!("could not create {}: {}", data_dir.to_string_lossy(), e);
    return Err(1);
  }

  let alias_sig = data_dir.join(format!("{}.asc", alias));
  if alias_sig.exists() {
    return check_existing_signature(config, id, alias_sig);
  }

  create_signature(config, alias, id, alias_sig)
}

fn check_existing_signature(config: &Config, id: &str, sig_path: PathBuf) -> Result<bool, i32> {
  let mut file = match File::open(&sig_path) {
    Ok(f) => f,
    Err(e) => {
      error!("could not open signature file {}: {}", sig_path.to_string_lossy(), e);
      return Err(1);
    },
  };

  let mut signed = Vec::new();
  if let Err(e) = file.read_to_end(&mut signed) {
    error!("could not read signature file: {}", e);
    return Err(1);
  }

  let mut ctx = match Context::from_protocol(Protocol::OpenPgp) {
    Ok(c) => c,
    Err(e) => {
      error!("could not created gpgme context: {}", e);
      return Err(1);
    },
  };
  let mut plaintext = Vec::new();
  let verify_res = match ctx.verify_opaque(signed, &mut plaintext) {
    Ok(res) => res,
    Err(e) => {
      error!("could not verify signature: {}", e);
      return Err(1);
    },
  };

  let plaintext_str = match std::str::from_utf8(&plaintext) {
    Ok(s) => s.trim_end(),
    Err(e) => {
      error!("could not create utf-8 string from signed data: {}", e);
      return Err(1);
    },
  };

  if plaintext_str != id {
    error!("invalid signed content: key does not match (`{}` != `{}`)", plaintext_str, id);
    return Err(1);
  }

  let sigs: Vec<Signature> = verify_res.signatures().collect();
  if sigs.len() != 1 {
    error!("invalid number of signatures: expected 1, got {}", sigs.len());
    return Err(1);
  }

  if !sigs[0].summary().contains(SignatureSummary::VALID) {
    error!("invalid signature");
    return Err(1);
  }

  let fingerprint = match sigs[0].fingerprint() {
    Ok(f) => f,
    Err(_) => {
      error!("invalid fingerprint on key signature was made by");
      return Err(1);
    },
  };

  let expected_key = match ctx.get_key(&config.signing.key) {
    Ok(k) => k,
    Err(e) => {
      error!("could not get signing key: {}", e);
      return Err(1);
    },
  };

  if expected_key.fingerprint() != Ok(fingerprint) {
    if expected_key.subkeys().all(|x| x.fingerprint() != Ok(fingerprint)) {
      error!("signature made by wrong key (got {})", fingerprint);
      return Err(1);
    }
  }

  Ok(true)
}

fn create_signature(config: &Config, alias: &str, id: &str, sig_path: PathBuf) -> Result<bool, i32> {
  warn!("no signature for alias `{}`", alias);
  info!("Please stop to read this message. gpg-alias did not find a signature for the alias called `{}`.", alias);
  info!("If you just added this alias, this is normal, and you will need to verify the key ID for the alias.");
  warn!("Alias `{}` points to key ID `{}`.", alias, id);

  print!("Is this correct? [y/N] ");
  std::io::stdout().flush().map_err(|_| 1)?;
  let mut resp = String::with_capacity(1);
  std::io::stdin().read_line(&mut resp).map_err(|_| 1)?;
  if resp.trim_end().to_ascii_lowercase() != "y" {
    error!("no signature found for alias `{}` and creating a new signature was not authorised", alias);
    return Err(1);
  }

  info!("creating signature for alias `{}`. you may need to enter your pgp passphrase", alias);

  let mut ctx = match Context::from_protocol(Protocol::OpenPgp) {
    Ok(c) => c,
    Err(e) => {
      error!("could not created gpgme context: {}", e);
      return Err(1);
    },
  };
  ctx.clear_signers();
  let key = match ctx.get_key(&config.signing.key) {
    Ok(k) => k,
    Err(e) => {
      error!("missing signing key: {}", e);
      return Err(1);
    },
  };
  if let Err(e) = ctx.add_signer(&key) {
    error!("could not add signing key as a signer: {}", e);
    return Err(1);
  }
  let mut signed = Vec::new();
  if let Err(e) = ctx.sign_clear(id, &mut signed) {
    error!("could not create signature: {}", e);
    return Err(1);
  }

  let mut file = match File::create(&sig_path) {
    Ok(f) => f,
    Err(e) => {
      error!("could not create {}: {}", sig_path.to_string_lossy(), e);
      return Err(1);
    },
  };
  if let Err(e) = file.write_all(&signed) {
    error!("could not write signature file: {}", e);
    return Err(1);
  }

  Ok(true)
}
