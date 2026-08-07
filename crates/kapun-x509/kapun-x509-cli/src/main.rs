use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand, ValueEnum};
use josekit::{jwk::Jwk, Value};
use kapun_x509::x509_parser::{
    self,
    prelude::{oid_registry, X509Certificate},
};
use oid_registry::{
    OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA,
    OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512, OID_SIG_ED25519, OID_SIG_ED448,
};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts};

/// Small tool to verify/look at simple x509 certificates and chains
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of times to greet
    #[arg(short, long)]
    certificate: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Get either bei oid or by predefined "Keywords"
    Get {
        #[arg(short, long)]
        oid: Option<String>,
        #[arg(value_enum)]
        what: Option<What>,
    },
    Validate {
        /// Validate the certificate and optionally the chain
        #[arg(short, long)]
        chain: Option<String>,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum What {
    Crl,
    BasicConstraint,
    Issuer,
    Subject,
    San,
    PublicKey,
    BasicInfo,
}

fn main() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .try_init();
    let cli = Args::parse();
    let mut cert_bytes = std::fs::read(&cli.certificate).expect("File does not exist");

    let (_, cert) = match std::str::from_utf8(&cert_bytes) {
        Ok(c) => {
            let pem_content = pem::parse(c).expect("Invalid PEM");
            cert_bytes = pem_content.into_contents();
            x509_parser::parse_x509_certificate(&cert_bytes).expect("Failed to parse x509")
        }
        Err(_) => x509_parser::parse_x509_certificate(&cert_bytes).expect("Failed to parse x509"),
    };
    match cli.command {
        Commands::Get {
            oid: Some(oid_str),
            what: None,
        } => {
            let extension = cert
                .get_extension_unique(&oid_str.parse().expect("invalid oid"))
                .expect("Failed to parse extension");
            match extension {
                Some(ext) => println!("{ext:?}"),
                None => println!("extension not found"),
            }
        }
        Commands::Get {
            oid: None,
            what: Some(reference),
        } => match reference {
            What::Crl => {
                let uri = kapun_x509::x509::get_crl_uri(&cert).expect("Failed to parse extension");
                match uri {
                    Some(uri) => println!("{uri}"),
                    None => println!("No crl found"),
                }
            }
            What::BasicConstraint => {
                let Some(basic_constraints) = cert
                    .basic_constraints()
                    .expect("Failed to parse basic constraints")
                else {
                    println!("No basic constraints found");
                    return;
                };
                println!("{:?}", basic_constraints)
            }
            What::Issuer => {
                println!(
                    "{}",
                    cert.issuer()
                        .to_string_with_registry(oid_registry())
                        .expect("Failed to format string")
                )
            }
            What::Subject => println!(
                "{}",
                cert.subject()
                    .to_string_with_registry(oid_registry())
                    .expect("Failed to format string")
            ),
            What::San => {
                let sans = cert
                    .subject_alternative_name()
                    .expect("Failed to parse SAN");
                let Some(sans) = sans else {
                    println!("No subject alternative name found");
                    return;
                };
                for name in &sans.value.general_names {
                    println!("- {}", name.to_string())
                }
            }
            What::BasicInfo => {
                print_info(&cert);
            }
            What::PublicKey => {
                print_public_key(&cert);
            }
        },
        Commands::Validate { chain } => {
            if let Some(chain) = chain {
                let chain = std::fs::read_to_string(&chain).expect("Expected a PEM file");
                let many = pem::parse_many(&chain).expect("failed to parse chain");
                let mut certs_array = many
                    .into_iter()
                    .map(|a| a.contents().to_vec())
                    .collect::<Vec<_>>();
                let certs = certs_array
                    .iter()
                    .map(|a| x509_parser::parse_x509_certificate(a).unwrap().1)
                    .collect::<Vec<_>>();

                let i = certs
                    .iter()
                    .enumerate()
                    .find(|a| a.1.serial == cert.serial)
                    .map(|a| a.0);

                match i {
                    Some(i) => {
                        println!("Chain length: {}", certs.len());
                        let mut certs = certs.clone();

                        if i == certs.len() - 1 {
                            certs.reverse();
                            for c in certs {
                                print_info(&c)
                            }
                            certs_array.reverse();
                        } else {
                            for c in certs {
                                print_info(&c)
                            }
                        }

                        let res = kapun_x509::x509::verify_chain(certs_array);
                        println!();
                        println!();
                        println!("Certificate Chain valid: {}", res);
                    }
                    None => {
                        println!("Chain length: {}", certs.len() + 1);
                        let mut certs = certs.clone();
                        certs.push(cert.clone());
                        certs.reverse();
                        for c in certs {
                            println!();
                            print_info(&c);
                            println!();
                        }
                        certs_array.reverse();
                        let res = kapun_x509::x509::verify_chain(certs_array);
                        println!();
                        println!();
                        println!("Certificate Chain valid: {}", res);
                        println!();
                    }
                }
            }
            let revocation_status =
                kapun_x509::x509::check_revocation(&cert).expect("Failed to check revocation");
            println!("[Revocation status Leaf] Certificate is revoked: {revocation_status}");
        }
        _ => panic!("Unknown command"),
    }
}

fn print_info(cert: &X509Certificate) {
    println!(
        "Subject: {}",
        cert.subject()
            .to_string_with_registry(oid_registry())
            .expect("Failed to format string")
    );
    println!();
    println!(
        "Issuer: {}",
        cert.issuer()
            .to_string_with_registry(oid_registry())
            .expect("Failed to format string")
    );
    let sans = cert
        .subject_alternative_name()
        .expect("Failed to parse SAN");
    match sans {
        Some(sans) => {
            println!();
            println!("Subject Alternative Names:");
            for name in &sans.value.general_names {
                println!("- {}", name.to_string())
            }
        }
        None => {
            println!("No subject alternative name found");
        }
    }
    println!();
    let uri = kapun_x509::x509::get_crl_uri(&cert).expect("Failed to parse extension");
    match uri {
        Some(uri) => println!("CRL: {uri}"),
        None => println!("No crl found"),
    }
    let revocation_status =
        kapun_x509::x509::check_revocation(&cert).expect("Failed to check revocation");
    println!("[Revocation status] Certificate is revoked: {revocation_status}");
    println!();
    println!();
}

fn print_public_key(cert: &X509Certificate) {
    let public_key = cert.public_key();
    let subject_alg = public_key.algorithm.algorithm.clone();
    if subject_alg == OID_PKCS1_SHA256WITHRSA
        || subject_alg == OID_PKCS1_SHA384WITHRSA
        || subject_alg == OID_PKCS1_SHA512WITHRSA
    {
        println!("RSA public key [PKCS1]");
        let key_pair = josekit::jws::RS256
            .key_pair_from_der(public_key.raw)
            .expect("Invalid RSA key pair");
        println!(
            "{}",
            serde_json::to_string_pretty(&key_pair.to_jwk_public_key())
                .expect("Failed to serialize")
        );
    } else if subject_alg == OID_PKCS1_RSASSAPSS {
        println!("RSA public key [PSS]");
        let key_pair = josekit::jws::PS256
            .key_pair_from_der(public_key.raw)
            .expect("Invalid RSA key pair");
        println!(
            "{}",
            serde_json::to_string_pretty(&key_pair.to_jwk_public_key())
                .expect("Failed to serialize")
        );
    } else if subject_alg == OID_KEY_TYPE_EC_PUBLIC_KEY
        || subject_alg == OID_SIG_ECDSA_WITH_SHA384
        || subject_alg == OID_SIG_ECDSA_WITH_SHA512
    {
        println!("ECDSA public key");

        // println!(
        //     "{}",
        //     serde_json::to_string_pretty(&key_pair.to_jwk_public_key())
        //         .expect("Failed to serialize")
        // );
    } else if subject_alg == OID_SIG_ED25519 || subject_alg == OID_SIG_ED448 {
        println!("EdDSA public key");
        let key_pair = josekit::jws::EdDSA
            .key_pair_from_der(public_key.raw)
            .expect("Invalid EdDSA key pair");
        println!(
            "{}",
            serde_json::to_string_pretty(&key_pair.to_jwk_public_key())
                .expect("Failed to serialize")
        );
    } else if subject_alg == OID_PKCS1_SHA1WITHRSA {
        println!("RSA key with SHA1 [LEGACY!!]");
        let public_key = rsa::RsaPublicKey::from_public_key_der(&public_key.raw)
            .expect("Failed to parse RSA key");
        let mut jwk = Jwk::new("RSA");
        jwk.set_algorithm("RS1");

        let n = public_key.n().to_be_bytes_trimmed_vartime().to_vec();
        let n = BASE64_URL_SAFE_NO_PAD.encode(&n);
        jwk.set_parameter("n", Some(Value::String(n))).unwrap();

        let e = public_key.e().to_be_bytes_trimmed_vartime();
        let e = BASE64_URL_SAFE_NO_PAD.encode(e);
        jwk.set_parameter("e", Some(Value::String(e))).unwrap();
    } else {
        println!("Algorithm oid: {}", subject_alg.to_id_string());
        println!("Unknown algorithm");
    }
}
