//! What a Kata KMS node refuses to find in its measured environment.
//!
//! A Kata node's environment is in the agent policy inside its init-data, and
//! `GET /v1/node/evidence` serves that init-data to anyone who asks for a nonce (#87). Whatever the
//! environment holds is therefore public, so a node that finds a database password there refuses to
//! start rather than serve it (Hacktron ACC-FD-101). A prototype node's environment is dstack's
//! encrypted env, which no endpoint serves, so it may still carry one.
//!
//! The rule is the one `db_auth::check_url` applies on a Kata node in the D10 draft (#105): a
//! password in the URL's userinfo or a `password` query parameter is refused. Once #105 lands the
//! two checks agree, and this one can be folded into it.

/// The env variable the KMS reads its Postgres URL from.
pub const DATABASE_URL_ENV: &str = "ALPHACOMPUTE_DATABASE_URL";

/// Refuses `url` on a Kata node (`kata`) when it carries a password. A prototype node's URL is
/// not checked.
pub fn check_database_url(url: &str, kata: bool) -> Result<(), String> {
    if kata && carries_password(url) {
        return Err(format!(
            "{DATABASE_URL_ENV} carries a password, which this Kata node's evidence endpoint \
             would publish (GET /v1/node/evidence serves the init-data, and the init-data holds \
             the environment); give a URL without one (deploy/coco/platform/README.md, \
             \"The database credential\")"
        ));
    }
    Ok(())
}

/// Whether `url` (`scheme://[user[:password]@]host…[?…]`) holds a password: a `:` in its userinfo,
/// or a `password` query parameter.
pub fn carries_password(url: &str) -> bool {
    userinfo(url).is_some_and(|info| info.contains(':')) || query_param(url, "password").is_some()
}

fn authority(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    Some(rest.split(['/', '?']).next().unwrap_or(rest))
}

fn userinfo(url: &str) -> Option<&str> {
    authority(url)?.rsplit_once('@').map(|(info, _)| info)
}

fn query_param<'a>(url: &'a str, name: &str) -> Option<&'a str> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kata_node_refuses_a_database_url_with_a_password() {
        for url in [
            "postgres://alpha_kms_node:s3cret@db:5432/alpha",
            "postgres://alpha_kms_node:@db:5432/alpha",
            "postgres://alpha_kms_node:p@ss@db:5432/alpha",
            "postgres://alpha_kms_node@db:5432/alpha?sslmode=verify-full&password=s3cret",
            "postgresql://:s3cret@db/alpha",
        ] {
            let err = check_database_url(url, true).unwrap_err();
            assert!(
                err.contains("ALPHACOMPUTE_DATABASE_URL carries a password"),
                "{url}"
            );
            assert!(
                !err.contains("s3cret"),
                "the refusal must not echo the secret: {err}"
            );
            // A prototype node's env is encrypted and served by no endpoint.
            assert!(check_database_url(url, false).is_ok(), "{url}");
        }
    }

    #[test]
    fn a_kata_node_takes_a_database_url_without_a_password() {
        for url in [
            "postgres://alpha_kms_node@db:5432/alpha?sslmode=verify-full",
            "postgres://db:5432/alpha",
            "postgres://alpha_kms_node@db/alpha?sslmode=verify-full&sslrootcert=/ca.pem",
            // A `:` after the authority is not userinfo.
            "postgres://alpha_kms_node@db:5432/alpha?options=-c%20a:b",
        ] {
            assert!(check_database_url(url, true).is_ok(), "{url}");
        }
    }
}
