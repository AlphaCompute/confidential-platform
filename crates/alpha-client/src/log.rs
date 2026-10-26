//! One JSON object per line on stderr: `ts`, `level`, `service`, `event` and typed fields.
//!
//! ```
//! let app_id = alpha_core::AppId::mint();
//! alpha_client::info!("attested", app_id = app_id, gpus = 8u64);
//! ```
//!
//! A field takes no `String`, so a request, a peer answer or a Secret value cannot reach a line
//! by accident:
//!
//! ```compile_fail
//! let token = String::from("bearer");
//! alpha_client::info!("attested", token = token);
//! ```

use std::io::Write;
use std::time::{Duration, SystemTime};

use alpha_core::{AppId, ComposeHash};
use serde_json::{Map, Value};

pub struct Field(Value);

impl Field {
    /// A name from the measured env, such as a model or a Secret name, or a digest; never a
    /// request, a peer answer or a Secret value.
    pub fn text(value: &str) -> Self {
        Field(Value::from(value))
    }
}

impl From<&'static str> for Field {
    fn from(value: &'static str) -> Self {
        Field(Value::from(value))
    }
}

impl From<u64> for Field {
    fn from(value: u64) -> Self {
        Field(Value::from(value))
    }
}

impl From<bool> for Field {
    fn from(value: bool) -> Self {
        Field(Value::from(value))
    }
}

/// In milliseconds.
impl From<Duration> for Field {
    fn from(value: Duration) -> Self {
        Field(Value::from(
            u64::try_from(value.as_millis()).unwrap_or(u64::MAX),
        ))
    }
}

impl From<std::io::ErrorKind> for Field {
    fn from(value: std::io::ErrorKind) -> Self {
        Field(Value::from(format!("{value:?}")))
    }
}

pub fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl From<SystemTime> for Field {
    fn from(value: SystemTime) -> Self {
        Field(Value::from(rfc3339(value)))
    }
}

impl From<AppId> for Field {
    fn from(value: AppId) -> Self {
        Field(Value::from(value.to_string()))
    }
}

impl From<&ComposeHash> for Field {
    fn from(value: &ComposeHash) -> Self {
        Field(Value::from(value.to_string()))
    }
}

pub fn line(
    level: &'static str,
    service: &'static str,
    event: &'static str,
    fields: Vec<(&'static str, Field)>,
) -> String {
    let mut object: Map<String, Value> = fields
        .into_iter()
        .map(|(key, Field(value))| (key.to_owned(), value))
        .collect();
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    object.insert("ts".into(), ts.into());
    object.insert("level".into(), level.into());
    object.insert("service".into(), service.into());
    object.insert("event".into(), event.into());
    Value::Object(object).to_string()
}

/// A full or closed stderr loses the line rather than stopping the service.
pub fn emit(
    level: &'static str,
    service: &'static str,
    event: &'static str,
    fields: Vec<(&'static str, Field)>,
) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        line(level, service, event, fields)
    );
}

#[doc(hidden)]
#[macro_export]
macro_rules! log_line {
    ($level:literal, $event:literal $(, $key:ident = $value:expr)* $(,)?) => {
        $crate::log::emit(
            $level,
            env!("CARGO_PKG_NAME"),
            $event,
            vec![$((stringify!($key), $crate::log::Field::from($value))),*],
        )
    };
}

#[macro_export]
macro_rules! info {
    ($($line:tt)*) => { $crate::log_line!("info", $($line)*) };
}

#[macro_export]
macro_rules! warn {
    ($($line:tt)*) => { $crate::log_line!("warn", $($line)*) };
}

#[macro_export]
macro_rules! error {
    ($($line:tt)*) => { $crate::log_line!("error", $($line)*) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_one_json_object_whose_own_keys_win_over_a_field() {
        let line = line(
            "warn",
            "alpha-test",
            "renewal_failed",
            vec![
                ("level", Field::from("info")),
                ("error", Field::from("policy_denied")),
                ("after", Field::from(Duration::from_secs(2))),
            ],
        );
        assert!(!line.contains('\n'));
        let object: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(object["level"], "warn");
        assert_eq!(object["service"], "alpha-test");
        assert_eq!(object["event"], "renewal_failed");
        assert_eq!(object["error"], "policy_denied");
        assert_eq!(object["after"], 2000);
        assert!(chrono::DateTime::parse_from_rfc3339(object["ts"].as_str().unwrap()).is_ok());
    }
}
