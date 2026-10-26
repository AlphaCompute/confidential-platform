//! Token usage, one row per completion that reached an upstream. A `Meter` sees every byte of
//! the answer as it is relayed and keeps only what it needs to read `usage`; when the answer's
//! body is dropped (finished, failed or cut by the caller), it writes the row.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::Error;
use crate::keys::Key;
use tokio_util::task::TaskTracker;

/// A non-stream answer longer than this is not parsed, and its row has no token counts.
const BODY_MAX: usize = 4 * 1024 * 1024;
/// An SSE event longer than this is not a usage chunk; it is skipped.
const EVENT_MAX: usize = 64 * 1024;
const INSERT_TRIES: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tokens {
    pub prompt: i64,
    pub completion: i64,
}

fn tokens(answer: &Value) -> Option<Tokens> {
    let usage = answer.get("usage")?;
    let count = |field: &str| {
        usage
            .get(field)?
            .as_u64()
            .and_then(|n| i64::try_from(n).ok())
    };
    Some(Tokens {
        prompt: count("prompt_tokens")?,
        completion: count("completion_tokens")?,
    })
}

pub struct Meter {
    pool: PgPool,
    tasks: TaskTracker,
    key: Key,
    model: String,
    started_at: DateTime<Utc>,
    stream: bool,
    buf: Vec<u8>,
    overflow: bool,
    last: Option<Tokens>,
}

impl Meter {
    pub fn new(
        pool: PgPool,
        tasks: TaskTracker,
        key: Key,
        model: String,
        stream: bool,
        started_at: DateTime<Utc>,
    ) -> Self {
        Meter {
            pool,
            tasks,
            key,
            model,
            started_at,
            stream,
            buf: Vec::new(),
            overflow: false,
            last: None,
        }
    }

    pub fn observe(&mut self, chunk: &[u8]) {
        if !self.stream {
            if self.overflow {
                return;
            }
            if self.buf.len().saturating_add(chunk.len()) > BODY_MAX {
                self.overflow = true;
                self.buf = Vec::new();
            } else {
                self.buf.extend_from_slice(chunk);
            }
            return;
        }
        // Only `\n` and `\r\n` line ends are framed; the bytes the caller gets are untouched.
        self.buf.extend(chunk.iter().filter(|&&b| b != b'\r'));
        while let Some(end) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let event: Vec<u8> = self.buf.drain(..end.saturating_add(2)).collect();
            if let Some(found) = sse_tokens(&event) {
                self.last = Some(found);
            }
        }
        if self.buf.len() > EVENT_MAX {
            self.buf.clear();
        }
    }

    fn result(&self) -> Option<Tokens> {
        if self.stream {
            self.last
        } else if self.overflow {
            None
        } else {
            serde_json::from_slice(&self.buf)
                .ok()
                .as_ref()
                .and_then(tokens)
        }
    }
}

fn sse_tokens(event: &[u8]) -> Option<Tokens> {
    let text = std::str::from_utf8(event).ok()?;
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find_map(|v| tokens(&v))
}

impl Drop for Meter {
    fn drop(&mut self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let found = self.result();
        let id = Uuid::now_v7();
        let (pool, key, started_at) = (self.pool.clone(), self.key, self.started_at);
        let model = std::mem::take(&mut self.model);
        self.tasks.spawn_on(
            async move {
            // ponytail: a row whose insert fails three times is lost, and the completion goes
            // unbilled. Upgrade: an outbox the front drains before it reports ready.
            for attempt in 1..=INSERT_TRIES {
                let done = sqlx::query(
                    "insert into usage (id, key_id, org_id, model, prompt_tokens, completion_tokens, started_at)
                     values ($1, $2, $3, $4, $5, $6, $7) on conflict (id) do nothing",
                )
                .bind(id)
                .bind(key.id)
                .bind(key.org_id)
                .bind(&model)
                .bind(found.map(|t| t.prompt))
                .bind(found.map(|t| t.completion))
                .bind(started_at)
                .execute(&pool)
                .await;
                match done {
                    Ok(_) => return,
                    Err(_) if attempt == INSERT_TRIES => {
                        alpha_client::error!("usage_row_lost");
                    }
                    Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            }
            },
            &runtime,
        );
    }
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ByModel {
    pub model: String,
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
}

pub async fn of_key(pool: &PgPool, key_id: Uuid) -> Result<Vec<ByModel>, Error> {
    Ok(sqlx::query_as(
        "select model, count(*) as requests,
                coalesce(sum(prompt_tokens), 0)::bigint as prompt_tokens,
                coalesce(sum(completion_tokens), 0)::bigint as completion_tokens
         from usage where key_id = $1 group by model order by model",
    )
    .bind(key_id)
    .fetch_all(pool)
    .await?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub org_id: Option<Uuid>,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Hourly {
    pub org_id: Uuid,
    pub key_id: Uuid,
    pub model: String,
    pub hour: DateTime<Utc>,
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
}

/// Sums per organization, key, model and hour of `started_at`, for `from <= started_at < to`.
pub async fn hourly(pool: &PgPool, range: &Range) -> Result<Vec<Hourly>, Error> {
    Ok(sqlx::query_as(
        "select org_id, key_id, model, date_trunc('hour', started_at, 'UTC') as hour, count(*) as requests,
                coalesce(sum(prompt_tokens), 0)::bigint as prompt_tokens,
                coalesce(sum(completion_tokens), 0)::bigint as completion_tokens
         from usage
         where started_at >= $1 and started_at < $2 and ($3::uuid is null or org_id = $3)
         group by 1, 2, 3, 4 order by 4, 1, 2, 3",
    )
    .bind(range.from)
    .bind(range.to)
    .bind(range.org_id)
    .fetch_all(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meter(stream: bool) -> Meter {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1:1/none")
            .unwrap();
        let key = Key {
            id: Uuid::nil(),
            org_id: Uuid::nil(),
        };
        Meter::new(
            pool,
            TaskTracker::new(),
            key,
            "m".into(),
            stream,
            Utc::now(),
        )
    }

    #[tokio::test]
    async fn a_stream_yields_the_usage_chunk_even_when_split_across_reads() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":34,\"total_tokens\":46}}\n\n",
            "data: [DONE]\n\n",
        );
        let mut m = meter(true);
        for piece in body.as_bytes().chunks(7) {
            m.observe(piece);
        }
        assert_eq!(
            m.result(),
            Some(Tokens {
                prompt: 12,
                completion: 34
            })
        );
        let mut crlf = meter(true);
        crlf.observe(body.replace("\n", "\r\n").as_bytes());
        assert_eq!(
            crlf.result(),
            Some(Tokens {
                prompt: 12,
                completion: 34
            })
        );
        let mut cut = meter(true);
        cut.observe(&body.as_bytes()[..60]);
        assert_eq!(cut.result(), None);
    }

    #[tokio::test]
    async fn a_whole_answer_yields_its_usage_unless_it_is_too_long() {
        let body = br#"{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":6}}"#;
        let mut m = meter(false);
        m.observe(&body[..10]);
        m.observe(&body[10..]);
        assert_eq!(
            m.result(),
            Some(Tokens {
                prompt: 5,
                completion: 6
            })
        );
        let mut long = meter(false);
        long.observe(&vec![b' '; BODY_MAX]);
        long.observe(body);
        assert_eq!(long.result(), None);
    }
}
