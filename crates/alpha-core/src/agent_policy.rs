//! What a Kata agent policy (the init-data's `policy.rego`) lets the host do, read from the Rego
//! itself so that a page or a relying party shows what the pod enforces rather than what a label
//! claims.
//!
//! The Kata agent asks the policy `data.agent_policy.<Request>` before it serves each request
//! from the host, and refuses the request unless the answer is `true`; a rule the policy does not
//! define has no answer. So a request is denied for certain when its rule is defined only as
//! `default <Request> := false`, or not at all. Anything else (a rule body, a function, a partial
//! set, even a mention inside another rule's body) may allow it under some input, and is reported
//! as such: this reads the Rego's tokens, not its meaning, and claims a denial only where no
//! evaluation could give another answer. Two rules undo every denial: `SetPolicyRequest` lets the
//! host replace the policy, and `AllowRequestsFailingPolicy` lets a refused request through.
//!
//! The images are the ones genpolicy lists in `policy_data.containers[].OCI.Annotations` under
//! `io.kubernetes.cri.image-name`, which the agent compares with each container it is asked to
//! create; a policy written another way names none this reads.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The package the Kata agent queries.
pub const PACKAGE: &str = "agent_policy";
/// Runs a command inside a running container (`kubectl exec`).
pub const EXEC: &str = "ExecProcessRequest";
/// Reads a container's stdout and stderr (`kubectl logs`).
pub const LOGS: &str = "ReadStreamRequest";
/// Replaces the policy inside the running pod.
pub const SET_POLICY: &str = "SetPolicyRequest";
/// Lets the agent serve a request the policy refused.
pub const ALLOW_FAILING: &str = "AllowRequestsFailingPolicy";
const IMAGE_ANNOTATION: &str = "io.kubernetes.cri.image-name";

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("agent policy line {line}: a string is not closed")]
    Unterminated { line: usize },
    #[error("agent policy: the package is not {PACKAGE}")]
    Package,
}

/// How the policy answers one request, from the strongest denial to the weakest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The rule is only `default … := false`, or absent, and the policy can be neither replaced nor
    /// bypassed: the agent refuses every such request.
    Denied,
    /// The policy has a rule for the request that may allow it.
    Ruled,
    /// The request's rule denies it, but the policy may let the host replace the policy.
    Replaceable,
    /// The request's rule denies it, but the policy may let refused requests through.
    FailuresAllowed,
}

/// What the agent policy lets the host do to the pod's containers, and the images it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySummary {
    pub exec: Verdict,
    pub logs: Verdict,
    /// In the order the policy lists them, each once.
    pub images: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind<'a> {
    Word(&'a str),
    Str,
    /// `:=`
    Assign,
    /// `=` alone, not part of `==`, `!=`, `<=` or `>=`.
    Equals,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct Token<'a> {
    kind: Kind<'a>,
    line: usize,
    start: usize,
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The policy's tokens outside comments, with string literals (whose contents never define a
/// rule) reduced to one token each.
fn tokens(policy: &str) -> Result<Vec<Token<'_>>, PolicyError> {
    let mut out = Vec::new();
    let mut chars = policy.char_indices().peekable();
    let mut line = 1usize;
    let mut previous = '\n';
    while let Some((start, c)) = chars.next() {
        let kind = match c {
            '\n' => {
                line = line.saturating_add(1);
                None
            }
            c if c.is_whitespace() => None,
            '#' => {
                while chars.next_if(|&(_, c)| c != '\n').is_some() {}
                None
            }
            '"' => {
                let opened = line;
                loop {
                    match chars.next() {
                        Some((_, '"')) => break,
                        Some((_, '\\')) => {
                            if chars.next_if(|&(_, c)| c != '\n').is_none() {
                                return Err(PolicyError::Unterminated { line: opened });
                            }
                        }
                        Some((_, '\n')) | None => {
                            return Err(PolicyError::Unterminated { line: opened });
                        }
                        Some(_) => {}
                    }
                }
                Some(Kind::Str)
            }
            '`' => {
                let opened = line;
                loop {
                    match chars.next() {
                        Some((_, '`')) => break,
                        Some((_, '\n')) => line = line.saturating_add(1),
                        Some(_) => {}
                        None => return Err(PolicyError::Unterminated { line: opened }),
                    }
                }
                Some(Kind::Str)
            }
            c if is_word(c) => {
                while chars.next_if(|&(_, c)| is_word(c)).is_some() {}
                let end = chars.peek().map_or(policy.len(), |&(i, _)| i);
                Some(Kind::Word(policy.get(start..end).unwrap_or_default()))
            }
            ':' if chars.next_if(|&(_, c)| c == '=').is_some() => Some(Kind::Assign),
            '=' if chars.next_if(|&(_, c)| c == '=').is_some() => Some(Kind::Other),
            '=' if matches!(previous, '!' | '<' | '>') => Some(Kind::Other),
            '=' => Some(Kind::Equals),
            _ => Some(Kind::Other),
        };
        previous = c;
        if let Some(kind) = kind {
            out.push(Token { kind, line, start });
        }
    }
    Ok(out)
}

/// Whether `tokens[at]` is the first token of a line whose tokens are exactly `words`, where
/// `":="` stands for either `:=` or `=`.
fn line_is(tokens: &[Token<'_>], at: usize, words: &[&str]) -> bool {
    let Some(first) = tokens.get(at) else {
        return false;
    };
    let starts_line = at
        .checked_sub(1)
        .and_then(|i| tokens.get(i))
        .is_none_or(|t| t.line < first.line);
    let Some(rest) = tokens.get(at..) else {
        return false;
    };
    let on_line: Vec<Kind<'_>> = rest
        .iter()
        .take_while(|t| t.line == first.line)
        .map(|t| t.kind)
        .collect();
    let expected = words.iter().map(|&w| (w != ":=").then_some(Kind::Word(w)));
    starts_line
        && on_line.len() == words.len()
        && on_line.iter().zip(expected).all(|(kind, want)| match want {
            Some(want) => *kind == want,
            None => matches!(kind, Kind::Assign | Kind::Equals),
        })
}

/// Whether the agent refuses `request` whatever the input: its only definition is
/// `default <request> := false` on a line of its own, or it is never named.
fn never_true(tokens: &[Token<'_>], request: &str) -> bool {
    let mentions: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| t.kind == Kind::Word(request))
        .map(|(i, _)| i)
        .collect();
    match mentions.as_slice() {
        [] => true,
        [at] => at
            .checked_sub(1)
            .is_some_and(|d| line_is(tokens, d, &["default", request, ":=", "false"])),
        _ => false,
    }
}

fn images(policy: &str, tokens: &[Token<'_>]) -> Vec<String> {
    let data = tokens.iter().enumerate().find_map(|(i, t)| {
        let starts_line = i
            .checked_sub(1)
            .and_then(|p| tokens.get(p))
            .is_none_or(|p| p.line < t.line);
        let assigns = i
            .checked_add(1)
            .and_then(|n| tokens.get(n))
            .is_some_and(|n| matches!(n.kind, Kind::Assign | Kind::Equals));
        (starts_line && assigns && t.kind == Kind::Word("policy_data"))
            .then(|| i.checked_add(2).and_then(|v| tokens.get(v)))
            .flatten()
    });
    let Some(value) = data
        .and_then(|t| policy.get(t.start..))
        .and_then(|rest| {
            serde_json::Deserializer::from_str(rest)
                .into_iter::<Value>()
                .next()
        })
        .and_then(Result::ok)
    else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for container in value
        .get("containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let image = container
            .pointer("/OCI/Annotations")
            .and_then(|a| a.get(IMAGE_ANNOTATION))
            .and_then(Value::as_str);
        if let Some(image) = image
            && !out.iter().any(|seen| seen == image)
        {
            out.push(image.to_owned());
        }
    }
    out
}

/// What `policy` lets the host do. Refuses a policy whose strings do not close or whose package is
/// not the one the agent queries, since then nothing it says can be read with certainty.
pub fn summarize(policy: &str) -> Result<PolicySummary, PolicyError> {
    let tokens = tokens(policy)?;
    let packages: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| t.kind == Kind::Word("package"))
        .map(|(i, _)| i)
        .collect();
    let [package] = packages.as_slice() else {
        return Err(PolicyError::Package);
    };
    if !line_is(&tokens, *package, &["package", PACKAGE]) {
        return Err(PolicyError::Package);
    }
    let verdict = |request: &str| {
        if !never_true(&tokens, request) {
            Verdict::Ruled
        } else if !never_true(&tokens, ALLOW_FAILING) {
            Verdict::FailuresAllowed
        } else if !never_true(&tokens, SET_POLICY) {
            Verdict::Replaceable
        } else {
            Verdict::Denied
        }
    };
    Ok(PolicySummary {
        exec: verdict(EXEC),
        logs: verdict(LOGS),
        images: images(policy, &tokens),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY_ALL: &str = "package agent_policy\n\ndefault ExecProcessRequest := false\ndefault ReadStreamRequest := false\ndefault SetPolicyRequest := false\ndefault AllowRequestsFailingPolicy := false\n";

    fn summary(policy: &str) -> PolicySummary {
        summarize(policy).unwrap()
    }

    #[test]
    fn a_default_false_and_nothing_else_is_denied() {
        let s = summary(DENY_ALL);
        assert_eq!((s.exec, s.logs), (Verdict::Denied, Verdict::Denied));
        assert!(s.images.is_empty());
        // Rego v0's `=`, comments after the statement, and rules the agent never defines.
        let s = summary(
            "# baseline\npackage agent_policy # ours\ndefault ExecProcessRequest = false # no exec\n",
        );
        assert_eq!((s.exec, s.logs), (Verdict::Denied, Verdict::Denied));
    }

    #[test]
    fn any_other_definition_or_mention_is_ruled() {
        for policy in [
            "package agent_policy\ndefault ExecProcessRequest := true\n",
            "package agent_policy\nExecProcessRequest := true\n",
            "package agent_policy\ndefault ExecProcessRequest := false\nExecProcessRequest if { input.process.Args[0] == \"sh\" }\n",
            "package agent_policy\ndefault ExecProcessRequest := false\nExecProcessRequest { true }\n",
            "package agent_policy\ndefault ExecProcessRequest := false\nExecProcessRequest(x) := true\n",
            "package agent_policy\ndefault ExecProcessRequest := false\nx := y with ExecProcessRequest as true\n",
            "package agent_policy\ndefault ExecProcessRequest := false\ndefault ExecProcessRequest := false\n",
            "package agent_policy\ndefault ExecProcessRequest := false; ExecProcessRequest := true\n",
            "package agent_policy\ndefault ExecProcessRequest := false x\n",
            "package agent_policy\ndefault ExecProcessRequest := false == x\n",
            "package agent_policy\nx default ExecProcessRequest := false\n",
            "package agent_policy\ndefault\nExecProcessRequest := false\n",
        ] {
            assert_eq!(summary(policy).exec, Verdict::Ruled, "{policy}");
        }
    }

    #[test]
    fn comments_and_strings_neither_hide_nor_define_a_rule() {
        // A `#` inside a string does not start a comment, so the rule after it counts.
        let hidden = "package agent_policy\ndefault ExecProcessRequest := false\nx := \"#\"; ExecProcessRequest := true\n";
        assert_eq!(summary(hidden).exec, Verdict::Ruled);
        let escaped = "package agent_policy\ndefault ExecProcessRequest := false\nx := \"\\\"#\"; ExecProcessRequest := true\n";
        assert_eq!(summary(escaped).exec, Verdict::Ruled);
        let raw = "package agent_policy\ndefault ExecProcessRequest := false\nx := `\n#`; ExecProcessRequest := true\n";
        assert_eq!(summary(raw).exec, Verdict::Ruled);
        // A rule in a comment or a string's contents is not a rule.
        let quoted = "package agent_policy\ndefault ExecProcessRequest := false\n# ExecProcessRequest := true\nx := \"ExecProcessRequest := true\"\n";
        assert_eq!(summary(quoted).exec, Verdict::Denied);
    }

    #[test]
    fn a_replaceable_or_bypassable_policy_denies_nothing() {
        let replaceable = DENY_ALL.replace(
            "default SetPolicyRequest := false",
            "default SetPolicyRequest := true",
        );
        let s = summary(&replaceable);
        assert_eq!(
            (s.exec, s.logs),
            (Verdict::Replaceable, Verdict::Replaceable)
        );
        let bypassed = format!("{replaceable}AllowRequestsFailingPolicy := true\n");
        let s = summary(&bypassed);
        assert_eq!(
            (s.exec, s.logs),
            (Verdict::FailuresAllowed, Verdict::FailuresAllowed)
        );
        let logs = format!("{DENY_ALL}ReadStreamRequest if {{ true }}\n");
        let s = summary(&logs);
        assert_eq!((s.exec, s.logs), (Verdict::Denied, Verdict::Ruled));
    }

    #[test]
    fn refuses_what_it_cannot_read() {
        for policy in [
            "package agent_policy\nx := \"open\n",
            "package agent_policy\nx := \"open\\\n\"\n",
            "package agent_policy\nx := `open\n",
        ] {
            assert!(
                matches!(summarize(policy), Err(PolicyError::Unterminated { .. })),
                "{policy}"
            );
        }
        for policy in [
            "",
            "default ExecProcessRequest := false\n",
            "package other\ndefault ExecProcessRequest := false\n",
            "package agent_policy.sub\ndefault ExecProcessRequest := false\n",
            "package agent_policy[\"ExecProcessRequest\"]\nx := true\n",
            "package agent_policy\npackage agent_policy\n",
        ] {
            assert!(
                matches!(summarize(policy), Err(PolicyError::Package)),
                "{policy}"
            );
        }
    }

    #[test]
    fn images_come_from_genpolicy_policy_data() {
        let policy = format!(
            "{DENY_ALL}\npolicy_data := {{\n  \"containers\": [\n    {{\"OCI\": {{\"Annotations\": {{\"io.kubernetes.cri.image-name\": \"pause@sha256:{a}\"}}}}}},\n    {{\"OCI\": {{\"Annotations\": {{\"io.kubernetes.cri.image-name\": \"vllm@sha256:{b}\"}}}}}},\n    {{\"OCI\": {{\"Annotations\": {{\"io.kubernetes.cri.image-name\": \"pause@sha256:{a}\"}}}}}},\n    {{\"OCI\": {{}}}}\n  ]\n}}\n",
            a = "aa".repeat(32),
            b = "bb".repeat(32),
        );
        assert_eq!(
            summary(&policy).images,
            [
                format!("pause@sha256:{}", "aa".repeat(32)),
                format!("vllm@sha256:{}", "bb".repeat(32)),
            ]
        );
        // policy_data that is not JSON, or not at the start of a line, names nothing.
        assert!(
            summary(&format!("{DENY_ALL}policy_data := {{containers: x}}\n"))
                .images
                .is_empty()
        );
        assert!(
            summary(&format!(
                "{DENY_ALL}x := 1; policy_data := {{\"containers\": [{{\"OCI\": {{\"Annotations\": {{\"io.kubernetes.cri.image-name\": \"x\"}}}}}}]}}\n"
            ))
            .images
            .is_empty()
        );
    }
}
