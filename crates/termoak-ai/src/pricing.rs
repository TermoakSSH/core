//! Cost calculation in micro-USD (1 USD = 1,000,000), as in VoxPanel.
//!
//! Two amounts are computed for each AI call:
//! - the **real cost**: what the server pays per token (0 on a subscription
//!   such as Codex with ChatGPT or OpenCode Go, unless the provider reports it);
//! - the **credit cost**: what the call takes from the plan's monthly AI credit.
//!   Subscription providers and providers without a price are charged at a
//!   reference price, so the credit is also spent when the real cost is 0.

use serde::{Deserialize, Serialize};

use crate::message::Usage;

/// Price per million tokens (USD).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Price {
    pub input: f64,
    pub output: f64,
    /// Cache read / cached input (defaults to 10% of input).
    #[serde(alias = "cached_input")]
    pub cache_read: Option<f64>,
    /// Cache write (defaults to 125% of input).
    pub cache_write: Option<f64>,
}

impl Price {
    /// Price with the cache read given and cache writes billed as input.
    const fn cached(input: f64, output: f64, cached_input: f64) -> Self {
        Self {
            input,
            output,
            cache_read: Some(cached_input),
            cache_write: Some(input),
        }
    }
}

/// Credit reference price for Codex (ChatGPT subscription) when its model is
/// unknown: GPT-5.3-codex at OpenAI API list price (list price, update when it
/// changes).
pub const CODEX_CREDIT_PRICE: Price = Price::cached(1.75, 14.0, 0.175);

/// Conservative credit reference price for any other provider whose model has
/// no known price (subscriptions, local models...).
pub const DEFAULT_CREDIT_PRICE: Price = Price::cached(2.0, 10.0, 0.2);

/// Built-in table of known prices. Accepts a vendor prefix (`openai/gpt-5`)
/// and dated snapshots (`gpt-5-codex-2025-09-15`).
pub fn builtin_price(model: &str) -> Option<Price> {
    let name = model
        .rsplit('/')
        .next()
        .unwrap_or(model)
        .to_ascii_lowercase();
    let lookup = |m: &str| -> Option<Price> {
        let anthropic = |input: f64, output: f64, cache_read: f64| Price {
            input,
            output,
            cache_read: Some(cache_read),
            cache_write: Some(input * 1.25),
        };
        let openai = Price::cached;
        Some(match m {
            "claude-fable-5-1" | "claude-fable-5" | "claude-mythos-5-1" => {
                anthropic(10.0, 50.0, 0.25)
            }
            "claude-opus-5-5" => anthropic(4.0, 20.0, 0.20),
            "claude-opus-5" | "claude-opus-4-8" | "claude-opus-4-7" | "claude-opus-4-6" => {
                anthropic(5.0, 25.0, 0.5)
            }
            "claude-sonnet-5" => anthropic(2.0, 10.0, 0.2),
            "claude-sonnet-4-6" => anthropic(3.0, 15.0, 0.3),
            "claude-haiku-4-5" => anthropic(1.0, 5.0, 0.1),
            // OpenAI API list prices (list price, update when it changes).
            "gpt-5.6-sol" => openai(5.0, 30.0, 0.5),
            "gpt-5.6-terra" => openai(2.0, 12.0, 0.2),
            "gpt-5.6-luna" => openai(0.2, 1.2, 0.02),
            "gpt-5.3-codex" | "gpt-5.2-codex" | "gpt-5.2" => openai(1.75, 14.0, 0.175),
            "gpt-5.1-codex" | "gpt-5.1" | "gpt-5-codex" | "gpt-5" => openai(1.25, 10.0, 0.125),
            "gpt-5.1-codex-mini" | "gpt-5-mini" => openai(0.25, 2.0, 0.025),
            "gpt-5-nano" => openai(0.05, 0.4, 0.005),
            // Models served by OpenCode Go, at their vendors' list prices
            // (DeepSeek: peak hours) (list price, update when it changes).
            "deepseek-v4-flash" => openai(0.44, 1.32, 0.014),
            "kimi-k2.6" => openai(0.95, 4.0, 0.16),
            _ => return None,
        })
    };
    lookup(&name).or_else(|| {
        // Dated snapshot: `<model>-2025-09-15` or `<model>-20250915`.
        let i = name.find("-20")?;
        lookup(&name[..i])
    })
}

/// Cost of some usage at a price, in micro-USD.
pub fn priced_micros(usage: &Usage, price: Price) -> i64 {
    let per = |tokens: u64, usd_per_m: f64| tokens as f64 * usd_per_m;
    // In Anthropic, `input_tokens` already excludes cache reads/writes.
    let micros = per(usage.input_tokens, price.input)
        + per(usage.output_tokens, price.output)
        + per(
            usage.cache_read_tokens,
            price.cache_read.unwrap_or(price.input * 0.1),
        )
        + per(
            usage.cache_write_tokens,
            price.cache_write.unwrap_or(price.input * 1.25),
        );
    micros.round() as i64
}

/// Real cost in micro-USD. If the provider reported the cost, that is used.
pub fn cost_micros(usage: &Usage, price: Option<Price>, subscription: bool) -> i64 {
    if let Some(usd) = usage.reported_cost_usd {
        return (usd * 1_000_000.0).round() as i64;
    }
    if subscription {
        return 0;
    }
    price.map(|p| priced_micros(usage, p)).unwrap_or(0)
}

/// Credit cost in micro-USD: what a call on the server's providers takes from
/// the plan's AI credit, in this order:
/// 1. the provider's `credit_price`, if the operator set one;
/// 2. the real cost, if there is one;
/// 3. the model's price (`price` or the built-in table), even on a subscription;
/// 4. the `fallback` reference price (Codex: [`CODEX_CREDIT_PRICE`], others:
///    [`DEFAULT_CREDIT_PRICE`]).
pub fn credit_micros(
    usage: &Usage,
    real_cost_micros: i64,
    credit_price: Option<Price>,
    model_price: Option<Price>,
    fallback: Price,
) -> i64 {
    if let Some(p) = credit_price {
        return priced_micros(usage, p);
    }
    if real_cost_micros > 0 {
        return real_cost_micros;
    }
    priced_micros(usage, model_price.unwrap_or(fallback))
}

/// Real and credit cost of an AI call, in micro-USD.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageCost {
    /// Real cost at the provider's price (0 on a subscription).
    pub cost_micros: i64,
    /// What it takes from the plan's AI credit (0 with the user's own key).
    pub credit_micros: i64,
}

/// Rough token count of a text (about 4 characters per token), for providers
/// that report no usage.
pub fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(4)
}

/// Formats micro-USD as `$0.0123`.
pub fn format_usd(micros: i64) -> String {
    format!("${:.4}", micros as f64 / 1_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opus_cost() {
        let u = Usage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            ..Default::default()
        };
        // $5 + $2.50 = $7.50
        assert_eq!(
            cost_micros(&u, builtin_price("claude-opus-5"), false),
            7_500_000
        );
        assert_eq!(cost_micros(&u, builtin_price("claude-opus-5"), true), 0);
        let reported = Usage {
            reported_cost_usd: Some(0.01),
            ..u
        };
        assert_eq!(cost_micros(&reported, None, true), 10_000);
    }

    #[test]
    fn openai_prices_and_snapshots() {
        let u = Usage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            cache_read_tokens: 1_000_000,
            ..Default::default()
        };
        // $5 + $3 + $0.50
        assert_eq!(
            cost_micros(&u, builtin_price("gpt-5.6-sol"), false),
            8_500_000
        );
        assert_eq!(
            builtin_price("openai/gpt-5-codex-2025-09-15"),
            builtin_price("gpt-5-codex")
        );
        assert_eq!(
            builtin_price("opencode-go/kimi-k2.6"),
            builtin_price("kimi-k2.6")
        );
        assert!(builtin_price("gpt-5.6-sol").is_some());
        assert!(builtin_price("codex").is_none());
        assert!(builtin_price("claude-sonnet-5-5").is_none());
    }

    #[test]
    fn credit_cost_order() {
        let u = Usage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            ..Default::default()
        };
        let model = builtin_price("gpt-5.6-sol");
        let fixed = Price {
            input: 1.0,
            output: 0.0,
            ..Default::default()
        };
        // The operator's credit price wins.
        assert_eq!(
            credit_micros(&u, 42, Some(fixed), model, DEFAULT_CREDIT_PRICE),
            1_000_000
        );
        // Then the real cost.
        assert_eq!(credit_micros(&u, 42, None, model, DEFAULT_CREDIT_PRICE), 42);
        // A subscription (real cost 0) is charged at the model's price...
        assert_eq!(
            credit_micros(&u, 0, None, model, DEFAULT_CREDIT_PRICE),
            8_000_000
        );
        // ...or at the reference price if the model is unknown.
        assert_eq!(
            credit_micros(&u, 0, None, None, CODEX_CREDIT_PRICE),
            3_150_000
        );
        assert_eq!(
            credit_micros(&u, 0, None, None, DEFAULT_CREDIT_PRICE),
            3_000_000
        );
        assert_eq!(estimate_tokens("abcdefghi"), 3);
    }
}
