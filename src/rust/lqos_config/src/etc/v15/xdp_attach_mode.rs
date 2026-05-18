//! XDP attach mode configuration.
//!
//! Controls how the LibreQoS XDP program (`xdp_prog`) is attached to network
//! interfaces:
//!
//! * `Raw` (default): direct `bpf_xdp_attach()` — historical behavior. The
//!   XDP program owns the interface exclusively. Cannot coexist with any
//!   other XDP program on the same interface.
//!
//! * `Libxdp { priority }`: attach via the `libxdp` dispatcher. Other XDP
//!   programs can also attach via libxdp (at different priorities) and run
//!   in the same chain. Required for composability with external XDP tools
//!   (e.g., DSCP markers, observability probes).
//!
//! `Raw` stays the default to preserve existing behavior bit-for-bit. Opt
//! into libxdp via `lqos.conf` (`xdp_attach_mode = "libxdp"`) or the
//! `--xdp-attach-mode=libxdp` CLI flag on `lqosd`.

use allocative::Allocative;
use serde::{Deserialize, Serialize};

/// Default priority for LibreQoS's xdp_prog when running under the libxdp
/// dispatcher. LibreQoS performs `XDP_REDIRECT` (a terminating action) so it
/// should run LAST in any composed chain — hence a low priority. External
/// tools that want to mark/observe packets before redirect attach at higher
/// priorities (e.g., 50 for DSCP markers).
pub const DEFAULT_LIBXDP_PRIORITY: u32 = 10;

fn default_libxdp_priority() -> u32 {
    DEFAULT_LIBXDP_PRIORITY
}

/// How `lqosd` attaches its XDP program to network interfaces.
///
/// Serializes to/from TOML as:
/// ```toml
/// xdp_attach_mode = "raw"
/// # or
/// xdp_attach_mode = { mode = "libxdp", priority = 10 }
/// ```
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Allocative)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum XdpAttachMode {
    /// Raw `bpf_xdp_attach()`. Exclusive ownership of the interface. Default.
    Raw,
    /// `libxdp` dispatcher. Composable with other libxdp-attached programs.
    Libxdp {
        /// Run priority of LibreQoS's xdp_prog inside the dispatcher.
        /// Lower numbers run later in the chain. LibreQoS terminates the
        /// chain via `XDP_REDIRECT`, so a low priority is appropriate.
        #[serde(default = "default_libxdp_priority")]
        priority: u32,
    },
}

impl Default for XdpAttachMode {
    fn default() -> Self {
        Self::Raw
    }
}

impl XdpAttachMode {
    /// Parse a CLI flag value like `raw`, `libxdp`, or `libxdp:50`.
    /// Returns `Err` on malformed input.
    pub fn parse_cli(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("raw") {
            return Ok(Self::Raw);
        }
        if let Some(rest) = trimmed.strip_prefix("libxdp") {
            let priority = if rest.is_empty() {
                DEFAULT_LIBXDP_PRIORITY
            } else if let Some(p) = rest.strip_prefix(':') {
                p.parse::<u32>()
                    .map_err(|e| format!("invalid libxdp priority `{p}`: {e}"))?
            } else if let Some(p) = rest.strip_prefix('=') {
                p.parse::<u32>()
                    .map_err(|e| format!("invalid libxdp priority `{p}`: {e}"))?
            } else {
                return Err(format!(
                    "unrecognized xdp-attach-mode `{s}` (expected `raw`, `libxdp`, or `libxdp:<priority>`)"
                ));
            };
            return Ok(Self::Libxdp { priority });
        }
        Err(format!(
            "unrecognized xdp-attach-mode `{s}` (expected `raw`, `libxdp`, or `libxdp:<priority>`)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_raw() {
        assert_eq!(XdpAttachMode::default(), XdpAttachMode::Raw);
    }

    #[test]
    fn parse_cli_raw() {
        assert_eq!(XdpAttachMode::parse_cli("raw").unwrap(), XdpAttachMode::Raw);
        assert_eq!(XdpAttachMode::parse_cli("RAW").unwrap(), XdpAttachMode::Raw);
    }

    #[test]
    fn parse_cli_libxdp_default_priority() {
        assert_eq!(
            XdpAttachMode::parse_cli("libxdp").unwrap(),
            XdpAttachMode::Libxdp { priority: DEFAULT_LIBXDP_PRIORITY },
        );
    }

    #[test]
    fn parse_cli_libxdp_with_priority() {
        assert_eq!(
            XdpAttachMode::parse_cli("libxdp:50").unwrap(),
            XdpAttachMode::Libxdp { priority: 50 },
        );
        assert_eq!(
            XdpAttachMode::parse_cli("libxdp=50").unwrap(),
            XdpAttachMode::Libxdp { priority: 50 },
        );
    }

    #[test]
    fn parse_cli_rejects_garbage() {
        assert!(XdpAttachMode::parse_cli("foo").is_err());
        assert!(XdpAttachMode::parse_cli("libxdpfoo").is_err());
        assert!(XdpAttachMode::parse_cli("libxdp:not-a-number").is_err());
    }

    #[test]
    fn toml_roundtrip_raw() {
        let mode = XdpAttachMode::Raw;
        let s = toml::to_string(&mode).unwrap();
        let back: XdpAttachMode = toml::from_str(&s).unwrap();
        assert_eq!(mode, back);
    }

    #[test]
    fn toml_roundtrip_libxdp() {
        let mode = XdpAttachMode::Libxdp { priority: 42 };
        let s = toml::to_string(&mode).unwrap();
        let back: XdpAttachMode = toml::from_str(&s).unwrap();
        assert_eq!(mode, back);
    }
}
