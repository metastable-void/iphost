//! DHCPv6 Client Identifiers (`ra` or `dhcpv6` feature).
// Only `dhcpv6` sends them; with `ra` alone, `Ipv6ResolverConfig` accepts and ignores them.
#![cfg_attr(not(feature = "dhcpv6"), allow(dead_code))]

use std::io;

use crate::custom::random_u32;

/// DHCPv6 Client Identifier sent in Information-Requests.
///
/// RFC 8415 treats DUIDs as opaque, and allows Information-Requests without one, so most DHCPv6
/// servers accept any choice here. Some networks are stricter; check what yours requires.
///
/// # Network-specific requirements
///
/// Known examples (this crate is not specific to any of them):
///
/// - **NTT FLET'S NGN (Japan)**, RA lines (フレッツ 光ネクスト IPoE without an HGW):
///   Information-Requests go to the NGN directly. NTT's interface specification
///   (技術参考資料 IP通信網サービスのインタフェース 第三分冊, §2.4.2.1.4) requires a DUID-LL with
///   hardware type 1 made from the terminal's MAC address, and the NGN is reported to silently
///   ignore other DUIDs. Use [`ClientId::DuidLl`] with the interface's MAC address. On
///   DHCPv6-PD lines (with an HGW), the HGW answers instead; its requirements are not documented.
/// - Networks that expect one specific, registered DUID: use [`ClientId::Raw`].
#[cfg_attr(docsrs, doc(cfg(any(feature = "ra", feature = "dhcpv6"))))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientId {
    /// No Client Identifier (RFC 7844 anonymity profile). Allowed by RFC 8415 and accepted by
    /// most servers, but **ignored by stricter networks such as NTT's NGN**.
    None,

    /// DUID-LL (RFC 8415 section 11.4) with hardware type 1 (Ethernet), made from this
    /// 6-byte MAC address in transmission order. Pass the plain MAC address, not a DUID:
    /// the DUID-LL header is added for you.
    ///
    /// ```
    /// # use iphost::ClientId;
    /// // MAC 00:11:22:33:44:55, sent as DUID 00:03:00:01:00:11:22:33:44:55.
    /// let id = ClientId::DuidLl([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    /// ```
    ///
    /// Use the MAC address of the interface for networks that check it, such as NTT's NGN.
    DuidLl([u8; 6]),

    /// DUID-LL with a random locally administered unicast MAC address, generated once per
    /// resolver config. Hides the real MAC address, but **probably rejected by networks that
    /// check it, such as NTT's NGN**.
    RandomDuidLl,

    /// This exact DUID (the whole Client Identifier option data, including the DUID type), for
    /// networks that expect a specific one, or to reuse the DUID another client on the host uses.
    ///
    /// DUIDs are variable-length: 3 to 130 bytes (RFC 8415 section 11.1). Resolver configs
    /// reject other lengths.
    ///
    /// ```
    /// # use iphost::ClientId;
    /// // A DUID-LLT: type 1, hardware type 1, time, MAC.
    /// let id = ClientId::Raw(vec![0, 1, 0, 1, 0x2a, 0x3b, 0x4c, 0x5d, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    /// ```
    Raw(Vec<u8>),
}

impl ClientId {
    pub(crate) fn validate(&self) -> io::Result<()> {
        match self {
            ClientId::Raw(duid) if !(3..=130).contains(&duid.len()) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DUID must be 3 to 130 bytes long",
            )),
            _ => Ok(()),
        }
    }

    /// Replaces [`ClientId::RandomDuidLl`] with a concrete random MAC address.
    pub(crate) fn resolve(self) -> Self {
        match self {
            ClientId::RandomDuidLl => {
                let mut mac = [0u8; 6];
                mac[..4].copy_from_slice(&random_u32().to_be_bytes());
                mac[4..].copy_from_slice(&random_u32().to_be_bytes()[..2]);
                // Locally administered, unicast.
                mac[0] = (mac[0] & 0xfc) | 0x02;
                ClientId::DuidLl(mac)
            }
            other => other,
        }
    }

    /// The Client Identifier option's data (the DUID), if any.
    pub(crate) fn duid(&self) -> Option<Vec<u8>> {
        match self {
            ClientId::DuidLl(mac) => Some([&[0, 3, 0, 1][..], mac].concat()),
            ClientId::Raw(duid) => Some(duid.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DUID: [u8; 10] = [0, 3, 0, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    #[test]
    fn client_ids() {
        assert_eq!(ClientId::DuidLl(MAC).duid(), Some(DUID.to_vec()));
        assert_eq!(ClientId::Raw(vec![0, 1, 2]).duid(), Some(vec![0, 1, 2]));
        assert_eq!(ClientId::None.duid(), None);
        assert_eq!(ClientId::DuidLl(MAC).resolve(), ClientId::DuidLl(MAC));
        let ClientId::DuidLl(random) = ClientId::RandomDuidLl.resolve() else {
            panic!("RandomDuidLl did not resolve to DuidLl");
        };
        assert_eq!(random[0] & 0x03, 0x02, "not locally administered unicast");
    }

    #[test]
    fn validates_raw_lengths() {
        for len in [0, 2, 131] {
            let err = ClientId::Raw(vec![0; len]).validate().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "length {len}");
        }
        for len in [3, 130] {
            assert!(ClientId::Raw(vec![0; len]).validate().is_ok());
        }
    }
}
