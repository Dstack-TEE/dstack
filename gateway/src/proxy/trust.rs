use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum TrustStrategy {
    None,
    All,
    Ips(Vec<IpAddr>),
    Cidrs(Vec<IpNet>),
}

impl TrustStrategy {
    pub fn is_trusted(&self, addr: &IpAddr) -> bool {
        match self {
            TrustStrategy::None => false,
            TrustStrategy::All => true,
            TrustStrategy::Ips(ips) => ips.contains(addr),
            TrustStrategy::Cidrs(cidrs) => cidrs.iter().any(|cidr| cidr.contains(addr)),
        }
    }

    pub fn from_config(config: &crate::config::ProxyProtocolTrustStrategy) -> anyhow::Result<Self> {
        use crate::config::TrustStrategyType;

        Ok(match config.strategy_type {
            TrustStrategyType::None => TrustStrategy::None,
            TrustStrategyType::All => TrustStrategy::All,
            TrustStrategyType::Ips => {
                let ips = config
                    .addresses
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("IP addresses required for 'ips' trust strategy"))?
                    .iter()
                    .map(|s| IpAddr::from_str(s))
                    .collect::<Result<Vec<_>, _>>()?;
                TrustStrategy::Ips(ips)
            }
            TrustStrategyType::Cidrs => {
                let cidrs = config
                    .ranges
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("CIDR ranges required for 'cidrs' trust strategy"))?
                    .iter()
                    .map(|s| IpNet::from_str(s))
                    .collect::<Result<Vec<_>, _>>()?;
                TrustStrategy::Cidrs(cidrs)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_strategy_none() {
        let strategy = TrustStrategy::None;
        let addr = IpAddr::from_str("192.168.1.1").unwrap();
        assert!(!strategy.is_trusted(&addr));
    }

    #[test]
    fn test_trust_strategy_all() {
        let strategy = TrustStrategy::All;
        let addr = IpAddr::from_str("192.168.1.1").unwrap();
        assert!(strategy.is_trusted(&addr));
    }

    #[test]
    fn test_trust_strategy_ips() {
        let strategy = TrustStrategy::Ips(vec![
            IpAddr::from_str("10.0.0.1").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
        ]);

        assert!(strategy.is_trusted(&IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(strategy.is_trusted(&IpAddr::from_str("10.0.0.2").unwrap()));
        assert!(!strategy.is_trusted(&IpAddr::from_str("10.0.0.3").unwrap()));
    }

    #[test]
    fn test_trust_strategy_cidrs() {
        let strategy = TrustStrategy::Cidrs(vec![
            IpNet::from_str("10.0.0.0/24").unwrap(),
            IpNet::from_str("172.16.0.0/16").unwrap(),
        ]);

        assert!(strategy.is_trusted(&IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(strategy.is_trusted(&IpAddr::from_str("10.0.0.255").unwrap()));
        assert!(strategy.is_trusted(&IpAddr::from_str("172.16.1.1").unwrap()));
        assert!(!strategy.is_trusted(&IpAddr::from_str("10.0.1.1").unwrap()));
        assert!(!strategy.is_trusted(&IpAddr::from_str("192.168.1.1").unwrap()));
    }
}