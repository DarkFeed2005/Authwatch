//! MITRE ATT&CK technique metadata used by the detection rules.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: &'static str,
}

impl Technique {
    /// `T1110.001` -> `https://attack.mitre.org/techniques/T1110/001/`
    pub fn url(&self) -> String {
        format!(
            "https://attack.mitre.org/techniques/{}/",
            self.id.replace('.', "/")
        )
    }
}

pub const T1110_001: Technique = Technique {
    id: "T1110.001",
    name: "Brute Force: Password Guessing",
    tactic: "Credential Access",
};
pub const T1110_003: Technique = Technique {
    id: "T1110.003",
    name: "Brute Force: Password Spraying",
    tactic: "Credential Access",
};
/// Success-after-failures has no dedicated sub-technique; "Valid Accounts"
/// is the closest fit (the attacker now holds working credentials).
pub const T1078: Technique = Technique {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Initial Access",
};
pub const T1136_001: Technique = Technique {
    id: "T1136.001",
    name: "Create Account: Local Account",
    tactic: "Persistence",
};
pub const T1548_003: Technique = Technique {
    id: "T1548.003",
    name: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    tactic: "Privilege Escalation",
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_format() {
        assert_eq!(T1110_001.url(), "https://attack.mitre.org/techniques/T1110/001/");
        assert_eq!(T1078.url(), "https://attack.mitre.org/techniques/T1078/");
    }
}
