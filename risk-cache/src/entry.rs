#[derive(Debug, Clone)]
pub struct RiskEntry {
    pub risk_score: f32,
    pub reason: String,
    /// Combined audit line: "<verdict> | <graph_reason>" — written to audit log on erasure.
    pub audit_reason: String,
    pub updated_at: u64,
}
