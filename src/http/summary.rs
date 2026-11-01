use crate::dmarc::{DkimResultType, DmarcResultType, SpfResultType};
use crate::state::{AppState, DmarcReportWithMailId, TlsReportWithMailId};
use crate::tls::{FailureResultType, PolicyType, TlsResultType};
use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Deserialize, Debug)]
pub struct SummaryFilters {
    /// Unix timestamp in seconds.
    /// If set, reports ending before this are excluded.
    after: Option<i64>,

    /// Unix timestamp in seconds.
    /// If set, reports beginning after this are excluded.
    before: Option<i64>,

    /// Domain to be filtered. Other domains will be ignored.
    /// None means the filter is disabled!
    domain: Option<String>,
}

impl SummaryFilters {
    fn url_decode(&mut self) {
        self.domain = self
            .domain
            .as_ref()
            .and_then(|s| urlencoding::decode(s).ok())
            .map(|s| s.to_string());
    }
}

pub async fn handler(
    State(state): State<Arc<RwLock<AppState>>>,
    mut filters: Query<SummaryFilters>,
) -> impl IntoResponse {
    filters.url_decode();
    let guard = state.read().await;
    let summary = Summary::new(
        guard.mails.len(),
        Reports {
            dmarc: &guard.dmarc_reports,
            tls: &guard.tls_reports,
        },
        guard.last_update,
        guard.next_update,
        filters.after,
        filters.before,
        filters.domain.clone(),
    );
    Json(summary)
}

#[derive(Serialize, Default, Clone)]
pub struct DmarcSummary {
    /// Number of successfully parsed DMARC reports XML files found in IMAP inbox
    pub reports: usize,

    /// Map of organizations with number of corresponding DMARC reports
    pub orgs: HashMap<String, usize>,

    /// Map of domains with number of corresponding DMARC reports
    pub domains: HashMap<String, usize>,

    /// Map of DMARC SPF policy evaluation results
    pub spf_policy_results: HashMap<DmarcResultType, usize>,

    /// Map of DMARC DKIM policy evaluation results
    pub dkim_policy_results: HashMap<DmarcResultType, usize>,

    /// Map of DMARC SPF auth results
    pub spf_auth_results: HashMap<SpfResultType, usize>,

    /// Map of DMARC DKIM auth results
    pub dkim_auth_results: HashMap<DkimResultType, usize>,

    /// Map of the overall DMARC results, a message passes DMARC if SPF or DKIM passed the policy evaluation
    pub dmarc_results: HashMap<DmarcResultType, usize>,
}

#[derive(Serialize, Default, Clone)]
pub struct TlsSummary {
    /// Number of successfully parsed SMTP TLS reports JSON files found in IMAP inbox
    pub reports: usize,

    /// Map of organizations with number of corresponding SMTP TLS reports
    pub orgs: HashMap<String, usize>,

    /// Map of domains with number of corresponding SMTP TLS policy evaluations
    pub domains: HashMap<String, usize>,

    /// Map of SMTP TLS policy types
    pub policy_types: HashMap<PolicyType, usize>,

    /// Map of SMTP TLS STS policy evaluation results
    pub sts_policy_results: HashMap<TlsResultType, usize>,

    /// Map of SMTP TLS TLSA policy evaluation results
    pub tlsa_policy_results: HashMap<TlsResultType, usize>,

    /// Map of SMTP TLS STS failure results
    pub sts_failure_types: HashMap<FailureResultType, usize>,

    /// Map of SMTP TLS TLSA failure results
    pub tlsa_failure_types: HashMap<FailureResultType, usize>,
}

pub struct Reports<'a> {
    /// Parsed DMARC reports with mail UID and corresponding hash as key
    pub dmarc: &'a BTreeMap<String, DmarcReportWithMailId>,

    /// Parsed SMTP TLS reports with mail UID and corresponding hash as key
    pub tls: &'a BTreeMap<String, TlsReportWithMailId>,
}

#[derive(Serialize, Default, Clone)]
pub struct Summary {
    /// Number of mails from IMAP inbox
    pub mails: usize,

    /// Unix timestamp with time of last update
    pub last_update: Option<u64>,

    /// Unix timestamp with time of next update
    pub next_update: Option<u64>,

    /// Information about DMARC reports
    pub dmarc: DmarcSummary,

    /// Information about SMTP TLS reports
    pub tls: TlsSummary,
}

impl Summary {
    pub fn new(
        mails: usize,
        reports: Reports,
        last_update: Option<u64>,
        next_update: Option<u64>,
        after: Option<i64>,
        before: Option<i64>,
        domain_filter: Option<String>,
    ) -> Self {
        let mut dmarc = DmarcSummary {
            reports: reports.dmarc.len(),
            ..Default::default()
        };

        let mut tls = TlsSummary {
            reports: reports.tls.len(),
            ..Default::default()
        };

        let domain_filter = domain_filter.map(|d| d.to_lowercase());
        for DmarcReportWithMailId { report, .. } in reports.dmarc.values() {
            if let Some(after) = after
                && i128::from(report.report_metadata.date_range.end) < i128::from(after)
            {
                continue;
            }
            if let Some(before) = before
                && i128::from(report.report_metadata.date_range.begin) > i128::from(before)
            {
                continue;
            }
            if let Some(df) = &domain_filter
                && report.policy_published.domain.to_lowercase() != *df
            {
                continue;
            }
            let domain = report.policy_published.domain.to_lowercase();
            *dmarc.domains.entry(domain).or_insert(0) += 1;
            let org = report.report_metadata.org_name.clone();
            *dmarc.orgs.entry(org).or_insert(0) += 1;
            for record in &report.record {
                for r in &record.auth_results.spf {
                    *dmarc.spf_auth_results.entry(r.result.clone()).or_insert(0) +=
                        record.row.count;
                }
                if let Some(vec) = &record.auth_results.dkim {
                    for r in vec {
                        *dmarc.dkim_auth_results.entry(r.result.clone()).or_insert(0) +=
                            record.row.count;
                    }
                }
                if let Some(result) = &record.row.policy_evaluated.spf {
                    *dmarc.spf_policy_results.entry(result.clone()).or_insert(0) +=
                        record.row.count;
                }
                if let Some(result) = &record.row.policy_evaluated.dkim {
                    *dmarc.dkim_policy_results.entry(result.clone()).or_insert(0) +=
                        record.row.count;
                }
                let spf_pass = record.row.policy_evaluated.spf == Some(DmarcResultType::Pass);
                let dkim_pass = record.row.policy_evaluated.dkim == Some(DmarcResultType::Pass);
                let result = if spf_pass || dkim_pass {
                    DmarcResultType::Pass
                } else {
                    DmarcResultType::Fail
                };
                *dmarc.dmarc_results.entry(result).or_insert(0) += record.row.count;
            }
        }
        for TlsReportWithMailId { report, .. } in reports.tls.values() {
            if let Some(after) = after
                && report.date_range.end_datetime.timestamp() < after
            {
                continue;
            }
            if let Some(before) = before
                && report.date_range.start_datetime.timestamp() > before
            {
                continue;
            }
            if let Some(df) = &domain_filter
                && report
                    .policies
                    .iter()
                    .all(|p| p.policy.policy_domain.to_lowercase() != *df)
            {
                continue;
            }
            let org = report.organization_name.clone();
            *tls.orgs.entry(org).or_insert(0) += 1;
            for policy_result in report.policies.iter() {
                let domain = policy_result.policy.policy_domain.to_lowercase();
                *tls.domains.entry(domain).or_insert(0) += 1;
                *tls.policy_types
                    .entry(policy_result.policy.policy_type.clone())
                    .or_insert(0) += 1;
                let (policy_results, failure_types) = match &policy_result.policy.policy_type {
                    PolicyType::Sts => (&mut tls.sts_policy_results, &mut tls.sts_failure_types),
                    PolicyType::Tlsa => (&mut tls.tlsa_policy_results, &mut tls.tlsa_failure_types),
                    PolicyType::NoPolicyFound => {
                        continue;
                    }
                };
                let success_count = policy_result.summary.total_successful_session_count;
                let failure_count = policy_result.summary.total_failure_session_count;
                *policy_results.entry(TlsResultType::Successful).or_insert(0) += success_count;
                *policy_results.entry(TlsResultType::Failure).or_insert(0) += failure_count;
                if let Some(failure_details) = &policy_result.failure_details {
                    for failure_detail in failure_details {
                        *failure_types
                            .entry(failure_detail.result_type.clone())
                            .or_insert(0) += failure_detail.failed_session_count;
                    }
                }
            }
        }
        Self {
            mails,
            last_update,
            next_update,
            dmarc,
            tls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmarc::Report;

    fn record(ip: &str, dkim: &str, spf: &str, count: usize) -> String {
        format!(
            "<record><row><source_ip>{ip}</source_ip><count>{count}</count><policy_evaluated>\
            <disposition>none</disposition><dkim>{dkim}</dkim><spf>{spf}</spf>\
            </policy_evaluated></row><identifiers><header_from>example.com</header_from>\
            </identifiers><auth_results><spf><domain>example.com</domain><result>pass</result>\
            </spf></auth_results></record>"
        )
    }

    #[test]
    fn dmarc_results_fail_only_if_spf_and_dkim_failed() {
        let xml = format!(
            "<feedback><report_metadata><org_name>a</org_name><email>a@a.org</email>\
            <report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range>\
            </report_metadata><policy_published><domain>example.com</domain><p>none</p>\
            </policy_published>{}{}{}{}</feedback>",
            record("192.0.2.1", "pass", "pass", 1),
            record("192.0.2.2", "pass", "fail", 2),
            record("192.0.2.3", "fail", "pass", 3),
            record("192.0.2.4", "fail", "fail", 4),
        );
        let report = Report::from_slice(xml.as_bytes()).unwrap();
        let mut dmarc = BTreeMap::new();
        dmarc.insert(
            String::from("hash"),
            DmarcReportWithMailId {
                mail_id: String::from("mail"),
                report,
            },
        );
        let tls = BTreeMap::new();

        let summary = Summary::new(
            1,
            Reports {
                dmarc: &dmarc,
                tls: &tls,
            },
            None,
            None,
            None,
            None,
            None,
        );

        let results = &summary.dmarc.dmarc_results;
        assert_eq!(results.get(&DmarcResultType::Pass), Some(&6));
        assert_eq!(results.get(&DmarcResultType::Fail), Some(&4));
        assert_eq!(results.len(), 2);
    }
}
