use anyhow::Result;

use crate::types::ScanResult;

/// Categorize a technology name into a group for organized display.
fn categorize_technology(tech: &str) -> &'static str {
    let lower = tech.to_lowercase();

    if lower.contains("react")
        || lower.contains("vue")
        || lower.contains("angular")
        || lower.contains("svelte")
        || lower.contains("next")
        || lower.contains("nuxt")
        || lower.contains("remix")
        || lower.contains("gatsby")
        || lower.contains("ember")
        || lower.contains("backbone")
    {
        return "Frameworks";
    }

    if lower.contains("auth0")
        || lower.contains("clerk")
        || lower.contains("okta")
        || lower.contains("firebase auth")
        || lower.contains("supabase auth")
    {
        return "Authentication";
    }

    if lower.contains("stripe")
        || lower.contains("paypal")
        || lower.contains("braintree")
        || lower.contains("square")
    {
        return "Payment";
    }

    if lower.contains("google analytics")
        || lower.contains("gtag")
        || lower.contains("mixpanel")
        || lower.contains("segment")
        || lower.contains("amplitude")
        || lower.contains("hotjar")
        || lower.contains("heap")
        || lower.contains("fullstory")
        || lower.contains("plausible")
    {
        return "Analytics";
    }

    if lower.contains("wordpress")
        || lower.contains("drupal")
        || lower.contains("webflow")
        || lower.contains("contentful")
        || lower.contains("strapi")
    {
        return "CMS";
    }

    if lower.contains("supabase")
        || lower.contains("firebase")
        || lower.contains("appwrite")
        || lower.contains("aws")
        || lower.contains("azure")
        || lower.contains("gcp")
    {
        return "Cloud/BaaS";
    }

    if lower.contains("jquery")
        || lower.contains("lodash")
        || lower.contains("axios")
        || lower.contains("moment")
        || lower.contains("tailwind")
        || lower.contains("bootstrap")
    {
        return "Libraries";
    }

    if lower.contains("redux")
        || lower.contains("mobx")
        || lower.contains("zustand")
        || lower.contains("pinia")
        || lower.contains("recoil")
    {
        return "State Management";
    }

    if lower.contains("sentry")
        || lower.contains("datadog")
        || lower.contains("newrelic")
        || lower.contains("logr")
    {
        return "Monitoring";
    }

    "Other"
}

pub(crate) fn render_technologies(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    if result.technologies.is_empty() && result.technology_versions.is_empty() {
        return report;
    }

    report.push("---\n## Technology Stack\n".to_owned());

    // Group technologies by category
    let mut categories: std::collections::HashMap<&str, Vec<String>> =
        std::collections::HashMap::new();

    for tech in &result.technologies {
        let category = categorize_technology(tech);
        // Check if we have a version for this technology
        let version_info = result
            .technology_versions
            .iter()
            .find(|tv| tv.name.eq_ignore_ascii_case(tech))
            .and_then(|tv| tv.version.as_ref());

        let display = if let Some(ver) = version_info {
            format!("{tech} {ver}")
        } else {
            tech.clone()
        };

        categories.entry(category).or_default().push(display);
    }

    // Also add technology versions not in the base list
    for tv in &result.technology_versions {
        let already_listed = result
            .technologies
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&tv.name));
        if !already_listed {
            let category = categorize_technology(&tv.name);
            let display = if let Some(ver) = &tv.version {
                format!("{} {} (via {})", tv.name, ver, tv.detection_method)
            } else {
                format!("{} (via {})", tv.name, tv.detection_method)
            };
            categories.entry(category).or_default().push(display);
        }
    }

    // Render in a stable order
    let category_order = [
        "Frameworks",
        "Authentication",
        "Payment",
        "Analytics",
        "CMS",
        "Cloud/BaaS",
        "Libraries",
        "State Management",
        "Monitoring",
        "Other",
    ];

    for category in category_order {
        if let Some(techs) = categories.get(category) {
            if !techs.is_empty() {
                report.push(format!("**{category}**:"));
                for tech in techs {
                    report.push(format!("- {tech}"));
                }
                report.push(String::new());
            }
        }
    }

    report
}

pub(crate) fn render_dom(result: &ScanResult) -> Result<Vec<String>> {
    let mut report = Vec::new();

    report.push("---\n## DOM Insights\n".to_owned());
    report.push(format!("- Scripts: {}", result.dom.scripts));
    report.push(format!("- Forms: {}", result.dom.forms.len()));
    report.push(format!(
        "- Hidden Inputs: {}",
        result.dom.hidden_inputs.len()
    ));
    report.push(format!("- iframes: {}", result.dom.iframes.len()));

    if !result.dom.data_attributes.is_empty() {
        report.push("\n### Data Attributes\n".to_owned());
        for attr in &result.dom.data_attributes {
            report.push(format!(
                "- {}: {}",
                attr.tag,
                serde_json::to_string_pretty(&attr.attributes)?
            ));
        }
    }

    Ok(report)
}
