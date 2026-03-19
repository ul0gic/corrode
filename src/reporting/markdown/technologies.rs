use anyhow::Result;

use crate::types::ScanResult;

/// Keyword-to-category mapping for technology classification.
const TECH_CATEGORIES: &[(&str, &str)] = &[
    // Frameworks
    ("react", "Frameworks"),
    ("vue", "Frameworks"),
    ("angular", "Frameworks"),
    ("svelte", "Frameworks"),
    ("next", "Frameworks"),
    ("nuxt", "Frameworks"),
    ("remix", "Frameworks"),
    ("gatsby", "Frameworks"),
    ("ember", "Frameworks"),
    ("backbone", "Frameworks"),
    // Static Site Generators
    ("astro", "Static Site Generators"),
    ("hugo", "Static Site Generators"),
    ("jekyll", "Static Site Generators"),
    ("eleventy", "Static Site Generators"),
    ("hexo", "Static Site Generators"),
    ("docusaurus", "Static Site Generators"),
    ("vuepress", "Static Site Generators"),
    ("mkdocs", "Static Site Generators"),
    ("pelican", "Static Site Generators"),
    // Backend
    ("express", "Backend"),
    ("asp.net", "Backend"),
    ("php", "Backend"),
    ("flask", "Backend"),
    ("django", "Backend"),
    ("rails", "Backend"),
    ("fastify", "Backend"),
    ("koa", "Backend"),
    ("hapi", "Backend"),
    ("cowboy", "Backend"),
    // Infrastructure
    ("cloudflare", "Infrastructure"),
    ("nginx", "Infrastructure"),
    ("apache", "Infrastructure"),
    ("vercel", "Infrastructure"),
    ("netlify", "Infrastructure"),
    ("fly.io", "Infrastructure"),
    ("caddy", "Infrastructure"),
    ("iis", "Infrastructure"),
    ("envoy", "Infrastructure"),
    ("openresty", "Infrastructure"),
    ("gunicorn", "Infrastructure"),
    ("deno deploy", "Infrastructure"),
    // Authentication
    ("auth0", "Authentication"),
    ("clerk", "Authentication"),
    ("okta", "Authentication"),
    // Payment
    ("stripe", "Payment"),
    ("paypal", "Payment"),
    ("braintree", "Payment"),
    ("square", "Payment"),
    // Analytics
    ("google analytics", "Analytics"),
    ("gtag", "Analytics"),
    ("gtm", "Analytics"),
    ("mixpanel", "Analytics"),
    ("segment", "Analytics"),
    ("amplitude", "Analytics"),
    ("hotjar", "Analytics"),
    ("heap", "Analytics"),
    ("fullstory", "Analytics"),
    ("plausible", "Analytics"),
    // CMS/Platforms
    ("wordpress", "CMS/Platforms"),
    ("drupal", "CMS/Platforms"),
    ("joomla", "CMS/Platforms"),
    ("ghost", "CMS/Platforms"),
    ("wix", "CMS/Platforms"),
    ("squarespace", "CMS/Platforms"),
    ("shopify", "CMS/Platforms"),
    ("webflow", "CMS/Platforms"),
    ("contentful", "CMS/Platforms"),
    ("strapi", "CMS/Platforms"),
    // Cloud/BaaS
    ("supabase", "Cloud/BaaS"),
    ("firebase", "Cloud/BaaS"),
    ("appwrite", "Cloud/BaaS"),
    ("aws", "Cloud/BaaS"),
    ("azure", "Cloud/BaaS"),
    ("gcp", "Cloud/BaaS"),
    // Libraries
    ("jquery", "Libraries"),
    ("lodash", "Libraries"),
    ("axios", "Libraries"),
    ("moment", "Libraries"),
    ("tailwind", "Libraries"),
    ("bootstrap", "Libraries"),
    // State Management
    ("redux", "State Management"),
    ("mobx", "State Management"),
    ("zustand", "State Management"),
    ("pinia", "State Management"),
    ("recoil", "State Management"),
    // Monitoring
    ("sentry", "Monitoring"),
    ("datadog", "Monitoring"),
    ("newrelic", "Monitoring"),
    ("logr", "Monitoring"),
];

/// Categorize a technology name into a group for organized display.
fn categorize_technology(tech: &str) -> &'static str {
    let lower = tech.to_lowercase();
    for (keyword, category) in TECH_CATEGORIES {
        if lower.contains(keyword) {
            return category;
        }
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
        "Static Site Generators",
        "Backend",
        "Infrastructure",
        "Authentication",
        "Payment",
        "Analytics",
        "CMS/Platforms",
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
