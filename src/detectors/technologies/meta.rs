use crate::types::MetaTag;

/// Generator meta tag signatures for SSG/CMS frameworks.
const GENERATOR_SIGNATURES: &[(&str, &str)] = &[
    ("astro", "Astro"),
    ("wordpress", "WordPress"),
    ("drupal", "Drupal"),
    ("hugo", "Hugo"),
    ("jekyll", "Jekyll"),
    ("gatsby", "Gatsby"),
    ("next.js", "Next.js"),
    ("nuxt", "Nuxt.js"),
    ("ghost", "Ghost"),
    ("eleventy", "Eleventy"),
    ("hexo", "Hexo"),
    ("docusaurus", "Docusaurus"),
    ("vuepress", "VuePress"),
    ("mkdocs", "MkDocs"),
    ("pelican", "Pelican"),
    ("joomla", "Joomla"),
    ("wix.com", "Wix"),
    ("squarespace", "Squarespace"),
    ("shopify", "Shopify"),
    ("webflow", "Webflow"),
    ("svelte", "SvelteKit"),
];

/// Detect technologies from HTML `<meta>` tags.
pub fn detect(meta_tags: &[MetaTag]) -> Vec<String> {
    let mut detected = Vec::new();

    for tag in meta_tags {
        let name_lower = tag.name.to_lowercase();

        if name_lower == "generator" {
            let content_lower = tag.content.to_lowercase();
            for (pattern, name) in GENERATOR_SIGNATURES {
                if content_lower.contains(pattern) && !detected.contains(&(*name).to_owned()) {
                    detected.push((*name).to_owned());
                }
            }
        }
    }

    detected
}
