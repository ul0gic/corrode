// Does:  Exercises the scanner's public components with inputs available in a fresh checkout.
// Holds: Each inline script is analyzed as its own source unit.

mod confidence_labels;
mod config;
mod cve_detection;
mod manifest_intel;
mod patterns;
mod regression_guard;
mod sourcemap_intel;
mod taint_fixtures;
mod taint_gadgets;
mod wordpress_advisories;

fn scripts<'a>(html: &'a str, url: &'a str) -> Vec<(&'a str, &'a str)> {
    html.split("<script")
        .skip(1)
        .map(|element| {
            let (_, body) = element.split_once('>').expect("fixture script opening tag");
            let (source, _) = body
                .split_once("</script>")
                .expect("fixture script closing tag");
            (source, url)
        })
        .collect()
}
