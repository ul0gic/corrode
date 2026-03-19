use crate::types::ApiCall;

/// Server/reverse-proxy signatures detected from the `server` header.
const SERVER_SIGNATURES: &[(&str, &str)] = &[
    ("cloudflare", "Cloudflare"),
    ("nginx", "nginx"),
    ("apache", "Apache"),
    ("vercel", "Vercel"),
    ("netlify", "Netlify"),
    ("flyio", "Fly.io"),
    ("deno", "Deno Deploy"),
    ("caddy", "Caddy"),
    ("microsoft-iis", "IIS"),
    ("openresty", "OpenResty"),
    ("envoy", "Envoy"),
    ("cowboy", "Cowboy"),
    ("gunicorn", "Gunicorn"),
    ("uvicorn", "Uvicorn"),
    ("kestrel", "Kestrel"),
    ("lighttpd", "lighttpd"),
    ("litespeed", "LiteSpeed"),
];

/// Backend framework signatures detected from `x-powered-by`.
const POWERED_BY_SIGNATURES: &[(&str, &str)] = &[
    ("express", "Express"),
    ("asp.net", "ASP.NET"),
    ("php", "PHP"),
    ("next.js", "Next.js"),
    ("nuxt", "Nuxt.js"),
    ("flask", "Flask"),
    ("django", "Django"),
    ("rails", "Ruby on Rails"),
    ("fastify", "Fastify"),
    ("hapi", "Hapi"),
    ("koa", "Koa"),
    ("laravel", "Laravel"),
    ("symfony", "Symfony"),
    ("spring", "Spring"),
];

/// Detect technologies from HTTP response headers across all captured requests.
pub fn detect(calls: &[ApiCall]) -> Vec<String> {
    let mut detected = Vec::new();

    for call in calls {
        if let Some(server) = call.response_headers.get("server") {
            let lower = server.to_lowercase();
            for (pattern, name) in SERVER_SIGNATURES {
                if lower.contains(pattern) && !detected.contains(&(*name).to_owned()) {
                    detected.push((*name).to_owned());
                }
            }
        }

        if let Some(powered) = call.response_headers.get("x-powered-by") {
            let lower = powered.to_lowercase();
            for (pattern, name) in POWERED_BY_SIGNATURES {
                if lower.contains(pattern) && !detected.contains(&(*name).to_owned()) {
                    detected.push((*name).to_owned());
                }
            }
        }
    }

    detected
}
