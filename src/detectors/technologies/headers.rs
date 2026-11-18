// Does:  Detects technology signatures in captured response headers.
// Holds: Detection uses captured calls without issuing requests.

use crate::types::ApiCall;

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
    ("axum", "Axum"),
    ("actix", "Actix"),
    ("warp", "Warp"),
    ("hyper", "Hyper"),
    ("werkzeug", "Werkzeug"),
    ("tornado", "Tornado"),
    ("puma", "Puma"),
    ("thin", "Thin"),
    ("unicorn", "Unicorn"),
];

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
    ("phoenix", "Phoenix"),
    ("gin", "Gin"),
    ("fiber", "Fiber"),
    ("echo", "Echo"),
    ("nestjs", "NestJS"),
    ("adonisjs", "AdonisJS"),
    ("sails", "Sails.js"),
];

/// Detects technology signatures in captured response headers.
///
///     assert!(corrode_scanner::detectors::technologies::headers::detect(&[]).is_empty());
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
