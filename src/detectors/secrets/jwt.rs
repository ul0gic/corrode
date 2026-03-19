use base64::{engine::general_purpose, Engine as _};

pub(crate) fn jwt_has_role(jwt: &str, role: &str) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let Some(payload_part) = parts.get(1) else {
        return false;
    };
    if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(payload_part) {
        if let Ok(payload) = String::from_utf8(decoded) {
            let role_marker = format!(r#""role":"{role}""#);
            return payload.contains(role_marker.as_str());
        }
    }
    false
}

pub(crate) fn is_service_role_jwt(jwt: &str) -> bool {
    jwt_has_role(jwt, "service_role")
}

pub(crate) fn is_anon_jwt(jwt: &str) -> bool {
    jwt_has_role(jwt, "anon")
}
