//! QR codes (setting up two-factor authentication from a phone
//! authenticator app, invite links...).

use qrcode::{EcLevel, QrCode};

/// QR module matrix (`true` = dark), without a quiet zone.
pub fn matrix(text: &str) -> Option<Vec<Vec<bool>>> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    Some(
        colors
            .chunks(width)
            .map(|row| row.iter().map(|c| *c == qrcode::Color::Dark).collect())
            .collect(),
    )
}

/// QR as SVG (black on white, with a 4-module quiet zone), ready for an
/// `<img src="data:image/svg+xml;...">`.
pub fn svg(text: &str) -> Option<String> {
    let m = matrix(text)?;
    let quiet = 4;
    let size = m.len() + quiet * 2;
    let mut path = String::new();
    for (y, row) in m.iter().enumerate() {
        for (x, dark) in row.iter().enumerate() {
            if *dark {
                path.push_str(&format!("M{} {}h1v1h-1z", x + quiet, y + quiet));
            }
        }
    }
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
         shape-rendering=\"crispEdges\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/>\
         <path d=\"{path}\" fill=\"#000\"/></svg>"
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn qr_is_square_and_svg_is_valid() {
        let m = super::matrix("otpauth://totp/Termoak:ana?secret=GEZDGNBV").unwrap();
        assert!(m.len() >= 21);
        assert!(m.iter().all(|r| r.len() == m.len()));
        let svg = super::svg("hello").unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert!(svg.contains("h1v1h-1z"));
    }
}
