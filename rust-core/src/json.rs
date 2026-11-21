//! Zero-dependency Pure Safe Rust JSON parser & serializer (bounded depth <= 64).

use std::collections::BTreeMap;

pub const MAX_JSON_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Number(n) if *n >= 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.as_object()?.get(key)
    }

    pub fn to_json_string(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out, None, 0);
        out
    }

    pub fn to_json_pretty(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out, Some(2), 0);
        out
    }

    fn write_json(&self, out: &mut String, indent: Option<usize>, level: usize) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JsonValue::Number(n) => {
                if n.is_finite() {
                    if n.fract() == 0.0 && *n >= (i64::MIN as f64) && *n <= (i64::MAX as f64) {
                        out.push_str(&format!("{}", *n as i64));
                    } else {
                        out.push_str(&format!("{}", n));
                    }
                } else {
                    out.push_str("null");
                }
            }
            JsonValue::String(s) => write_escaped_str(out, s),
            JsonValue::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if let Some(ind) = indent {
                        out.push('\n');
                        for _ in 0..((level + 1) * ind) {
                            out.push(' ');
                        }
                    }
                    item.write_json(out, indent, level + 1);
                }
                if !items.is_empty()
                    && let Some(ind) = indent
                {
                    out.push('\n');
                    for _ in 0..(level * ind) {
                        out.push(' ');
                    }
                }
                out.push(']');
            }
            JsonValue::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    if let Some(ind) = indent {
                        out.push('\n');
                        for _ in 0..((level + 1) * ind) {
                            out.push(' ');
                        }
                    }
                    write_escaped_str(out, k);
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.write_json(out, indent, level + 1);
                }
                if !map.is_empty()
                    && let Some(ind) = indent
                {
                    out.push('\n');
                    for _ in 0..(level * ind) {
                        out.push(' ');
                    }
                }
                out.push('}');
            }
        }
    }
}

pub fn write_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn obj(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    let mut map = BTreeMap::new();
    for (k, v) in entries {
        map.insert(k.to_string(), v);
    }
    JsonValue::Object(map)
}

pub fn jstr(s: impl Into<String>) -> JsonValue {
    JsonValue::String(s.into())
}

pub fn jnum(n: f64) -> JsonValue {
    JsonValue::Number(n)
}

pub fn jbool(b: bool) -> JsonValue {
    JsonValue::Bool(b)
}

pub fn parse_json(input: &str) -> Result<JsonValue, String> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing characters at byte {}", parser.pos));
    }
    Ok(val)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON maximum nesting depth exceeded".to_string());
        }
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(c) => Err(format!("unexpected byte '{}' at {}", c as char, self.pos)),
            None => Err("unexpected EOF".to_string()),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], val: JsonValue) -> Result<JsonValue, String> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected '\"'".to_string());
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.pos >= self.bytes.len() {
                        return Err("unterminated escape".to_string());
                    }
                    let esc = self.bytes[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.bytes.len() {
                                return Err("truncated unicode escape".to_string());
                            }
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|_| "invalid utf8 in unicode escape".to_string())?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|_| "invalid hex in unicode escape".to_string())?;
                            self.pos += 4;
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                        _ => return Err(format!("invalid escape '\\{}'", esc as char)),
                    }
                }
                _ => {
                    let start = self.pos - 1;
                    let s = std::str::from_utf8(&self.bytes[start..])
                        .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
                    let ch = s.chars().next().ok_or("empty utf8")?;
                    out.push(ch);
                    self.pos = start + ch.len_utf8();
                }
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number utf8".to_string())?;
        let n: f64 = s.parse().map_err(|_| format!("invalid number '{}'", s))?;
        Ok(JsonValue::Number(n))
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at byte {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(map));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_json() {
        let v = obj(vec![
            ("engine", jstr("nala-oclp-rs")),
            ("version", jnum(3.0)),
            ("safe", jbool(true)),
        ]);
        let s = v.to_json_string();
        let parsed = parse_json(&s).expect("valid json");
        assert_eq!(parsed.get("engine").and_then(|x| x.as_str()), Some("nala-oclp-rs"));
        assert_eq!(parsed.get("safe").and_then(|x| x.as_bool()), Some(true));
    }

    #[test]
    fn rejects_excessive_depth() {
        let deep = "[".repeat(80) + &"]".repeat(80);
        assert!(parse_json(&deep).is_err());
    }
}
