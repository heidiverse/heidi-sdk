use heidi_util_rust::value::Value;

pub fn canonicalize_object(v: &heidi_util_rust::value::Value) -> String {
    let Some(obj) = v.as_object() else {
        return String::new();
    };
    let mut keys = obj.keys().collect::<Vec<_>>();
    keys.sort();
    let mut output_string = String::new();
    output_string.push_str("{");
    for key in keys {
        output_string.push_str(r#"""#);
        output_string.push_str(key);
        output_string.push_str(r#"""#);
        output_string.push_str(":");
        output_string.push_str(&stringify_value(obj.get(key).unwrap()));
        output_string.push_str(",");
    }
    if output_string.contains(",") {
        output_string = (&output_string[..output_string.len() - 1]).to_string();
    }
    output_string.push_str("}");
    output_string
}

fn canonicalize_array(v: &Value) -> String {
    let mut output_string = String::new();
    output_string.push_str("[");
    for item in v.as_array().unwrap() {
        output_string.push_str(&stringify_value(item));
        output_string.push_str(",")
    }
    if output_string.contains(",") {
        output_string = (&output_string[..output_string.len() - 1]).to_string();
    }
    output_string.push_str("]");
    output_string
}
fn canonicalize_primitive(v: &Value) -> String {
    let serde_json_value: serde_json::Value = v.into();
    serde_json::to_string(&serde_json_value)
        .unwrap()
        .trim()
        .to_string()
}

fn stringify_value(value: &heidi_util_rust::value::Value) -> String {
    match value {
        Value::Array(_) => canonicalize_array(value),
        Value::Object(_) => canonicalize_object(value),
        _ => canonicalize_primitive(value),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::sdjwt_util::hash_algs::ec_pedersen::canonicalize::canonicalize_object;

    #[test]
    fn test_canonicalize() {
        let v = json!({
            "b" : [
                1,2,


                4
            ],
            "a" : 120,
            "c" : "test",
            "f" : true
        });
        let val: heidi_util_rust::value::Value = v.into();
        let canonicalized = canonicalize_object(&val);
        assert_eq!(
            canonicalized,
            "{\"a\":120,\"b\":[1,2,4],\"c\":\"test\",\"f\":true}"
        );
    }
}
