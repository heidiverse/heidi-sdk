//! The goal of this module is to provide utilities for working with JSON-LD data, specifically
//! parsing JSON-LD documents, converting them to RDF, and taking RDF data and converting it back to
//! compact JSON-LD documents.

use iref::IriBuf;
use json_ld::{
    JsonLdProcessor, Loader, RemoteDocument, RemoteDocumentReference,
    rdf_types::generator::Blank as BlankGenerator,
    syntax::{Context, ContextEntry, Parse, Value as JsonLdValue},
};
use mime::Mime;
use serde_json::Value as JsonValue;

use frame::FramingOptions;

pub mod loader;

pub struct JsonLdDocument<L: Loader> {
    document: RemoteDocument<IriBuf, JsonLdValue>,
    loader: L,
}

impl<L: Loader> JsonLdDocument<L> {
    pub fn new(input: &str, loader: L) -> Self {
        let (input, _) = JsonLdValue::parse_str(input).unwrap();

        let url = None::<IriBuf>;
        let content_type = None::<Mime>;

        let document = RemoteDocument::new(url, content_type, input);

        Self { document, loader }
    }

    pub async fn compacted(&self, context: Vec<IriBuf>) -> JsonValue {
        let context = Context::Many(
            context
                .into_iter()
                .map(|e| ContextEntry::IriRef(e.into()))
                .collect(),
        );

        let context = RemoteDocument::new(None::<IriBuf>, None::<Mime>, context);
        let context = RemoteDocumentReference::Loaded(context);

        let compacted = self.document.compact(context, &self.loader).await.unwrap();
        convert_value(compacted)
    }

    pub async fn flattened(&self) -> JsonValue {
        let mut generator = BlankGenerator::new();

        let flattened = self
            .document
            .flatten(&mut generator, &self.loader)
            .await
            .unwrap();
        convert_value(flattened)
    }

    pub async fn framed(&self, frame: &JsonValue) -> JsonValue {
        let flattened = self.flattened().await;

        let node_map = frame::create_node_map(flattened);

        let framed = frame::frame(
            &node_map,
            frame,
            FramingOptions {
                embed: frame::EmbedMode::Once,
                explicit: false,
                require_all: false,
                omit_default: false,
                omit_graph: true,
            },
        )
        .unwrap();

        framed
    }
}

fn convert_value(value: json_syntax::Value) -> JsonValue {
    let string = value.to_string();
    serde_json::from_str(&string).expect("Converted JSON-LD value should be valid JSON")
}

mod frame {
    use serde_json::{Map, Value, json};
    use std::collections::{HashMap, HashSet};

    /// Configuration options for the JSON-LD Framing algorithm.
    ///
    /// These options determine how the Framing Algorithm restructures the input graph,
    /// specifically controlling embedding logic, pattern matching strictness, and output formatting.
    #[derive(Debug, Clone)]
    pub struct FramingOptions {
        /// Controls how referenced node objects are embedded in the output.
        ///
        /// * **Default**: `EmbedMode::Once`
        ///
        /// This corresponds to the `@embed` keyword in JSON-LD.
        pub embed: EmbedMode,

        /// Controls whether to include properties not specified in the frame.
        ///
        /// * **`false` (Default)**: All properties found in the matching node are included in the output,
        ///   even if they are not present in the input Frame. This preserves extra data ("duck typing").
        /// * **`true`**: Only properties explicitly defined in the input Frame are included in the output.
        ///   Any extra data in the node is discarded.
        ///
        /// This corresponds to the `@explicit` keyword in JSON-LD.
        pub explicit: bool,

        /// Controls the strictness of the Frame Matching algorithm.
        ///
        /// * **`false` (Default)**: A node matches the frame if it matches the `@id`, `@type`,
        ///   or *any* of the properties defined in the frame.
        /// * **`true`**: A node matches the frame only if it contains *all* of the non-keyword
        ///   properties defined in the frame.
        ///
        /// This corresponds to the `@requireAll` keyword in JSON-LD.
        pub require_all: bool,

        /// Controls how missing properties are handled in the output.
        ///
        /// * **`false` (Default)**: If a property is defined in the Frame but missing from the matching Node,
        ///   it is included in the output with the value `null`.
        /// * **`true`**: If a property is missing from the matching Node, it is strictly omitted from the output.
        ///
        /// Note: This is overridden if a property in the Frame has an explicit `@default` value.
        pub omit_default: bool,

        /// Controls the structure of the root output.
        ///
        /// * **`false` (Default)**: The output is always a valid JSON-LD object containing a `"@graph"` property,
        ///   which holds an array of matches (e.g., `{ "@context": ..., "@graph": [...] }`).
        /// * **`true`**: If the framing result contains exactly one matching node, the `"@graph"` wrapper
        ///   is removed, and that single node object is returned directly. If there are 0 or >1 matches,
        ///   the `"@graph"` array is preserved.
        pub omit_graph: bool,
    }

    /// Defines the strategy for embedding node objects within the JSON tree.
    #[derive(Debug, Clone, PartialEq, Copy)]
    pub enum EmbedMode {
        /// Embeds the node object every time it is referenced in the graph.
        ///
        /// **Warning**: This can lead to very large outputs or infinite loops if the graph is cyclic
        /// (though robust implementations often detect cycles and fall back to references).
        Always,

        /// (Default) Embeds the node object the first time it is encountered.
        ///
        /// Subsequent references to the same node (by `@id`) will use a simple node reference
        /// (e.g., `{ "@id": "did:example:123" }`) rather than re-embedding the full object.
        Once,

        /// Never embeds the node object.
        ///
        /// Always uses a simple node reference (e.g., `{ "@id": "did:example:123" }`),
        /// keeping the graph flat.
        Never,
    }

    impl Default for FramingOptions {
        fn default() -> Self {
            FramingOptions {
                embed: EmbedMode::Once,
                explicit: false,
                require_all: false,
                omit_default: false,
                omit_graph: false,
            }
        }
    }

    struct FramingState<'a> {
        options: FramingOptions,
        node_map: &'a HashMap<String, Map<String, Value>>,
        embedded_nodes: HashSet<String>,
    }

    pub fn frame(
        node_map: &HashMap<String, Map<String, Value>>,
        frame: &Value,
        options: FramingOptions,
    ) -> Result<Value, String> {
        let mut state = FramingState {
            options,
            node_map,
            embedded_nodes: HashSet::new(),
        };

        let frame_map = frame.as_object().ok_or("Frame must be a JSON object")?;

        // 1. Identify valid subjects (keys in the map)
        let subjects: Vec<String> = node_map.keys().cloned().collect();

        // 2. Initial match to find root nodes
        let matches = filter_subjects(&state, &subjects, frame_map);

        let mut results = Vec::new();

        // 3. Process matches
        for id in matches {
            if let Some(node_output) = frame_node(&mut state, &id, frame_map) {
                results.push(Value::Object(node_output));
            }
        }

        // 4. Handle omitGraph
        if state.options.omit_graph && results.len() == 1 {
            Ok(results[0].clone())
        } else {
            Ok(json!({ "@graph": results }))
        }
    }

    /// Recursive function to frame a specific node
    fn frame_node(
        state: &mut FramingState,
        id: &str,
        frame: &Map<String, Value>,
    ) -> Option<Map<String, Value>> {
        let node = state.node_map.get(id)?;

        // Handle @embed logic
        let embed_mode = get_frame_flag(frame, "@embed", state.options.embed);

        // If @embed is Never, or Once and already embedded, return a Node Reference
        if embed_mode == EmbedMode::Never
            || (embed_mode == EmbedMode::Once && state.embedded_nodes.contains(id))
        {
            return Some(json!({ "@id": id }).as_object().unwrap().clone());
        }

        // Mark as embedded
        state.embedded_nodes.insert(id.to_string());

        let mut output = Map::new();
        output.insert("@id".to_string(), json!(id));

        let explicit = get_frame_bool(frame, "@explicit", state.options.explicit);

        // Iterate over node properties
        // We sort keys to ensure deterministic output
        let mut keys: Vec<&String> = node.keys().collect();
        keys.sort();

        for key in keys {
            // Always include keywords (@type, etc)
            if key.starts_with('@') {
                output.insert(key.clone(), node[key].clone());
                continue;
            }

            // Check if property is in frame
            let in_frame = frame.contains_key(key);
            if explicit && !in_frame {
                continue;
            }

            // Get sub-frame (default to empty object if not present)
            let empty_object = json!({});
            let sub_frame_val = frame.get(key).unwrap_or(&empty_object);
            let empty_map: Map<String, Value> = Map::new();
            let sub_frame = sub_frame_val.as_object().unwrap_or(&empty_map);

            // Handle the values (Robust: handles both Array and Single Value)
            let values = to_vec(&node[key]);
            let mut output_values = Vec::new();

            for item in values {
                // Check if it is a reference to another node
                if let Some(node_ref_id) = get_node_id(&item) {
                    // RECURSION: Frame the referenced node
                    if let Some(framed_child) = frame_node(state, &node_ref_id, sub_frame) {
                        output_values.push(Value::Object(framed_child));
                    }
                } else {
                    // Literal value: verify matches pattern if needed, otherwise copy
                    // (Simplified: just copy literal)
                    output_values.push(item.clone());
                }
            }

            // If we have results, add to output
            if !output_values.is_empty() {
                // Preservation: if original was single value, try to keep it single?
                // Standard JSON-LD usually outputs arrays for framed graphs unless @container is set.
                // For this simple implementation, we'll output arrays to be safe,
                // OR single values if length is 1 to match your test expectation.
                if output_values.len() == 1 {
                    output.insert(key.clone(), output_values[0].clone());
                } else {
                    output.insert(key.clone(), Value::Array(output_values));
                }
            }
        }

        // Handle @default values
        for (key, val) in frame {
            // Skip keywords
            if key.starts_with('@') {
                continue;
            }

            // If the property is NOT already in the output (meaning it wasn't in the node data)
            if !output.contains_key(key) {
                let sub_frame_obj = val.as_object();

                // 1. Check for explicit @default in the frame
                if let Some(default_val) = sub_frame_obj.and_then(|o| o.get("@default")) {
                    output.insert(key.clone(), default_val.clone());
                }
                // 2. If no explicit default, check the omit_default flag
                // If omit_default is FALSE (default), we must output null to indicate "missing".
                else if !state.options.omit_default {
                    output.insert(key.clone(), Value::Null);
                }
                // If omit_default is TRUE, we do nothing (exclude the property).
            }
        }

        Some(output)
    }

    /// Filter subjects based on Frame matching
    fn filter_subjects(
        state: &FramingState,
        subjects: &[String],
        frame: &Map<String, Value>,
    ) -> Vec<String> {
        let mut matched = Vec::new();
        let require_all = get_frame_bool(frame, "@requireAll", state.options.require_all);

        for id in subjects {
            if let Some(node) = state.node_map.get(id) {
                if node_matches(node, frame, require_all) {
                    matched.push(id.clone());
                }
            }
        }
        matched
    }

    /// Check if a node matches the frame pattern
    fn node_matches(
        node: &Map<String, Value>,
        frame: &Map<String, Value>,
        require_all: bool,
    ) -> bool {
        // 1. Match @type
        if let Some(frame_type) = frame.get("@type") {
            let node_types = to_vec(node.get("@type").unwrap_or(&Value::Null));
            // Check if ANY frame type is present in node types
            let frame_types = to_vec(frame_type);
            let mut type_match = false;
            for ft in &frame_types {
                if node_types.contains(ft) {
                    type_match = true;
                    break;
                }
            }
            if !type_match {
                return false;
            }
        }

        // 2. Match @id
        if let Some(frame_id) = frame.get("@id") {
            let node_id = node
                .get("@id")
                .map(|v| v.as_str().unwrap_or(""))
                .unwrap_or("");
            let frame_ids = to_vec(frame_id);
            let mut id_match = false;
            for fid in frame_ids {
                if fid.as_str() == Some(node_id) {
                    id_match = true;
                    break;
                }
            }
            if !id_match {
                return false;
            }
        }

        // 3. Match Properties (Duck Typing)
        // If require_all is true, checks that node has all properties defined in frame
        if require_all {
            for key in frame.keys() {
                if key.starts_with('@') {
                    continue;
                }
                if !node.contains_key(key) {
                    // If frame has default, it's okay
                    let has_default = frame[key]
                        .as_object()
                        .map(|o| o.contains_key("@default"))
                        .unwrap_or(false);
                    if !has_default {
                        return false;
                    }
                }
            }
        }

        true
    }

    // --- Helpers ---

    fn get_frame_bool(frame: &Map<String, Value>, key: &str, default: bool) -> bool {
        frame.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
    }

    fn get_frame_flag(frame: &Map<String, Value>, key: &str, default: EmbedMode) -> EmbedMode {
        if let Some(val) = frame.get(key).and_then(|v| v.as_str()) {
            match val {
                "@always" => EmbedMode::Always,
                "@never" => EmbedMode::Never,
                "@once" => EmbedMode::Once,
                _ => default,
            }
        } else {
            default
        }
    }

    /// Helper to normalize Single Value vs Array into a Vec
    fn to_vec(val: &Value) -> Vec<Value> {
        match val {
            Value::Array(arr) => arr.clone(),
            Value::Null => vec![],
            _ => vec![val.clone()],
        }
    }

    /// Helper to extract ID from a node reference {"@id": "..."}
    fn get_node_id(val: &Value) -> Option<String> {
        val.as_object()
            .and_then(|obj| obj.get("@id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    pub fn create_node_map(json_ld: Value) -> HashMap<String, Map<String, Value>> {
        let nodes = match &json_ld {
            Value::Array(arr) => Some(arr),
            Value::Object(obj) => obj.get("@graph").and_then(|g| g.as_array()),
            _ => None,
        };

        let mut map = HashMap::new();
        if let Some(nodes) = nodes {
            for node in nodes {
                let id = node["@id"].as_str().unwrap().to_string();
                let obj = node.as_object().unwrap().clone();
                map.insert(id, obj);
            }
        }
        map
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_arrays_vs_singles() {
            let data = json!({
                "@graph": [
                    {
                        "@id": "node:1",
                        "tags": ["tag1", "tag2"],
                        "title": ["Single Title"]
                    }
                ]
            });

            let frame = json!({
                "@id": "node:1",
                "tags": {},
                "title": {}
            });

            let map = create_node_map(data);
            let result = super::frame(&map, &frame, FramingOptions::default()).unwrap();

            assert_eq!(
                result,
                json!({
                    "@graph": [{
                        "@id": "node:1",
                        "tags": ["tag1", "tag2"], // Keeps array
                        "title": "Single Title"   // Unwraps single value
                    }]
                })
            );
        }

        #[test]
        fn test_explicit_flag() {
            let data = json!({
                "@graph": [{
                    "@id": "node:1",
                    "keepMe": "value1",
                    "dropMe": "value2"
                }]
            });

            let map = create_node_map(data);

            // Case A: Explicit = false (Default)
            // Should keep properties even if not in frame
            let frame_loose = json!({ "@id": "node:1", "keepMe": {} });
            let res_loose = frame(&map, &frame_loose, FramingOptions::default()).unwrap();

            assert_eq!(
                res_loose,
                json!({
                    "@graph": [{
                        "@id": "node:1",
                        "keepMe": "value1",
                        "dropMe": "value2"
                    }]
                })
            );

            // Case B: Explicit = true
            // Should drop properties not in frame
            let frame_strict = json!({
                "@id": "node:1",
                "keepMe": {},
                "@explicit": true
            });
            let options_strict = FramingOptions {
                explicit: true,
                ..FramingOptions::default()
            };
            // Note: The @explicit keyword in the frame object overrides the options struct in a real impl,
            // but for this test we pass it via options to ensure our logic picks it up.
            // In the implementation I provided, we check: get_frame_bool(..., "@explicit", state.options.explicit)
            // so putting it in the JSON frame works too!
            let res_strict = super::frame(&map, &frame_strict, options_strict).unwrap();

            assert_eq!(
                res_strict,
                json!({
                    "@graph": [{
                        "@id": "node:1",
                        "keepMe": "value1"
                    }]
                })
            );
        }

        #[test]
        fn test_require_all() {
            let data = json!({
                "@graph": [
                    { "@id": "node:match", "propA": "a", "propB": "b" },
                    { "@id": "node:partial", "propA": "a" }
                ]
            });

            let frame = json!({
                "@requireAll": true,
                "propA": {},
                "propB": {}
            });

            let map = create_node_map(data);
            let result = super::frame(&map, &frame, FramingOptions::default()).unwrap();

            // Should only contain the node that has BOTH properties
            assert_eq!(
                result,
                json!({
                    "@graph": [{
                        "@id": "node:match",
                        "propA": "a",
                        "propB": "b"
                    }]
                })
            );
        }

        #[test]
        fn test_default_values() {
            let data = json!({
                "@graph": [{ "@id": "node:1", "existing": "present" }]
            });

            let frame = json!({
                "@id": "node:1",
                "existing": { "@default": "wrong" }, // Should NOT overwrite
                "missing": { "@default": "filled" }   // Should fill
            });

            let map = create_node_map(data);
            let result = super::frame(&map, &frame, FramingOptions::default()).unwrap();

            assert_eq!(
                result,
                json!({
                    "@graph": [{
                        "@id": "node:1",
                        "existing": "present",
                        "missing": "filled"
                    }]
                })
            );
        }

        #[test]
        fn test_embed_never() {
            let data = json!({
                "@graph": [
                    { "@id": "parent", "child": { "@id": "child" } },
                    { "@id": "child", "name": "The Child" }
                ]
            });

            let frame = json!({
                "@id": "parent",
                "child": {
                    "@embed": "@never",
                    "name": {}
                }
            });

            let map = create_node_map(data);
            let result = super::frame(&map, &frame, FramingOptions::default()).unwrap();

            // Child should be a reference only ({"@id": "child"}), ignoring "name"
            assert_eq!(
                result,
                json!({
                    "@graph": [{
                        "@id": "parent",
                        "child": { "@id": "child" }
                    }]
                })
            );
        }

        #[test]
        fn test_deep_chain() {
            let data = json!({
                "@graph": [
                    { "@id": "1", "next": { "@id": "2" } },
                    { "@id": "2", "next": { "@id": "3" } },
                    { "@id": "3", "value": "end" }
                ]
            });

            let frame = json!({
                "@id": "1",
                "next": {
                    "next": {
                        "value": {}
                    }
                }
            });

            let map = create_node_map(data);
            let result = super::frame(&map, &frame, FramingOptions::default()).unwrap();

            assert_eq!(
                result,
                json!({
                    "@graph": [{
                        "@id": "1",
                        "next": {
                            "@id": "2",
                            "next": {
                                "@id": "3",
                                "value": "end"
                            }
                        }
                    }]
                })
            );
        }

        #[test]
        fn test_omit_graph() {
            let data = json!({ "@graph": [{ "@id": "1", "p": "v" }] });
            let frame = json!({ "@id": "1", "p": {} });
            let map = create_node_map(data);

            // 1. Standard: returns { @graph: [...] }
            let res_std = super::frame(&map, &frame, FramingOptions::default()).unwrap();
            assert_eq!(
                res_std,
                json!({
                    "@graph": [{ "@id": "1", "p": "v" }]
                })
            );

            // 2. Option set: returns { @id: ... } directly (unwraps the graph array)
            let options = FramingOptions {
                omit_graph: true,
                ..FramingOptions::default()
            };
            let res_opt = super::frame(&map, &frame, options).unwrap();

            assert_eq!(
                res_opt,
                json!({
                    "@id": "1",
                    "p": "v"
                })
            );
        }

        #[test]
        fn test_omit_default_flag() {
            // Data has ID but missing "missingProp"
            let data = json!({ "@graph": [{ "@id": "1" }] });

            // Frame asks for "missingProp"
            let frame = json!({
                "@id": "1",
                "missingProp": {}
            });

            let map = create_node_map(data);

            // Case 1: Default Behavior (omit_default = false)
            // Expectation: Missing property appears as null
            let res_default = super::frame(&map, &frame, FramingOptions::default()).unwrap();
            assert_eq!(
                res_default,
                json!({
                    "@graph": [{
                        "@id": "1",
                        "missingProp": null
                    }]
                })
            );

            // Case 2: Omit Default = true
            // Expectation: Missing property is excluded entirely
            let options = FramingOptions {
                omit_default: true,
                ..FramingOptions::default()
            };
            let res_omit = super::frame(&map, &frame, options).unwrap();
            assert_eq!(
                res_omit,
                json!({
                    "@graph": [{
                        "@id": "1"
                        // "missingProp" is gone
                    }]
                })
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use json_ld::ReqwestLoader;
    use serde_json::json;
    use static_iref::iri;

    use crate::json_ld::loader::{FallbackLoader, StaticLoader};

    use super::JsonLdDocument;

    #[tokio::test]
    async fn test() {
        let mut loader = StaticLoader::new();
        loader.add_document(
            "https://www.w3.org/ns/credentials/v2",
            include_str!("../../jsonld/www.w3.org/ns/credentials/v2"),
        );
        loader.add_document(
            "https://www.w3.org/ns/credentials/examples/v2",
            include_str!("../../jsonld/www.w3.org/ns/credentials/examples/v2"),
        );
        let loader = FallbackLoader::new(loader, ReqwestLoader::new());

        let jsonld = r#"
{
  "@graph": [
    {
      "@id": "_:b0",
      "@type": "https://www.w3.org/ns/credentials/examples#ExampleBachelorDegree",
      "https://schema.org/name": "Bachelor of Science and Arts"
    },
    {
      "@id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "https://www.w3.org/ns/credentials/examples#degree": {
        "@id": "_:b0"
      }
    },
    {
      "@id": "http://university.example/credentials/3732",
      "@type": [
        "https://www.w3.org/2018/credentials#VerifiableCredential",
        "https://www.w3.org/ns/credentials/examples#ExampleDegreeCredential"
      ],
      "https://schema.org/description": "2015 Bachelor of Science and Arts Degree",
      "https://schema.org/name": "Example University Degree",
      "https://www.w3.org/2018/credentials#credentialSubject": {
        "@id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
      },
      "https://www.w3.org/2018/credentials#issuer": {
        "@id": "https://university.example/issuers/565049"
      },
      "https://www.w3.org/2018/credentials#validFrom": {
        "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
        "@value": "2015-05-10T12:30:00Z"
      }
    },
    {
      "@id": "https://university.example/issuers/565049",
      "https://schema.org/description": "A public university focusing on teaching examples.",
      "https://schema.org/name": "Example University"
    }
  ]
}
        "#;

        let doc = JsonLdDocument::new(jsonld, &loader);

        let context = vec![
            iri!("https://www.w3.org/ns/credentials/v2").to_owned(),
            iri!("https://www.w3.org/ns/credentials/examples/v2").to_owned(),
        ];

        let compacted = doc.compacted(context.clone()).await;
        println!("Compacted JSON-LD: {:#}", compacted);

        let flattened = doc.flattened().await;
        println!("Flattened JSON-LD: {:#}", flattened);

        let flattened_doc = JsonLdDocument::new(&flattened.to_string(), &loader);

        let frame = json!({
            "@type": "https://www.w3.org/2018/credentials#VerifiableCredential"
        });
        let framed = flattened_doc.framed(&frame).await;
        println!("Framed JSON-LD: {:#}", framed);

        let compacted_framed = JsonLdDocument::new(&framed.to_string(), &loader)
            .compacted(context)
            .await;
        println!("Compacted Framed JSON-LD: {:#}", compacted_framed);
    }
}
