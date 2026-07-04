use std::collections::HashMap;

use hive_router_config::error_masking::{
    ErrorMaskingConfig, ExtensionsMaskingConfig, SubgraphErrorMaskingConfig,
};
use sonic_rs::{JsonValueMutTrait, Value};

use crate::response::graphql_error::{GraphQLError, GraphQLErrorExtensions};

pub struct ErrorMaskingRuntime {
    default_redacted_error_message: String,
    per_subgraph_config: HashMap<String, ErrorMaskingCompiledConfig>,
    default_config: ErrorMaskingCompiledConfig,
}

impl ErrorMaskingRuntime {
    pub fn apply(&self, err: &mut GraphQLError) {
        if let Some(service_name) = &err.extensions.service_name {
            let effective_config = self
                .per_subgraph_config
                .get(service_name)
                .unwrap_or(&self.default_config);

            if effective_config.redact_error_message {
                err.message = self.default_redacted_error_message.clone();
            }

            if let Some(plan) = &effective_config.extensions_plan {
                plan.apply(&mut err.extensions);
            }
        }
    }

    pub fn compile_from_config(config: &ErrorMaskingConfig) -> Self {
        Self {
            default_redacted_error_message: config.redacted_error_message.clone(),
            per_subgraph_config: config
                .subgraphs
                .as_ref()
                .map(|subgraphs| {
                    subgraphs
                        .iter()
                        .map(|(name, cfg)| (name.clone(), Self::compile_config(cfg)))
                        .collect()
                })
                .unwrap_or_default(),
            default_config: Self::compile_config(&config.all),
        }
    }

    fn compile_config(config: &SubgraphErrorMaskingConfig) -> ErrorMaskingCompiledConfig {
        let extensions_plan = config.extensions.as_ref().map(|cfg| match cfg {
            ExtensionsMaskingConfig::AllowList(ref list) => RedactExtensionsPlan::Allow(
                list.iter()
                    .map(|s| RedactExtensionsPath::from_str(s))
                    .collect(),
            ),
            ExtensionsMaskingConfig::DenyList(ref list) => RedactExtensionsPlan::Deny(
                list.iter()
                    .map(|s| RedactExtensionsPath::from_str(s))
                    .collect(),
            ),
        });

        ErrorMaskingCompiledConfig {
            redact_error_message: config.error_message,
            extensions_plan,
        }
    }
}

struct ErrorMaskingCompiledConfig {
    redact_error_message: bool,
    extensions_plan: Option<RedactExtensionsPlan>,
}

enum RedactExtensionsPlan {
    Allow(Vec<RedactExtensionsPath>),
    Deny(Vec<RedactExtensionsPath>),
}

impl RedactExtensionsPlan {
    pub fn apply(&self, extensions: &mut GraphQLErrorExtensions) {
        match self {
            RedactExtensionsPlan::Allow(_list) => {}
            RedactExtensionsPlan::Deny(list) => {
                for removal_path in list {
                    Self::remove_field(extensions, &removal_path.0);
                }
            }
        }
    }

    fn remove_field(extensions: &mut GraphQLErrorExtensions, rest: &Vec<String>) {
        let Some(first) = rest.first() else {
            return;
        };

        // Known top-level struct fields only match as a whole (no nesting into a String).
        if rest.is_empty() {
            match first.as_str() {
                "code" => {
                    extensions.code = None;
                    return;
                }
                "service" => {
                    extensions.service_name = None;
                    return;
                }
                "affected_path" => {
                    extensions.affected_path = None;
                    return;
                }
                _ => {}
            }
        }

        if rest.is_empty() {
            extensions.extensions.remove(first);
        } else if let Some(value) = extensions.extensions.get_mut(first) {
            // "foo.bar.baz" -> walk into extensions["foo"] and remove "baz" from its parent
            Self::remove_nested(value, rest);
        }
    }

    fn remove_nested(value: &mut Value, segments: &Vec<String>) {
        if segments.is_empty() {
            return;
        }

        let mut current = value;
        for seg in &segments[..segments.len() - 1] {
            let next = match current.as_object_mut() {
                Some(obj) => obj.get_mut(seg),
                None => None,
            };
            match next {
                Some(v) => current = v,
                None => return, // path doesn't exist — nothing to remove
            }
        }

        if let Some(obj) = current.as_object_mut() {
            obj.remove(&segments[segments.len() - 1]);
        }
    }
}

struct RedactExtensionsPath(pub Vec<String>);

impl RedactExtensionsPath {
    fn from_str(s: &str) -> Self {
        Self(s.trim().split('.').map(|s| s.to_string()).collect())
    }
}
