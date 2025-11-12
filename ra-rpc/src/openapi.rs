// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Utilities to derive OpenAPI documents for pRPC services from their compiled
//! protobuf descriptors. The resulting spec can be served directly or embedded
//! inside a Swagger UI helper.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::TryFrom,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use prost_types::{
    field_descriptor_proto::{Label as FieldLabel, Type as FieldType},
    DescriptorProto, EnumDescriptorProto, FieldDescriptorProto, FileDescriptorSet,
    ServiceDescriptorProto, SourceCodeInfo,
};
use prpc::Message as _;
use serde_json::{json, Map, Value};

/// High level metadata used for the `info` and `servers` sections of the
/// generated OpenAPI specification.
#[derive(Clone, Debug)]
pub struct DocumentInfo<'a> {
    pub title: Cow<'a, str>,
    pub version: Cow<'a, str>,
    pub description: Option<Cow<'a, str>>,
    pub servers: Vec<Cow<'a, str>>,
}

impl<'a> DocumentInfo<'a> {
    pub fn new(title: impl Into<Cow<'a, str>>, version: impl Into<Cow<'a, str>>) -> Self {
        Self {
            title: title.into(),
            version: version.into(),
            description: None,
            servers: Vec::new(),
        }
    }

    pub fn with_description(mut self, description: impl Into<Cow<'a, str>>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn add_server(mut self, server: impl Into<Cow<'a, str>>) -> Self {
        self.servers.push(server.into());
        self
    }
}

/// Configuration describing how a pRPC service should be exposed over HTTP.
#[derive(Clone, Debug)]
pub struct ServiceConfig<'a> {
    pub name: Cow<'a, str>,
    pub mount_path: Cow<'a, str>,
    pub method_prefix: Cow<'a, str>,
    pub tag: Option<Cow<'a, str>>,
    pub description: Option<Cow<'a, str>>,
}

impl<'a> ServiceConfig<'a> {
    pub fn new(name: impl Into<Cow<'a, str>>, mount_path: impl Into<Cow<'a, str>>) -> Self {
        Self {
            name: name.into(),
            mount_path: mount_path.into(),
            method_prefix: Cow::Borrowed(""),
            tag: None,
            description: None,
        }
    }

    pub fn with_method_prefix(mut self, prefix: impl Into<Cow<'a, str>>) -> Self {
        self.method_prefix = prefix.into();
        self
    }

    pub fn with_tag(mut self, tag: impl Into<Cow<'a, str>>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    pub fn with_description(mut self, description: impl Into<Cow<'a, str>>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Descriptor blob plus the set of services that should be surfaced from it.
#[derive(Clone, Debug)]
pub struct DescriptorSource<'a> {
    pub descriptor: &'a [u8],
    pub services: Vec<ServiceConfig<'a>>,
}

impl<'a> DescriptorSource<'a> {
    pub fn new(descriptor: &'a [u8], services: Vec<ServiceConfig<'a>>) -> Self {
        Self {
            descriptor,
            services,
        }
    }
}

/// Combined OpenAPI document + UI preferences.
#[derive(Clone)]
pub struct OpenApiDoc {
    spec: Arc<String>,
    ui: SwaggerUiConfig,
}

impl OpenApiDoc {
    pub fn new(spec_json: String, ui: SwaggerUiConfig) -> Self {
        Self {
            spec: Arc::new(spec_json),
            ui,
        }
    }

    pub fn spec_json(&self) -> &str {
        self.spec.as_str()
    }

    pub fn clone_spec_json(&self) -> String {
        (*self.spec).clone()
    }

    pub(crate) fn render(&self, spec_url: &str) -> RenderedDoc {
        let html = build_swagger_ui_html(spec_url, &self.ui);
        RenderedDoc {
            spec: self.spec.clone(),
            ui_html: html,
        }
    }
}

#[derive(Default)]
struct SourceCodeComments {
    entries: HashMap<Vec<i32>, String>,
}

impl SourceCodeComments {
    fn from_source_info(info: Option<SourceCodeInfo>) -> Self {
        let mut entries = HashMap::new();
        if let Some(info) = info {
            for location in info.location {
                if let Some(comment) = comment_from_location(&location) {
                    entries.insert(location.path, comment);
                }
            }
        }
        Self { entries }
    }

    fn comment_for(&self, path: &[i32]) -> Option<&str> {
        self.entries.get(path).map(String::as_str)
    }
}

fn comment_from_location(location: &prost_types::source_code_info::Location) -> Option<String> {
    if let Some(text) = location.leading_comments.as_deref() {
        return normalize_comment(text);
    }

    let mut detached = Vec::new();
    for comment in &location.leading_detached_comments {
        if let Some(normalized) = normalize_comment(comment) {
            detached.push(normalized);
        }
    }
    if !detached.is_empty() {
        return Some(detached.join("\n\n"));
    }

    if let Some(text) = location.trailing_comments.as_deref() {
        return normalize_comment(text);
    }

    None
}

fn normalize_comment(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.replace("\r\n", "\n"))
    }
}

fn extend_path(base: &[i32], field_number: i32, index: i32) -> Vec<i32> {
    let mut path = base.to_vec();
    path.push(field_number);
    path.push(index);
    path
}

/// Final resources consumed by the Rocket helper.
#[derive(Clone)]
pub(crate) struct RenderedDoc {
    pub spec: Arc<String>,
    pub ui_html: String,
}

/// Customisation knobs for the embedded Swagger UI page.
#[derive(Clone, Debug)]
pub struct SwaggerUiConfig {
    pub title: String,
    pub dark_mode: bool,
    pub swagger_ui_dist: String,
}

impl Default for SwaggerUiConfig {
    fn default() -> Self {
        Self {
            title: "pRPC Explorer".to_string(),
            dark_mode: true,
            swagger_ui_dist: "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5".to_string(),
        }
    }
}

/// Builds an OpenAPI specification for the provided descriptor sources.
pub fn generate_document(
    sources: &[DescriptorSource<'_>],
    info: &DocumentInfo<'_>,
) -> Result<String> {
    if sources.is_empty() {
        bail!("at least one descriptor source is required");
    }

    let mut registry = DescriptorRegistry::default();
    for (source_id, source) in sources.iter().enumerate() {
        let descriptor_set = FileDescriptorSet::decode(source.descriptor)
            .context("failed to decode descriptor set")?;
        registry.ingest(descriptor_set, source_id);
    }

    let mut schema_builder = SchemaBuilder::new(&registry);
    let mut paths = BTreeMap::<String, Value>::new();

    for (source_id, source) in sources.iter().enumerate() {
        for svc_cfg in &source.services {
            let service = registry
                .resolve_service(source_id, svc_cfg.name.as_ref())
                .with_context(|| format!("service {} not found in descriptor", svc_cfg.name))?;

            for method in &service.methods {
                if method.client_streaming || method.server_streaming {
                    bail!(
                        "streaming method {}.{} is not supported by the HTTP bridge",
                        service.full_name,
                        method.name
                    );
                }

                let base = normalize_mount_path(svc_cfg.mount_path.as_ref());
                let method_segment = format!("{}{}", svc_cfg.method_prefix, method.name);
                let path = join_path(&base, &method_segment);
                let post_operation =
                    build_operation(service, method, svc_cfg, &mut schema_builder)?;

                let mut op_map = Map::new();
                op_map.insert("post".to_string(), post_operation);
                paths.insert(path, Value::Object(op_map));
            }
        }
    }

    if paths.is_empty() {
        bail!("no RPC methods were registered for OpenAPI export");
    }

    let mut schemas = schema_builder.finish();
    schemas.insert("RpcError".to_string(), rpc_error_schema());

    let mut doc = Map::new();
    doc.insert("openapi".into(), Value::String("3.1.0".into()));

    let mut info_obj = Map::new();
    info_obj.insert("title".into(), Value::String(info.title.to_string()));
    info_obj.insert("version".into(), Value::String(info.version.to_string()));
    if let Some(description) = &info.description {
        info_obj.insert("description".into(), Value::String(description.to_string()));
    }
    doc.insert("info".into(), Value::Object(info_obj));

    if !info.servers.is_empty() {
        let mut servers = Vec::new();
        for server in &info.servers {
            let mut server_obj = Map::new();
            server_obj.insert("url".into(), Value::String(server.to_string()));
            servers.push(Value::Object(server_obj));
        }
        doc.insert("servers".into(), Value::Array(servers));
    }

    let mut components = Map::new();
    components.insert("schemas".into(), Value::Object(schemas));

    doc.insert("paths".into(), map_to_value(paths));
    doc.insert("components".into(), Value::Object(components));

    serde_json::to_string_pretty(&Value::Object(doc)).context("failed to serialize OpenAPI spec")
}

/// Convenience helper that returns a ready-to-serve [`OpenApiDoc`].
pub fn build_openapi_doc(
    sources: &[DescriptorSource<'_>],
    info: &DocumentInfo<'_>,
    ui: SwaggerUiConfig,
) -> Result<OpenApiDoc> {
    let spec = generate_document(sources, info)?;
    Ok(OpenApiDoc::new(spec, ui))
}

fn build_operation(
    service: &ServiceInfo,
    method: &MethodInfo,
    svc_cfg: &ServiceConfig<'_>,
    schema_builder: &mut SchemaBuilder<'_>,
) -> Result<Value> {
    let mut operation = Map::new();
    let tag = svc_cfg
        .tag
        .as_ref()
        .map(|t| t.to_string())
        .unwrap_or_else(|| service.full_name.clone());
    operation.insert("tags".into(), Value::Array(vec![Value::String(tag)]));
    operation.insert(
        "operationId".into(),
        Value::String(format!(
            "{}_{}",
            service.full_name.replace('.', "_"),
            method.name
        )),
    );
    let summary = method
        .description
        .as_deref()
        .and_then(|doc| doc.lines().find(|line| !line.trim().is_empty()))
        .map(|line| line.trim().to_string())
        .unwrap_or_else(|| method.name.clone());
    operation.insert("summary".into(), Value::String(summary));

    let mut description_parts = Vec::new();
    if let Some(doc) = method.description.as_deref() {
        let trimmed = doc.trim();
        if !trimmed.is_empty() {
            description_parts.push(trimmed.to_string());
        }
    }
    let mut base = format!(
        "pRPC method `{}` on service `{}`.",
        method.name, service.full_name
    );
    if let Some(extra) = svc_cfg
        .description
        .as_ref()
        .map(|c| c.as_ref())
        .or(service.description.as_deref())
    {
        base.push_str("\n\n");
        base.push_str(extra);
    }
    description_parts.push(base);
    let description = description_parts.join("\n\n");
    operation.insert("description".into(), Value::String(description));

    if !is_empty_type(&method.input_type) {
        let schema = schema_builder.schema_ref(&method.input_type)?;
        let request = json!({
            "required": true,
            "content": {
                "application/json": {
                    "schema": schema
                }
            }
        });
        operation.insert("requestBody".into(), request);
    }

    let success_schema = if is_empty_type(&method.output_type) {
        json!({ "type": "object" })
    } else {
        schema_builder.schema_ref(&method.output_type)?
    };

    let mut responses = Map::new();
    responses.insert(
        "200".into(),
        json!({
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": success_schema
                }
            }
        }),
    );
    responses.insert(
        "400".into(),
        json!({
            "description": "RPC error",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/RpcError" }
                }
            }
        }),
    );
    operation.insert("responses".into(), Value::Object(responses));

    Ok(Value::Object(operation))
}

fn rpc_error_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "error": { "type": "string" }
        },
        "required": ["error"]
    })
}

fn normalize_mount_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    let mut normalized = path.trim().to_string();
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

fn join_path(base: &str, segment: &str) -> String {
    if base == "/" {
        format!("/{}", segment.trim_start_matches('/'))
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            segment.trim_start_matches('/')
        )
    }
}

fn map_to_value(map: BTreeMap<String, Value>) -> Value {
    let mut json_map = Map::new();
    for (k, v) in map {
        json_map.insert(k, v);
    }
    Value::Object(json_map)
}

fn is_empty_type(type_name: &str) -> bool {
    matches!(
        type_name,
        ".google.protobuf.Empty" | "google.protobuf.Empty" | ""
    )
}

#[derive(Default)]
struct DescriptorRegistry {
    messages: HashMap<String, MessageInfo>,
    enums: HashMap<String, EnumInfo>,
    services: Vec<ServiceInfo>,
    service_by_full_name: HashMap<String, usize>,
    service_by_simple_name: HashMap<String, Vec<usize>>,
}

impl DescriptorRegistry {
    fn ingest(&mut self, set: FileDescriptorSet, source_id: usize) {
        for file in set.file {
            let package = file.package.unwrap_or_default();
            let comments = SourceCodeComments::from_source_info(file.source_code_info.clone());
            for (idx, message) in file.message_type.into_iter().enumerate() {
                let path = vec![4, idx as i32];
                self.register_message(&package, &[], message, &path, &comments);
            }
            for (idx, enumeration) in file.enum_type.into_iter().enumerate() {
                let path = vec![5, idx as i32];
                self.register_enum(&package, &[], enumeration, &path, &comments);
            }
            for (idx, service) in file.service.into_iter().enumerate() {
                let path = vec![6, idx as i32];
                self.register_service(&package, service, source_id, &path, &comments);
            }
        }
    }

    fn register_message(
        &mut self,
        package: &str,
        parents: &[String],
        descriptor: DescriptorProto,
        descriptor_path: &[i32],
        comments: &SourceCodeComments,
    ) {
        let name = descriptor.name.clone().unwrap_or_default();
        let mut path = parents.to_owned();
        path.push(name.clone());
        let full_name = canonical_name(package, &path);
        let is_map = descriptor
            .options
            .as_ref()
            .and_then(|opt| opt.map_entry)
            .unwrap_or(false);
        let description = comments.comment_for(descriptor_path).map(|s| s.to_string());
        let mut field_comments = HashMap::new();
        for (idx, field) in descriptor.field.iter().enumerate() {
            if let Some(field_name) = field.name.as_ref() {
                let field_path = extend_path(descriptor_path, 2, idx as i32);
                if let Some(comment) = comments.comment_for(&field_path) {
                    field_comments.insert(field_name.clone(), comment.to_string());
                }
            }
        }
        let info = MessageInfo {
            full_name: full_name.clone(),
            descriptor: descriptor.clone(),
            is_map_entry: is_map,
            description,
            field_comments,
        };
        self.messages.insert(full_name.clone(), info);

        for (idx, nested) in descriptor.nested_type.into_iter().enumerate() {
            let nested_path = extend_path(descriptor_path, 3, idx as i32);
            self.register_message(package, &path, nested, &nested_path, comments);
        }
        for (idx, enumeration) in descriptor.enum_type.into_iter().enumerate() {
            let enum_path = extend_path(descriptor_path, 4, idx as i32);
            self.register_enum(package, &path, enumeration, &enum_path, comments);
        }
    }

    fn register_enum(
        &mut self,
        package: &str,
        parents: &[String],
        descriptor: EnumDescriptorProto,
        descriptor_path: &[i32],
        comments: &SourceCodeComments,
    ) {
        let name = descriptor.name.clone().unwrap_or_default();
        let mut path = parents.to_owned();
        path.push(name);
        let full_name = canonical_name(package, &path);
        let description = comments.comment_for(descriptor_path).map(|s| s.to_string());
        let info = EnumInfo {
            descriptor,
            description,
        };
        self.enums.insert(full_name, info);
    }

    fn register_service(
        &mut self,
        package: &str,
        descriptor: ServiceDescriptorProto,
        source_id: usize,
        descriptor_path: &[i32],
        comments: &SourceCodeComments,
    ) {
        let simple_name = descriptor.name.clone().unwrap_or_default();
        let full_name = qualified_service_name(package, &simple_name);
        let methods = descriptor
            .method
            .into_iter()
            .enumerate()
            .map(|(idx, method)| {
                let description = comments
                    .comment_for(&extend_path(descriptor_path, 2, idx as i32))
                    .map(|s| s.to_string());
                MethodInfo {
                    name: method.name.unwrap_or_default(),
                    input_type: normalize_type_name(&method.input_type.unwrap_or_default()),
                    output_type: normalize_type_name(&method.output_type.unwrap_or_default()),
                    client_streaming: method.client_streaming.unwrap_or(false),
                    server_streaming: method.server_streaming.unwrap_or(false),
                    description,
                }
            })
            .collect();
        let description = comments.comment_for(descriptor_path).map(|s| s.to_string());
        let service = ServiceInfo {
            full_name: full_name.clone(),
            source_id,
            description,
            methods,
        };
        let idx = self.services.len();
        self.services.push(service);
        self.service_by_full_name.insert(full_name, idx);
        self.service_by_simple_name
            .entry(simple_name)
            .or_default()
            .push(idx);
    }

    fn resolve_service(&self, source_id: usize, query: &str) -> Result<&ServiceInfo> {
        let normalized = query.trim_start_matches('.').to_string();
        if let Some(&idx) = self.service_by_full_name.get(&normalized) {
            let service = &self.services[idx];
            if service.source_id == source_id {
                return Ok(service);
            }
        }

        let matches = self
            .service_by_simple_name
            .get(query)
            .into_iter()
            .flatten()
            .filter_map(|idx| {
                let service = &self.services[*idx];
                (service.source_id == source_id).then_some(service)
            })
            .collect::<Vec<_>>();

        match matches.as_slice() {
            [service] => Ok(service),
            [] => bail!("service {} not found in descriptor {}", query, source_id),
            _ => bail!(
                "service name {} is ambiguous, please use the fully qualified name",
                query
            ),
        }
    }

    fn message(&self, name: &str) -> Option<&MessageInfo> {
        self.messages.get(name)
    }

    fn enumeration(&self, name: &str) -> Option<&EnumInfo> {
        self.enums.get(name)
    }
}

#[derive(Clone)]
struct MessageInfo {
    full_name: String,
    descriptor: DescriptorProto,
    is_map_entry: bool,
    description: Option<String>,
    field_comments: HashMap<String, String>,
}

#[derive(Clone)]
struct EnumInfo {
    descriptor: EnumDescriptorProto,
    description: Option<String>,
}

#[derive(Clone)]
struct ServiceInfo {
    full_name: String,
    source_id: usize,
    description: Option<String>,
    methods: Vec<MethodInfo>,
}

#[derive(Clone)]
struct MethodInfo {
    name: String,
    input_type: String,
    output_type: String,
    client_streaming: bool,
    server_streaming: bool,
    description: Option<String>,
}

struct SchemaBuilder<'a> {
    registry: &'a DescriptorRegistry,
    generated: BTreeMap<String, Value>,
    visited: BTreeSet<String>,
}

impl<'a> SchemaBuilder<'a> {
    fn new(registry: &'a DescriptorRegistry) -> Self {
        Self {
            registry,
            generated: BTreeMap::new(),
            visited: BTreeSet::new(),
        }
    }

    fn schema_ref(&mut self, type_name: &str) -> Result<Value> {
        let normalized = normalize_type_name(type_name);
        if let Some(schema) = builtin_type_schema(&normalized) {
            return Ok(schema);
        }

        if let Some(message) = self.registry.message(&normalized) {
            if message.is_map_entry {
                bail!(
                    "map entry type {} cannot be referenced directly",
                    normalized
                );
            }
            self.ensure_message_generated(&normalized)?;
            return Ok(json!({
                "$ref": format!("#/components/schemas/{}", schema_key(&normalized))
            }));
        }

        if self.registry.enumeration(&normalized).is_some() {
            self.ensure_enum_generated(&normalized)?;
            return Ok(json!({
                "$ref": format!("#/components/schemas/{}", schema_key(&normalized))
            }));
        }

        bail!("unknown type referenced in proto: {}", normalized);
    }

    fn ensure_message_generated(&mut self, name: &str) -> Result<()> {
        if self.generated.contains_key(&schema_key(name)) {
            return Ok(());
        }
        if !self.visited.insert(name.to_string()) {
            bail!("cyclic reference detected while processing {}", name);
        }
        let descriptor = self
            .registry
            .message(name)
            .ok_or_else(|| anyhow!("message {} not found", name))?;

        let mut required = Vec::new();
        let mut props = BTreeMap::new();
        for field in &descriptor.descriptor.field {
            let field_name = field.name.clone().unwrap_or_default();
            let mut schema = self.field_schema(field)?;
            if let Some(doc) = descriptor.field_comments.get(&field_name) {
                apply_schema_description(&mut schema, doc);
            }
            if is_required_field(field) {
                required.push(field_name.clone());
            }
            props.insert(field_name, schema);
        }

        let mut obj = Map::new();
        obj.insert("type".into(), Value::String("object".into()));
        let mut properties = Map::new();
        for (k, v) in props {
            properties.insert(k, v);
        }
        obj.insert("properties".into(), Value::Object(properties));
        if let Some(doc) = &descriptor.description {
            obj.insert("description".into(), Value::String(doc.clone()));
        }
        if !required.is_empty() {
            obj.insert(
                "required".into(),
                Value::Array(required.into_iter().map(Value::String).collect()),
            );
        }

        self.generated.insert(schema_key(name), Value::Object(obj));
        self.visited.remove(name);
        Ok(())
    }

    fn ensure_enum_generated(&mut self, name: &str) -> Result<()> {
        if self.generated.contains_key(&schema_key(name)) {
            return Ok(());
        }
        let descriptor = self
            .registry
            .enumeration(name)
            .ok_or_else(|| anyhow!("enum {} not found", name))?;
        let mut variants = Vec::new();
        for value in &descriptor.descriptor.value {
            if let Some(name) = &value.name {
                variants.push(Value::String(name.clone()));
            }
        }
        let mut schema = Map::new();
        schema.insert("type".into(), Value::String("string".into()));
        schema.insert("enum".into(), Value::Array(variants));
        if let Some(doc) = &descriptor.description {
            schema.insert("description".into(), Value::String(doc.clone()));
        }
        self.generated
            .insert(schema_key(name), Value::Object(schema));
        Ok(())
    }

    fn field_schema(&mut self, field: &FieldDescriptorProto) -> Result<Value> {
        if matches!(field_type(field), FieldType::Message)
            && matches!(field_label(field), FieldLabel::Repeated)
        {
            if let Some(type_name) = &field.type_name {
                let normalized = normalize_type_name(type_name);
                if let Some(message) = self.registry.message(&normalized) {
                    if message.is_map_entry {
                        return self.map_field_schema(message);
                    }
                }
            }
        }

        let schema = match field_label(field) {
            FieldLabel::Repeated => {
                let inner = self.scalar_schema(field)?;
                json!({
                    "type": "array",
                    "items": inner
                })
            }
            _ => self.scalar_schema(field)?,
        };
        Ok(schema)
    }

    fn scalar_schema(&mut self, field: &FieldDescriptorProto) -> Result<Value> {
        Ok(match field_type(field) {
            FieldType::Double => json!({"type": "number", "format": "double"}),
            FieldType::Float => json!({"type": "number", "format": "float"}),
            FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => {
                json!({"type": "integer", "format": "int64"})
            }
            FieldType::Uint64 | FieldType::Fixed64 => {
                json!({"type": "integer", "format": "uint64"})
            }
            FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => {
                json!({"type": "integer", "format": "int32"})
            }
            FieldType::Uint32 | FieldType::Fixed32 => {
                json!({"type": "integer", "format": "uint32"})
            }
            FieldType::Bool => json!({"type": "boolean"}),
            FieldType::String => json!({"type": "string"}),
            FieldType::Bytes => json!({"type": "string", "format": "byte"}),
            FieldType::Enum => {
                let type_name = field
                    .type_name
                    .as_ref()
                    .ok_or_else(|| anyhow!("enum field missing type name"))?;
                self.schema_ref(type_name)?
            }
            FieldType::Message => {
                let type_name = field
                    .type_name
                    .as_ref()
                    .ok_or_else(|| anyhow!("message field missing type name"))?;
                self.schema_ref(type_name)?
            }
            FieldType::Group => {
                bail!("group fields are not supported in OpenAPI export")
            }
        })
    }

    fn map_field_schema(&mut self, entry: &MessageInfo) -> Result<Value> {
        let mut value_field = None;
        for field in &entry.descriptor.field {
            if field.number.unwrap_or_default() == 2 {
                value_field = Some(field.clone());
            }
        }
        let value_field = value_field
            .ok_or_else(|| anyhow!("map entry {} is missing value field", entry.full_name))?;
        let value_schema = self.scalar_schema(&value_field)?;
        Ok(json!({
            "type": "object",
            "additionalProperties": value_schema
        }))
    }

    fn finish(self) -> Map<String, Value> {
        let mut map = Map::new();
        for (k, v) in self.generated {
            map.insert(k, v);
        }
        map
    }
}

fn apply_schema_description(schema: &mut Value, doc: &str) {
    let trimmed = doc.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Value::Object(obj) = schema {
        obj.insert("description".into(), Value::String(trimmed.to_string()));
    }
}

fn builtin_type_schema(name: &str) -> Option<Value> {
    match name {
        ".google.protobuf.Empty" => Some(json!({"type": "object"})),
        ".google.protobuf.Timestamp" => Some(json!({"type": "string", "format": "date-time"})),
        ".google.protobuf.Duration" => {
            Some(json!({"type": "string", "description": "Duration string"}))
        }
        ".google.protobuf.BytesValue" => {
            Some(wrapper_schema(json!({"type": "string", "format": "byte"})))
        }
        ".google.protobuf.StringValue" => Some(wrapper_schema(json!({"type": "string"}))),
        ".google.protobuf.BoolValue" => Some(wrapper_schema(json!({"type": "boolean"}))),
        ".google.protobuf.Int32Value" | ".google.protobuf.Sint32Value" => Some(wrapper_schema(
            json!({"type": "integer", "format": "int32"}),
        )),
        ".google.protobuf.UInt32Value" => Some(wrapper_schema(
            json!({"type": "integer", "format": "uint32"}),
        )),
        ".google.protobuf.Int64Value" | ".google.protobuf.Sint64Value" => Some(wrapper_schema(
            json!({"type": "integer", "format": "int64"}),
        )),
        ".google.protobuf.UInt64Value" => Some(wrapper_schema(
            json!({"type": "integer", "format": "uint64"}),
        )),
        ".google.protobuf.DoubleValue" => Some(wrapper_schema(
            json!({"type": "number", "format": "double"}),
        )),
        ".google.protobuf.FloatValue" => {
            Some(wrapper_schema(json!({"type": "number", "format": "float"})))
        }
        ".google.protobuf.Any" => Some(json!({"type": "object"})),
        _ if name.starts_with(".google.protobuf.") => Some(json!({"type": "object"})),
        _ => None,
    }
}

fn wrapper_schema(inner: Value) -> Value {
    json!({
        "type": "object",
        "properties": { "value": inner },
        "required": ["value"]
    })
}

fn schema_key(full_name: &str) -> String {
    full_name.trim_start_matches('.').to_string()
}

fn canonical_name(package: &str, path: &[String]) -> String {
    let mut name = String::new();
    name.push('.');
    if !package.is_empty() {
        name.push_str(package);
        if !path.is_empty() {
            name.push('.');
        }
    }
    name.push_str(&path.join("."));
    name
}

fn qualified_service_name(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}

fn normalize_type_name(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    if name.starts_with('.') {
        name.to_string()
    } else {
        format!(".{name}")
    }
}

fn is_required_field(field: &FieldDescriptorProto) -> bool {
    matches!(field_label(field), FieldLabel::Required)
}

fn field_label(field: &FieldDescriptorProto) -> FieldLabel {
    FieldLabel::try_from(field.label.unwrap_or_default()).unwrap_or(FieldLabel::Optional)
}

fn field_type(field: &FieldDescriptorProto) -> FieldType {
    FieldType::try_from(field.r#type.unwrap_or_default()).unwrap_or(FieldType::Message)
}

fn build_swagger_ui_html(spec_url: &str, cfg: &SwaggerUiConfig) -> String {
    let spec = spec_url.replace('\'', "\\'");
    let css = format!(
        "{}/swagger-ui.css",
        cfg.swagger_ui_dist.trim_end_matches('/')
    );
    let bundle = format!(
        "{}/swagger-ui-bundle.js",
        cfg.swagger_ui_dist.trim_end_matches('/')
    );
    let preset = format!(
        "{}/swagger-ui-standalone-preset.js",
        cfg.swagger_ui_dist.trim_end_matches('/')
    );
    let background = if cfg.dark_mode { "#0b0d10" } else { "#fafafa" };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <link rel="stylesheet" href="{css}" />
  <style>
    body {{
      margin: 0;
      background-color: {background};
    }}
    .swagger-ui .topbar {{
      display: none;
    }}
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="{bundle}"></script>
  <script src="{preset}"></script>
  <script>
    window.onload = () => {{
      window.ui = SwaggerUIBundle({{
        url: '{spec}',
        dom_id: '#swagger-ui',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout",
        requestInterceptor: (req) => {{
          const method = (req.method || '').toUpperCase();
          if (method === 'POST') {{
            req.headers = req.headers || {{}};
            if (!req.headers['Content-Type'] && !req.headers['content-type']) {{
              req.headers['Content-Type'] = 'application/json';
            }}
          }}
          return req;
        }}
      }});
    }};
  </script>
</body>
</html>
"#,
        title = cfg.title,
        css = css,
        bundle = bundle,
        preset = preset,
        spec = spec,
        background = background
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::{FileDescriptorProto, MethodDescriptorProto};
    fn test_descriptor() -> Vec<u8> {
        let request = DescriptorProto {
            name: Some("PingRequest".into()),
            field: vec![FieldDescriptorProto {
                name: Some("message".into()),
                number: Some(1),
                label: Some(FieldLabel::Optional as i32),
                r#type: Some(FieldType::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };

        let response = DescriptorProto {
            name: Some("PingResponse".into()),
            field: vec![FieldDescriptorProto {
                name: Some("echo".into()),
                number: Some(1),
                label: Some(FieldLabel::Optional as i32),
                r#type: Some(FieldType::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        };

        let service = ServiceDescriptorProto {
            name: Some("TestService".into()),
            method: vec![MethodDescriptorProto {
                name: Some("Ping".into()),
                input_type: Some(".test.PingRequest".into()),
                output_type: Some(".test.PingResponse".into()),
                ..Default::default()
            }],
            ..Default::default()
        };

        let file = FileDescriptorProto {
            name: Some("test.proto".into()),
            package: Some("test".into()),
            message_type: vec![request, response],
            service: vec![service],
            ..Default::default()
        };

        let set = FileDescriptorSet { file: vec![file] };
        let mut buf = Vec::new();
        set.encode(&mut buf).unwrap();
        buf
    }

    #[test]
    fn generates_document() {
        let descriptor = test_descriptor();
        let sources = vec![DescriptorSource::new(
            &descriptor,
            vec![ServiceConfig::new("TestService", "/prpc")],
        )];
        let info = DocumentInfo::new("Test API", "1.0.0")
            .with_description("test-only spec")
            .add_server("http://localhost:8000/prpc");
        let json = generate_document(&sources, &info).expect("spec");
        let doc: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(doc["info"]["title"], "Test API");
        assert!(
            doc["paths"]["/prpc/Ping"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]
                .is_object()
        );
    }
}
