//! CEL values for `x-kubernetes-list-type: set` and `map` arrays.
//!
//! Ported from `staging/src/k8s.io/apiserver/pkg/cel/common/valuesunstructured.go`
//! (release-1.35):
//! - `UnstructuredToVal` (:38-210) picks the list value by
//!   `x-kubernetes-list-type`; an unknown type is
//!   "invalid x-kubernetes-list-type, expected 'map', 'set' or 'atomic' but got %s".
//! - `unstructuredSetList` (:~420-480): `Equal` ignores element order, `Add`
//!   (`X + Y`) is a union that keeps the positions of `X` and appends the
//!   elements of `Y` that are not in it.
//! - `unstructuredMapList` (:241-336): `Equal` ignores element order, matching
//!   elements by the `x-kubernetes-list-map-keys` properties; `Add` keeps the
//!   position of every key of `X`, overwrites its value with the one in `Y`,
//!   and appends `Y` elements with unseen keys.
//! - `unstructuredList` (:420-570) for `Contains`, `Get`, `Iterator`, `Size`.
//!
//! A plain `cel::Value::List` has fixed list semantics, so these are native
//! `cel::common::value::Val` values; [`json_to_val_with_schema`] builds a whole
//! `self` tree of `Val`s (bind it with `Context::add_variable_as_val`).
//!
//! Known differences from upstream:
//! - Wiring into `CELContext` / the CRD validation path is a separate task;
//!   until then `json_to_cel_value_with_schema` (plain lists) is what CRD rules
//!   see.
//! - Map-list key properties are read by their raw names. Upstream reads them
//!   through `cel.Escape`d names, which finds nothing for a property that needs
//!   escaping (all such elements then share one key).
//! - `cel-rust`'s plain list compares itself to a set or map list pairwise (as
//!   cel-go's `unstructuredList` does with an ordered `Lister`), so
//!   `['a','b'] == self.set` is order-sensitive; `self.set == ['b','a']` is not.

use crate::cel::{json_to_cel_value, json_to_cel_value_with_schema};
use crate::resources::crd::{JSONSchemaProps, JSONSchemaPropsOrArray, JSONSchemaPropsOrBool};
use anyhow::{anyhow, Result};
use cel::common::traits;
use cel::common::traits::{Adder, Container, Indexer, Iterable, Sizer, Zeroer};
use cel::common::types::{
    CelBool, CelDouble, CelInt, CelList, CelMap, CelMapKey, CelString, CelUInt, Kind, Type,
    LIST_TYPE,
};
use cel::common::value::{CowVal, Val};
use cel::objects::Key;
use cel::{ExecutionError, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// `x-kubernetes-list-type` of a list that needs its own semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListKind {
    /// `set`: scalar elements, compared as a set.
    Set,
    /// `map`: object elements keyed by these properties
    /// (`x-kubernetes-list-map-keys`).
    Map(Vec<String>),
}

/// A scalar a map key or set element reduces to; the Go side uses the
/// element's `interface{}` value as a map key, so `int64(1)` and `float64(1)`
/// are different keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Atom {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(u64),
    Str(String),
}

fn atom(v: &dyn Val) -> Option<Atom> {
    match v.get_type().kind() {
        Kind::NullType => Some(Atom::Null),
        Kind::Boolean => v.downcast_ref::<CelBool>().map(|b| Atom::Bool(*b.inner())),
        Kind::Int => v.downcast_ref::<CelInt>().map(|i| Atom::Int(*i.inner())),
        Kind::UInt => v.downcast_ref::<CelUInt>().map(|i| Atom::UInt(*i.inner())),
        Kind::Double => v
            .downcast_ref::<CelDouble>()
            .map(|d| Atom::Float(d.inner().to_bits())),
        Kind::String => v
            .downcast_ref::<CelString>()
            .map(|s| Atom::Str(s.inner().to_string())),
        _ => None,
    }
}

/// `toMapKey` (valuesunstructured.go:261-286): the composite key of a map-list
/// element. An absent key property is `nil` (`eObj[prop]`); an element that is
/// not an object has no key (upstream returns an error value that never
/// matches).
fn map_key(element: &dyn Val, props: &[String]) -> Option<Vec<Atom>> {
    let idx = element.as_indexer()?;
    if element.get_type().kind() != Kind::Map {
        return None;
    }
    props
        .iter()
        .map(|p| {
            let key = CelString::from(p.as_str());
            match idx.get(&key) {
                Ok(v) => atom(v.as_ref()),
                Err(_) => Some(Atom::Null),
            }
        })
        .collect()
}

/// An `x-kubernetes-list-type` set or map list.
#[derive(Debug, Clone)]
pub struct SchemaList<'v> {
    elements: Vec<Box<dyn Val + 'v>>,
    kind: ListKind,
}

impl<'v> SchemaList<'v> {
    pub fn new(elements: Vec<Box<dyn Val + 'v>>, kind: ListKind) -> Self {
        Self { elements, kind }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    fn key_of(&self, v: &dyn Val) -> Option<Vec<Atom>> {
        match &self.kind {
            ListKind::Set => atom(v).map(|a| vec![a]),
            ListKind::Map(props) => map_key(v, props),
        }
    }

    fn same_kind(&self, elements: Vec<Box<dyn Val + 'v>>) -> Self {
        Self {
            elements,
            kind: self.kind.clone(),
        }
    }
}

impl<'x> Val for SchemaList<'x> {
    fn get_type(&self) -> &Type {
        &LIST_TYPE
    }

    fn cel_type() -> &'static Type {
        &LIST_TYPE
    }

    fn as_adder<'b, 'v>(&'b self) -> Option<&'b (dyn Adder + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_container(&self) -> Option<&dyn Container> {
        Some(self)
    }

    fn as_indexer<'b, 'v>(&'b self) -> Option<&'b (dyn Indexer + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_iterable<'b, 'v>(&'b self) -> Option<&'b (dyn Iterable + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn as_sizer(&self) -> Option<&dyn Sizer> {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn Zeroer> {
        Some(self)
    }

    /// `unstructuredSetList.Equal` / `unstructuredMapList.Equal`: same size,
    /// then every element of `other` is found in `self` (a map-list element by
    /// key, and then equal as a value). `other` is any list.
    fn equals(&self, other: &dyn Val) -> bool {
        let (Some(it), Some(sz)) = (other.as_iterable(), other.as_sizer()) else {
            return false;
        };
        if other.get_type().kind() != Kind::List || *sz.size().inner() != self.elements.len() as i64
        {
            return false;
        }
        let mut it = it.iter();
        match &self.kind {
            ListKind::Set => {
                let set: Vec<Option<Atom>> =
                    self.elements.iter().map(|e| atom(e.as_ref())).collect();
                while let Some(next) = it.next() {
                    let Some(a) = atom(next) else { return false };
                    if !set.iter().any(|s| s.as_ref() == Some(&a)) {
                        return false;
                    }
                }
                true
            }
            ListKind::Map(props) => {
                // `getMap`: the last element with a key wins.
                let mut by_key: HashMap<Vec<Atom>, &dyn Val> = HashMap::new();
                for e in &self.elements {
                    if let Some(k) = map_key(e.as_ref(), props) {
                        by_key.insert(k, e.as_ref());
                    }
                }
                while let Some(v) = it.next() {
                    let Some(k) = map_key(v, props) else {
                        return false;
                    };
                    match by_key.get(&k) {
                        Some(mine) if mine.equals(v) => {}
                        _ => return false,
                    }
                }
                true
            }
        }
    }

    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
    where
        Self: 'v,
    {
        Box::new(self.clone())
    }
}

impl<'x> Adder for SchemaList<'x> {
    /// `unstructuredSetList.Add` (union) / `unstructuredMapList.Add` (merge).
    fn add<'b, 'v>(&'b self, rhs: &(dyn Val + 'v)) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        let Some(other) = rhs.as_iterable() else {
            return Err(ExecutionError::no_such_overload(
                "_+_",
                vec![
                    self.get_type().name().to_string(),
                    rhs.get_type().name().to_string(),
                ],
            ));
        };
        let mut elements: Vec<Box<dyn Val + 'v>> =
            self.elements.iter().map(|e| e.clone_as_boxed()).collect();
        let mut it = other.iter();
        match &self.kind {
            ListKind::Set => {
                let mut set: Vec<Atom> = self
                    .elements
                    .iter()
                    .filter_map(|e| atom(e.as_ref()))
                    .collect();
                while let Some(next) = it.next() {
                    let a = atom(next);
                    if a.as_ref().is_some_and(|a| set.contains(a)) {
                        continue;
                    }
                    if let Some(a) = a {
                        set.push(a);
                    }
                    elements.push(next.clone_as_boxed());
                }
            }
            ListKind::Map(_) => {
                // `keyToIdx[k] = i`: the last duplicate in X wins; keys appended
                // from Y are not added, as upstream.
                let mut key_to_idx: HashMap<Vec<Atom>, usize> = HashMap::new();
                for (i, e) in self.elements.iter().enumerate() {
                    if let Some(k) = self.key_of(e.as_ref()) {
                        key_to_idx.insert(k, i);
                    }
                }
                while let Some(v) = it.next() {
                    match self.key_of(v).and_then(|k| key_to_idx.get(&k).copied()) {
                        Some(pos) => elements[pos] = v.clone_as_boxed(),
                        None => elements.push(v.clone_as_boxed()),
                    }
                }
            }
        }
        Ok(CowVal::owned(self.same_kind(elements)))
    }
}

impl<'x> Container for SchemaList<'x> {
    /// `unstructuredList.Contains`.
    fn contains(&self, value: &dyn Val) -> Result<bool, ExecutionError> {
        Ok(self.elements.iter().any(|e| e.equals(value)))
    }
}

impl<'x> Indexer for SchemaList<'x> {
    /// `unstructuredList.Get`.
    fn get<'b, 'v>(&'b self, idx: &dyn Val) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        let i = match idx.get_type().kind() {
            Kind::Int => idx.downcast_ref::<CelInt>().map(|i| *i.inner()),
            Kind::UInt => idx
                .downcast_ref::<CelUInt>()
                .and_then(|i| i64::try_from(*i.inner()).ok()),
            _ => {
                return Err(ExecutionError::UnexpectedType {
                    got: idx.get_type().name().to_string(),
                    want: "int".to_string(),
                })
            }
        }
        .ok_or_else(|| ExecutionError::UnexpectedType {
            got: idx.get_type().name().to_string(),
            want: "int".to_string(),
        })?;
        usize::try_from(i)
            .ok()
            .and_then(|i| self.elements.get(i))
            .map(|v| CowVal::Borrowed(v.as_ref()))
            .ok_or_else(|| ExecutionError::IndexOutOfBounds(i.into()))
    }

    fn steal<'v>(self: Box<Self>, idx: &dyn Val) -> Result<Box<dyn Val + 'v>, ExecutionError>
    where
        Self: 'v,
    {
        self.get(idx).map(CowVal::into_owned)
    }
}

struct Elements<'b, 'x> {
    items: &'b [Box<dyn Val + 'x>],
    pos: usize,
}

impl<'b, 'x: 'w, 'w> traits::Iterator<'b, 'w> for Elements<'b, 'x> {
    fn next(&mut self) -> Option<&'b (dyn Val + 'w)> {
        let v = self.items.get(self.pos)?;
        self.pos += 1;
        Some(v.as_ref())
    }
}

impl<'x> Iterable for SchemaList<'x> {
    fn iter<'b, 'v>(&'b self) -> Box<dyn traits::Iterator<'b, 'v> + 'b>
    where
        Self: 'v,
    {
        Box::new(Elements {
            items: &self.elements,
            pos: 0,
        })
    }
}

impl<'x> Sizer for SchemaList<'x> {
    fn size(&self) -> CelInt {
        (self.elements.len() as i64).into()
    }
}

impl<'x> Zeroer for SchemaList<'x> {
    fn is_zero_value(&self) -> bool {
        self.elements.is_empty()
    }
}

/// `UnstructuredToVal` as a native value tree: like
/// [`json_to_cel_value_with_schema`], but arrays with
/// `x-kubernetes-list-type` `set` / `map` become [`SchemaList`]s. Leaves are
/// converted by the schema-aware leaf rules of that function.
pub fn json_to_val_with_schema(
    value: &serde_json::Value,
    schema: &JSONSchemaProps,
) -> Result<Box<dyn Val>> {
    let to_val = |v: Value| -> Result<Box<dyn Val>> {
        Box::<dyn Val>::try_from(v).map_err(|e| anyhow!("{e}"))
    };
    if value.is_null() || schema.x_kubernetes_int_or_string == Some(true) {
        return to_val(json_to_cel_value_with_schema(value, schema)?);
    }
    match schema.type_.as_deref().unwrap_or("") {
        "object" => {
            let obj = value.as_object().ok_or_else(|| {
                anyhow!("invalid data, expected a map for the provided schema with type=object")
            })?;
            let addl = match schema.additional_properties.as_deref() {
                Some(JSONSchemaPropsOrBool::Schema(s)) => Some(s),
                _ => None,
            };
            let mut map: HashMap<CelMapKey, Box<dyn Val>> = HashMap::new();
            for (k, v) in obj {
                let child = schema.properties.as_ref().and_then(|p| p.get(k)).or(
                    if schema.properties.is_none() {
                        addl
                    } else {
                        None
                    },
                );
                let cv = match child {
                    Some(cs) => json_to_val_with_schema(v, cs)?,
                    None => to_val(json_to_cel_value(v)?)?,
                };
                map.insert(Key::String(Arc::new(k.clone())).into(), cv);
            }
            Ok(Box::new(CelMap::from(map)))
        }
        "array" => {
            let arr = value.as_array().ok_or_else(|| {
                anyhow!("invalid data, expected an array for the provided schema with type=array")
            })?;
            let items = match schema.items.as_deref() {
                Some(JSONSchemaPropsOrArray::Schema(s)) => s,
                _ => {
                    return Err(anyhow!(
                        "invalid array type, expected Items with a non-empty Schema"
                    ))
                }
            };
            let elements = arr
                .iter()
                .map(|v| json_to_val_with_schema(v, items))
                .collect::<Result<Vec<_>>>()?;
            match schema.x_kubernetes_list_type.as_deref().unwrap_or("") {
                "" | "atomic" => Ok(Box::new(CelList::from(elements))),
                "map" => Ok(Box::new(SchemaList::new(
                    elements,
                    ListKind::Map(schema.x_kubernetes_list_map_keys.clone().unwrap_or_default()),
                ))),
                "set" => Ok(Box::new(SchemaList::new(elements, ListKind::Set))),
                other => Err(anyhow!(
                    "invalid x-kubernetes-list-type, expected 'map', 'set' or 'atomic' but got {other}"
                )),
            }
        }
        _ => to_val(json_to_cel_value_with_schema(value, schema)?),
    }
}
