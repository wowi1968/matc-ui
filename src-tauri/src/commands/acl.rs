use std::sync::Arc;

use matc::{
    clusters::defs::{CLUSTER_ACCESS_CONTROL_ATTR_ID_ACL, CLUSTER_ID_ACCESS_CONTROL},
    tlv::{TlvBuffer, TlvItemValue},
};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclTargetDto {
    pub cluster: Option<u32>,
    pub endpoint: Option<u16>,
    pub device_type: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntryDto {
    pub privilege: Option<u8>,
    pub auth_mode: Option<u8>,
    /// Subject node IDs as decimal strings to avoid JS u64 precision loss.
    pub subjects: Vec<String>,
    pub targets: Vec<AclTargetDto>,
    /// Fabric index reported by the device; omitted when writing (device assigns it).
    pub fabric_index: Option<u8>,
}

#[tauri::command]
pub async fn read_acl(
    state: State<'_, Arc<AppState>>,
    node_id: u64,
) -> Result<Vec<AclEntryDto>, String> {
    let state = state.inner().clone();
    AppState::with_connection_retry(&state, node_id, |conn| async move {
        let tlv = conn
            .read_request2(
                0,
                CLUSTER_ID_ACCESS_CONTROL,
                CLUSTER_ACCESS_CONTROL_ATTR_ID_ACL,
            )
            .await?;
        let mut entries = Vec::new();
        // rust-matc normalises both TLV Array (0x16) and TLV List (0x17) to
        // TlvItemValue::List, so this matches correctly against CHIP's Array encoding.
        if let TlvItemValue::List(items) = &tlv {
            for item in items {
                let privilege = item.get_int(&[1]).map(|v| v as u8);
                let auth_mode = item.get_int(&[2]).map(|v| v as u8);
                let subjects: Vec<String> = match item.get(&[3]) {
                    Some(TlvItemValue::List(l)) => l
                        .iter()
                        .filter_map(|e| {
                            if let TlvItemValue::Int(v) = &e.value {
                                Some(v.to_string())
                            } else {
                                None
                            }
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                let targets: Vec<AclTargetDto> = match item.get(&[4]) {
                    Some(TlvItemValue::List(l)) => l
                        .iter()
                        .map(|t| AclTargetDto {
                            cluster: t.get_int(&[0]).map(|v| v as u32),
                            endpoint: t.get_int(&[1]).map(|v| v as u16),
                            device_type: t.get_int(&[2]).map(|v| v as u32),
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                // FabricIndex is at context tag 254 (0xFE) per Matter spec.
                // rust-matc's generated acl_cluster.rs incorrectly reads tag 5;
                // we read the correct tag here.
                let fabric_index = item.get_int(&[254]).map(|v| v as u8);
                entries.push(AclEntryDto {
                    privilege,
                    auth_mode,
                    subjects,
                    targets,
                    fabric_index,
                });
            }
        }
        Ok(entries)
    })
    .await
}

/// Write a uint64 value with an anonymous tag (no context-tag byte).
/// TLV Arrays require all elements to have anonymous tags; TlvBuffer only
/// provides write_uint8/16/32_notag, so we implement uint64 here.
fn write_anon_uint(buf: &mut TlvBuffer, value: u64) -> std::io::Result<()> {
    if value <= u8::MAX as u64 {
        buf.write_uint8_notag(value as u8)
    } else if value <= u16::MAX as u64 {
        buf.write_uint16_notag(value as u16)
    } else if value <= u32::MAX as u64 {
        buf.write_uint32_notag(value as u32)
    } else {
        // TYPE_UINT_8 = 7 (anonymous), followed by 8 LE bytes.
        let mut bytes = [0u8; 9];
        bytes[0] = 7;
        bytes[1..].copy_from_slice(&value.to_le_bytes());
        buf.write_raw(&bytes)
    }
}

/// Encode the ACL entry list as TLV bytes suitable for passing to
/// `conn.write_request(0, CLUSTER_ID_ACCESS_CONTROL, CLUSTER_ACCESS_CONTROL_ATTR_ID_ACL, &bytes)`.
///
/// The bytes produced start with context-tag 2 (the AttributeDataIB Data field) and
/// contain a TLV Array of AccessControlEntryStruct items, matching the wire format
/// that CHIP devices expect.
///
/// Wire format notes (confirmed from CHIP device captures):
///   - The outer ACL list is a TLV **Array** (0x36), NOT a List (0x37).
///   - Each entry's subjects list is also a TLV **Array** (0x36).
///   - Subjects with no entries: field is omitted (= null = any subject).
///   - Targets with no valid entries: field is omitted (= null = any target).
///   - All-null target structs {cluster=null, endpoint=null, device_type=null} are
///     invalid per the Matter spec and are filtered out.
///   - FabricIndex (tag 254) is omitted; the device fills it in.
fn encode_acl_tlv(entries: &[AclEntryDto]) -> Result<Vec<u8>, String> {
    let e = |err: std::io::Error| err.to_string();
    let mut buf = TlvBuffer::new();

    // AttributeDataIB Data field: context-tag 2, Array type (0x36 0x02).
    buf.write_array(2).map_err(e)?;

    for entry in entries {
        buf.write_anon_struct().map_err(e)?; // AccessControlEntryStruct

        if let Some(p) = entry.privilege {
            buf.write_uint8(1, p).map_err(e)?;
        }
        if let Some(a) = entry.auth_mode {
            buf.write_uint8(2, a).map_err(e)?;
        }

        // Subjects: TLV Array (0x36) at tag 3, containing one UInt64 per subject.
        // Omit entire field when list is empty (= null = any subject per spec).
        let subjects: Vec<u64> = entry
            .subjects
            .iter()
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        if !subjects.is_empty() {
            buf.write_array(3).map_err(e)?;
            for s in &subjects {
                // Array elements must have anonymous tags per Matter TLV spec.
                write_anon_uint(&mut buf, *s).map_err(e)?;
            }
            buf.write_struct_end().map_err(e)?; // end subjects array
        }

        // Targets: TLV Array (0x36) at tag 4.
        // Filter out all-null target structs (invalid per Matter spec).
        // Omit entire field when no valid targets remain (= null = any target per spec).
        let valid_targets: Vec<&AclTargetDto> = entry
            .targets
            .iter()
            .filter(|t| t.cluster.is_some() || t.endpoint.is_some() || t.device_type.is_some())
            .collect();
        if !valid_targets.is_empty() {
            buf.write_array(4).map_err(e)?;
            for t in &valid_targets {
                buf.write_anon_struct().map_err(e)?;
                if let Some(c) = t.cluster {
                    buf.write_uint32(0, c).map_err(e)?;
                }
                if let Some(ep) = t.endpoint {
                    buf.write_uint16(1, ep).map_err(e)?;
                }
                if let Some(d) = t.device_type {
                    buf.write_uint32(2, d).map_err(e)?;
                }
                buf.write_struct_end().map_err(e)?; // end target struct
            }
            buf.write_struct_end().map_err(e)?; // end targets array
        }

        // FabricIndex (tag 254) is intentionally omitted; the device assigns it.

        buf.write_struct_end().map_err(e)?; // end AccessControlEntryStruct
    }

    buf.write_struct_end().map_err(e)?; // end outer Array (tag 2)
    Ok(buf.data)
}

#[tauri::command]
pub async fn write_acl(
    state: State<'_, Arc<AppState>>,
    node_id: u64,
    entries: Vec<AclEntryDto>,
) -> Result<(), String> {
    let bytes = encode_acl_tlv(&entries)?;
    log::info!("write_acl: node={} entries={}", node_id, entries.len());
    let state = state.inner().clone();
    AppState::with_connection_retry(&state, node_id, |conn| {
        let bytes = bytes.clone();
        async move {
            conn.write_request(
                0,
                CLUSTER_ID_ACCESS_CONTROL,
                CLUSTER_ACCESS_CONTROL_ATTR_ID_ACL,
                &bytes,
            )
            .await?;
            Ok(())
        }
    })
    .await
    .map_err(|e| {
        log::error!("write_acl failed: node={} err={}", node_id, e);
        e
    })
}
