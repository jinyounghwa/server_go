// KMS (JSON 1.1): keys, aliases, encrypt/decrypt, data keys.
// ponytail: ciphertext is an MD5-keystream XOR — it keeps data opaque and tamper-evident enough for local tests,
// it is NOT real cryptography. Swap in AES-GCM if the emulator ever guards real secrets.
use crate::{b64, epoch, err, need, rand_bytes, unb64, ApiErr, ACCOUNT, REGION};
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::collections::BTreeMap;

struct Key {
    arn: String,
    desc: String,
    enabled: bool,
    created: f64,
    deletion: Option<f64>,
    secret: Vec<u8>,
}

#[derive(Default)]
pub struct Kms {
    keys: BTreeMap<String, Key>,
    aliases: BTreeMap<String, String>, // alias/name -> key id
}

const MAGIC: &[u8] = b"RCK1";

fn keystream_xor(secret: &[u8], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    data.chunks(16)
        .enumerate()
        .flat_map(|(i, c)| {
            let ks = Md5::new().chain_update(secret).chain_update(nonce).chain_update((i as u64).to_le_bytes()).finalize();
            c.iter().zip(ks).map(|(a, b)| a ^ b).collect::<Vec<_>>()
        })
        .collect()
}
fn ctx_hash(r: &Value) -> Vec<u8> {
    // serde_json maps are sorted, so equal contexts hash equally.
    Md5::digest(r["EncryptionContext"].to_string()).to_vec()
}
fn not_found(k: &str) -> ApiErr {
    err("NotFoundException", format!("Invalid keyId '{k}'"))
}

impl Kms {
    // KeyId may be an id, key ARN, alias name or alias ARN.
    fn resolve(&self, kid: &str) -> Result<String, ApiErr> {
        let alias = kid.find("alias/").map(|i| &kid[i..]);
        let id = match alias {
            Some(a) => self.aliases.get(a).cloned().ok_or_else(|| err("NotFoundException", format!("Alias {a} is not found.")))?,
            None => kid.rsplit("key/").next().unwrap_or(kid).to_string(),
        };
        if self.keys.contains_key(&id) { Ok(id) } else { Err(not_found(kid)) }
    }
    fn usable(&self, kid: &str) -> Result<(String, &Key), ApiErr> {
        let id = self.resolve(kid)?;
        let k = &self.keys[&id];
        if k.deletion.is_some() {
            return Err(err("KMSInvalidStateException", format!("{} is pending deletion.", k.arn)));
        }
        if !k.enabled {
            return Err(err("DisabledException", format!("{} is disabled.", k.arn)));
        }
        Ok((id, k))
    }
    fn meta(&self, id: &str) -> Value {
        let k = &self.keys[id];
        let state = if k.deletion.is_some() { "PendingDeletion" } else if k.enabled { "Enabled" } else { "Disabled" };
        let mut m = json!({"AWSAccountId": ACCOUNT, "KeyId": id, "Arn": k.arn, "CreationDate": k.created, "Enabled": k.enabled,
            "Description": k.desc, "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": state, "KeyManager": "CUSTOMER", "Origin": "AWS_KMS",
            "KeySpec": "SYMMETRIC_DEFAULT", "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT", "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"]});
        if let Some(t) = k.deletion {
            m["DeletionDate"] = t.into();
        }
        m
    }
    fn encrypt(&self, kid: &str, plain: &[u8], r: &Value) -> Result<(String, Vec<u8>), ApiErr> {
        let (id, k) = self.usable(kid)?;
        let nonce = rand_bytes(16);
        let mut blob = MAGIC.to_vec();
        blob.extend(id.as_bytes());
        blob.extend(&nonce);
        blob.extend(ctx_hash(r));
        blob.extend(keystream_xor(&k.secret, &nonce, plain));
        Ok((k.arn.clone(), blob))
    }

    pub fn handle(&mut self, op: &str, r: &Value) -> Result<Value, ApiErr> {
        let bytes = |k: &str| -> Result<Vec<u8>, ApiErr> { unb64(need(r, k)?).ok_or_else(|| err("ValidationException", format!("{k} is not valid base64"))) };
        Ok(match op {
            "CreateKey" => {
                let id = uuid::Uuid::new_v4().to_string();
                let arn = format!("arn:aws:kms:{}:{ACCOUNT}:key/{id}", *REGION);
                let desc = r["Description"].as_str().unwrap_or("").to_string();
                self.keys.insert(id.clone(), Key { arn, desc, enabled: true, created: epoch(), deletion: None, secret: rand_bytes(32) });
                json!({"KeyMetadata": self.meta(&id)})
            }
            "DescribeKey" => json!({"KeyMetadata": self.meta(&self.resolve(need(r, "KeyId")?)?)}),
            "ListKeys" => json!({"Keys": self.keys.iter().map(|(id, k)| json!({"KeyId": id, "KeyArn": k.arn})).collect::<Vec<_>>(), "Truncated": false}),
            "EnableKey" | "DisableKey" => {
                let id = self.resolve(need(r, "KeyId")?)?;
                self.keys.get_mut(&id).unwrap().enabled = op == "EnableKey";
                json!({})
            }
            "ScheduleKeyDeletion" => {
                let id = self.resolve(need(r, "KeyId")?)?;
                let when = epoch() + 86400.0 * r["PendingWindowInDays"].as_f64().unwrap_or(30.0);
                let k = self.keys.get_mut(&id).unwrap();
                (k.deletion, k.enabled) = (Some(when), false);
                json!({"KeyId": k.arn, "DeletionDate": when, "KeyState": "PendingDeletion", "PendingWindowInDays": r["PendingWindowInDays"].as_i64().unwrap_or(30)})
            }
            "CancelKeyDeletion" => {
                let id = self.resolve(need(r, "KeyId")?)?;
                let k = self.keys.get_mut(&id).unwrap();
                k.deletion = None; // stays disabled, like the real service
                json!({"KeyId": k.arn})
            }
            "CreateAlias" => {
                let a = need(r, "AliasName")?;
                if !a.starts_with("alias/") || a.starts_with("alias/aws/") {
                    return Err(err("ValidationException", "Alias must start with 'alias/' and not 'alias/aws/'"));
                }
                if self.aliases.contains_key(a) {
                    return Err(err("AlreadyExistsException", format!("An alias with the name arn:aws:kms:{}:{ACCOUNT}:{a} already exists", *REGION)));
                }
                let id = self.resolve(need(r, "TargetKeyId")?)?;
                self.aliases.insert(a.into(), id);
                json!({})
            }
            "DeleteAlias" => {
                let a = need(r, "AliasName")?;
                self.aliases.remove(a).ok_or_else(|| err("NotFoundException", format!("Alias {a} is not found.")))?;
                json!({})
            }
            "ListAliases" => {
                let list: Vec<Value> = self.aliases.iter()
                    .map(|(a, id)| json!({"AliasName": a, "AliasArn": format!("arn:aws:kms:{}:{ACCOUNT}:{a}", *REGION), "TargetKeyId": id})).collect();
                json!({"Aliases": list, "Truncated": false})
            }
            "Encrypt" => {
                let (arn, blob) = self.encrypt(need(r, "KeyId")?, &bytes("Plaintext")?, r)?;
                json!({"CiphertextBlob": b64(&blob), "KeyId": arn, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
            }
            "Decrypt" => {
                let blob = bytes("CiphertextBlob")?;
                let bad = || err("InvalidCiphertextException", "The ciphertext is invalid or was encrypted under a different key or encryption context.");
                if blob.len() < 4 + 36 + 16 + 16 || &blob[..4] != MAGIC {
                    return Err(bad());
                }
                let id = std::str::from_utf8(&blob[4..40]).map_err(|_| bad())?.to_string();
                if let Some(kid) = r["KeyId"].as_str() {
                    if self.resolve(kid)? != id {
                        return Err(err("IncorrectKeyException", "The key ID in the request does not identify a CMK that can perform this operation."));
                    }
                }
                let (_, k) = self.usable(&id).map_err(|e| if e.code == "NotFoundException" { bad() } else { e })?;
                if blob[56..72] != ctx_hash(r)[..] {
                    return Err(bad());
                }
                let plain = keystream_xor(&k.secret, &blob[40..56], &blob[72..]);
                json!({"Plaintext": b64(&plain), "KeyId": k.arn, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
            }
            "GenerateDataKey" | "GenerateDataKeyWithoutPlaintext" => {
                let n = r["NumberOfBytes"].as_u64().map(|n| n as usize).unwrap_or(if r["KeySpec"] == "AES_128" { 16 } else { 32 });
                let dk = rand_bytes(n);
                let (arn, blob) = self.encrypt(need(r, "KeyId")?, &dk, r)?;
                let mut out = json!({"CiphertextBlob": b64(&blob), "KeyId": arn});
                if op == "GenerateDataKey" {
                    out["Plaintext"] = b64(&dk).into();
                }
                out
            }
            _ => return Err(err("InvalidAction", format!("{op} is not supported yet"))),
        })
    }

    pub fn admin(&self) -> Value {
        self.keys
            .iter()
            .map(|(id, k)| {
                let aliases: Vec<&String> = self.aliases.iter().filter(|(_, t)| *t == id).map(|(a, _)| a).collect();
                let state = if k.deletion.is_some() { "삭제 예정" } else if k.enabled { "사용" } else { "중지" };
                json!({"name": aliases.first().map_or(id.as_str(), |a| a.as_str()), "count": aliases.len(), "sub": k.arn,
                       "cols": ["상태", "설명", "별칭"], "rows": [[state, k.desc, aliases.iter().map(|a| a.as_str()).collect::<Vec<_>>().join(", ")]]})
            })
            .collect()
    }
}
