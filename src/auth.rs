use crate::error::{ErrorResponse, MsalError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::{header, Client};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{from_str as json_from_str, Value};
use std::fmt;
use std::marker::PhantomData;
use urlencoding::encode as url_encode;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "broker")]
use compact_jwt::compact::JweCompact;
#[cfg(feature = "broker")]
use compact_jwt::crypto::JwsTpmSigner;
#[cfg(feature = "broker")]
use compact_jwt::crypto::MsOapxbcSessionKey;
#[cfg(feature = "broker")]
use compact_jwt::jwe::Jwe;
#[cfg(feature = "broker")]
use compact_jwt::jws::JwsBuilder;
#[cfg(feature = "broker")]
use compact_jwt::traits::JwsMutSigner;
#[cfg(feature = "broker")]
use compact_jwt::traits::JwsSignable;
#[cfg(feature = "broker")]
use compact_jwt::Jws;
#[cfg(feature = "broker")]
use kanidm_hsm_crypto::{
    BoxedDynTpm, IdentityKey, KeyAlgorithm, LoadableIdentityKey, MachineKey, SealedData, Tpm,
};
#[cfg(feature = "broker")]
use kanidm_hsm_crypto::{LoadableMsOapxbcRsaKey, MsOapxbcRsaKey};
#[cfg(feature = "broker")]
use openssl::pkey::Public;
#[cfg(feature = "broker")]
use openssl::rsa::Rsa;
#[cfg(feature = "broker")]
use openssl::x509::X509;
#[cfg(feature = "broker")]
use os_release::OsRelease;
#[cfg(feature = "broker")]
use reqwest::Url;
#[cfg(feature = "broker")]
use serde_json::{from_slice as json_from_slice, to_vec as json_to_vec};
#[cfg(feature = "broker")]
use std::convert::TryInto;
#[cfg(feature = "broker")]
use std::str::FromStr;
#[cfg(feature = "broker")]
use tracing::debug;

#[cfg(feature = "broker")]
use crate::discovery::{
    discover_enrollment_services, DISCOVERY_URL, DRS_CLIENT_NAME_HEADER_FIELD,
    DRS_CLIENT_VERSION_HEADER_FIELD,
};
#[cfg(feature = "broker")]
use base64::engine::general_purpose::STANDARD;
#[cfg(feature = "broker")]
use serde_json::{json, to_string_pretty};

#[cfg(feature = "broker")]
#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Certificate {
    #[serde(rename = "RawBody")]
    raw_body: String,
}

#[cfg(feature = "broker")]
#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
struct DRSResponse {
    #[serde(rename = "Certificate")]
    certificate: Certificate,
}

#[derive(Serialize, Clone, Default)]
struct JoinPayload {}

#[cfg(feature = "broker")]
const BROKER_CLIENT_IDENT: &str = "38aa3b87-a06d-4817-b275-7a316988d93b";
#[cfg(feature = "broker")]
pub const BROKER_APP_ID: &str = "29d9ed98-a469-4536-ade2-f981bc1d605e";
#[cfg(feature = "broker")]
const DRS_APP_ID: &str = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9";

/* RFC8628: 3.2. Device Authorization Response */
#[derive(Default, Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    // MS doesn't implement verification_uri_complete yet
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    pub interval: Option<u32>,
    pub message: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct IdToken {
    pub name: String,
    pub oid: String,
    pub preferred_username: Option<String>,
    pub puid: Option<String>,
    pub tenant_region_scope: Option<String>,
    pub tid: String,
}

fn decode_string_or_struct<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Deserialize<'de> + FromStr<Err = MsalError>,
    D: Deserializer<'de>,
{
    struct StringOrStruct<T>(PhantomData<fn() -> T>);

    impl<'de, T> Visitor<'de> for StringOrStruct<T>
    where
        T: Deserialize<'de> + FromStr<Err = MsalError>,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or map")
        }

        fn visit_str<E>(self, value: &str) -> Result<T, E>
        where
            E: de::Error,
        {
            FromStr::from_str(value)
                .map_err(|e| serde::de::Error::custom(format!("Failed to parse string: {:?}", e)))
        }

        fn visit_map<M>(self, map: M) -> Result<T, M::Error>
        where
            M: MapAccess<'de>,
        {
            Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_any(StringOrStruct(PhantomData))
}

impl FromStr for IdToken {
    type Err = MsalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut siter = s.splitn(3, '.');
        if siter.next().is_none() {
            return Err(MsalError::InvalidParse(
                "Failed parsing id_token header".to_string(),
            ));
        }
        let payload_str = match siter.next() {
            Some(payload_str) => URL_SAFE_NO_PAD
                .decode(payload_str)
                .map_err(|e| MsalError::InvalidParse(format!("Failed parsing id_token: {}", e)))
                .and_then(|bytes| {
                    String::from_utf8(bytes).map_err(|e| {
                        MsalError::InvalidParse(format!("Failed parsing id_token: {}", e))
                    })
                })?,
            None => {
                return Err(MsalError::InvalidParse(
                    "Failed parsing id_token payload".to_string(),
                ));
            }
        };
        let payload: IdToken = json_from_str(&payload_str).map_err(|e| {
            MsalError::InvalidParse(format!("Failed parsing id_token from json: {}", e))
        })?;
        Ok(payload)
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct ClientInfo {
    pub uid: Option<Uuid>,
    pub utid: Option<Uuid>,
}

impl FromStr for ClientInfo {
    type Err = MsalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let client_info: Value = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| MsalError::InvalidParse(format!("Failed parsing client_info: {}", e)))
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|e| {
                    MsalError::InvalidParse(format!("Failed parsing client_info: {}", e))
                })
            })
            .and_then(|client_info_str| {
                json_from_str(&client_info_str).map_err(|e| {
                    MsalError::InvalidParse(format!("Failed parsing client_info: {}", e))
                })
            })?;

        let uid_str = client_info["uid"].to_string();
        let uid = Uuid::parse_str(uid_str.trim_matches('"'))
            .map_err(|e| MsalError::InvalidParse(format!("Failed parsing client_info: {}", e)))?;

        let utid_str = client_info["utid"].to_string();
        let utid = Uuid::parse_str(utid_str.trim_matches('"'))
            .map_err(|e| MsalError::InvalidParse(format!("Failed parsing client_info: {}", e)))?;

        Ok(ClientInfo {
            uid: Some(uid),
            utid: Some(utid),
        })
    }
}

fn decode_number_from_string<'de, D>(d: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Value = Deserialize::deserialize(d)?;
    match v {
        Value::Number(n) => Ok(n
            .as_u64()
            .ok_or(serde::de::Error::custom("Expected number or string"))?
            as u32),
        Value::String(s) => s
            .parse::<u32>()
            .map_err(|e| serde::de::Error::custom(format!("{}", e))),
        _ => Err(serde::de::Error::custom("Expected number or string")),
    }
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UserToken {
    pub token_type: String,
    pub scope: Option<String>,
    #[serde(deserialize_with = "decode_number_from_string")]
    pub expires_in: u32,
    #[serde(deserialize_with = "decode_number_from_string")]
    pub ext_expires_in: u32,
    pub access_token: Option<String>,
    pub refresh_token: String,
    #[serde(deserialize_with = "decode_string_or_struct")]
    #[zeroize(skip)]
    pub id_token: IdToken,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    #[zeroize(skip)]
    pub client_info: ClientInfo,
    #[cfg(feature = "broker")]
    #[zeroize(skip)]
    pub prt: Option<SealedData>,
}

impl UserToken {
    /// Fetch the UUID from the user token
    ///
    /// # Returns
    ///
    /// * Success: The user Azure UUID
    /// * Failure: An MsalError, indicating the failure.
    pub fn uuid(&self) -> Result<Uuid, MsalError> {
        Uuid::parse_str(&self.id_token.oid).map_err(|e| MsalError::InvalidParse(format!("{}", e)))
    }

    /// Fetch the spn from the user token
    ///
    /// # Returns
    ///
    /// * Success: The user Azure spn
    /// * Failure: An MsalError, indicating the failure.
    pub fn spn(&self) -> Result<String, MsalError> {
        match &self.id_token.preferred_username {
            Some(spn) => Ok(spn.to_string()),
            // If all else fails, extract the upn from the access_token
            None => match &self.access_token {
                Some(access_token) => {
                    let mut siter = access_token.splitn(3, '.');
                    siter.next(); // Ignore the header
                    let payload: Value = json_from_str(
                        &String::from_utf8(
                            URL_SAFE_NO_PAD
                                .decode(siter.next().ok_or_else(|| {
                                    MsalError::InvalidParse("Payload not present".to_string())
                                })?)
                                .map_err(|e| MsalError::InvalidBase64(format!("{}", e)))?,
                        )
                        .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?,
                    )
                    .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
                    match payload.get("upn") {
                        Some(upn) => match upn.as_str() {
                            Some(upn) => Ok(upn.to_string()),
                            None => Err(MsalError::GeneralFailure(
                                "No spn available for UserToken".to_string(),
                            )),
                        },
                        None => Err(MsalError::GeneralFailure(
                            "No spn available for UserToken".to_string(),
                        )),
                    }
                }
                None => Err(MsalError::GeneralFailure(
                    "No spn available for UserToken".to_string(),
                )),
            },
        }
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
struct UsernamePasswordAuthenticationPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    username: String,
    password: String,
}

#[cfg(feature = "broker")]
impl UsernamePasswordAuthenticationPayload {
    fn new(username: &str, password: &str, request_nonce: &str) -> Self {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        UsernamePasswordAuthenticationPayload {
            client_id: BROKER_CLIENT_IDENT.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "password".to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default, Zeroize, ZeroizeOnDrop)]
struct RefreshTokenAuthenticationPayload {
    client_id: String,
    request_nonce: String,
    scope: String,
    win_ver: Option<String>,
    grant_type: String,
    refresh_token: String,
}

#[cfg(feature = "broker")]
impl RefreshTokenAuthenticationPayload {
    fn new(refresh_token: &str, request_nonce: &str) -> Self {
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        RefreshTokenAuthenticationPayload {
            client_id: BROKER_CLIENT_IDENT.to_string(),
            request_nonce: request_nonce.to_string(),
            scope: "openid aza ugs".to_string(),
            win_ver: os_release,
            grant_type: "refresh_token".to_string(),
            refresh_token: refresh_token.to_string(),
        }
    }
}

#[cfg(feature = "broker")]
#[derive(Serialize, Clone, Default)]
struct ExchangePRTPayload {
    win_ver: Option<String>,
    scope: String,
    resource: Option<String>,
    request_nonce: String,
    refresh_token: String,
    iss: String,
    grant_type: String,
    client_id: String,
    aud: String,
}

#[cfg(feature = "broker")]
impl ExchangePRTPayload {
    fn new(
        prt: &PrimaryRefreshToken,
        scope: &[&str],
        nonce: &str,
        resource: Option<String>,
        request_prt: bool,
    ) -> Result<Self, MsalError> {
        let mut scopes = format!("openid {}", scope.join(" "));
        if request_prt {
            scopes = format!("{} aza", scopes);
        }
        let os_release = match OsRelease::new() {
            Ok(os_release) => Some(format!(
                "{} {}",
                os_release.pretty_name, os_release.version_id
            )),
            Err(_) => None,
        };
        Ok(ExchangePRTPayload {
            win_ver: os_release,
            scope: scopes,
            resource,
            request_nonce: nonce.to_string(),
            refresh_token: prt.refresh_token.clone(),
            iss: "aad:brokerplugin".to_string(),
            grant_type: "refresh_token".to_string(),
            client_id: BROKER_CLIENT_IDENT.to_string(),
            aud: "login.microsoftonline.com".to_string(),
        })
    }
}

#[cfg(feature = "broker")]
#[derive(Debug, Deserialize)]
struct Nonce {
    #[serde(rename = "Nonce")]
    nonce: String,
}

#[cfg(feature = "broker")]
impl FromStr for TGT {
    type Err = MsalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        json_from_str(s).map_err(|e| MsalError::InvalidParse(format!("Failed parsing tgt: {}", e)))
    }
}

#[cfg(feature = "broker")]
#[derive(Default, Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct TGT {
    #[serde(rename = "clientKey")]
    pub client_key: Option<String>,
    #[serde(rename = "keyType")]
    pub key_type: u32,
    pub error: Option<String>,
    #[serde(rename = "messageBuffer")]
    pub message_buffer: Option<String>,
    pub realm: Option<String>,
    pub sn: Option<String>,
    pub cn: Option<String>,
    #[serde(rename = "sessionKeyType")]
    pub session_key_type: u32,
    #[serde(rename = "accountType")]
    pub account_type: u32,
}

#[cfg(feature = "broker")]
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[allow(dead_code)]
struct PrimaryRefreshToken {
    token_type: String,
    expires_in: String,
    ext_expires_in: String,
    expires_on: String,
    refresh_token: String,
    refresh_token_expires_in: u64,
    session_key_jwe: Option<String>,
    #[serde(deserialize_with = "decode_string_or_struct")]
    #[zeroize(skip)]
    id_token: IdToken,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    #[zeroize(skip)]
    client_info: ClientInfo,
    device_tenant_id: Option<String>,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    tgt_ad: TGT,
    #[serde(deserialize_with = "decode_string_or_struct", default)]
    tgt_cloud: TGT,
    kerberos_top_level_names: Option<String>,
}

#[cfg(feature = "broker")]
impl PrimaryRefreshToken {
    fn session_key(&self) -> Result<SessionKey, MsalError> {
        match &self.session_key_jwe {
            Some(session_key_jwe) => SessionKey::new(session_key_jwe),
            None => Err(MsalError::CryptoFail("session_key_jwe missing".to_string())),
        }
    }

    fn clone_session_key(&self, new_prt: &mut PrimaryRefreshToken) {
        new_prt.session_key_jwe = self.session_key_jwe.clone();
    }
}

#[cfg(feature = "broker")]
struct SessionKey {
    session_key_jwe: JweCompact,
}

#[cfg(feature = "broker")]
impl SessionKey {
    fn new(session_key_jwe: &str) -> Result<Self, MsalError> {
        Ok(SessionKey {
            session_key_jwe: JweCompact::from_str(session_key_jwe)
                .map_err(|e| MsalError::InvalidParse(format!("Failed parsing jwe: {}", e)))?,
        })
    }

    fn decipher_prt_v2(
        &self,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
        jwe: &JweCompact,
    ) -> Result<Jwe, MsalError> {
        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            tpm,
            transport_key,
            &self.session_key_jwe,
        )
        .map_err(|e| MsalError::CryptoFail(format!("Unable to decipher session_key_jwe: {}", e)))?;
        session_key
            .decipher_prt_v2(tpm, transport_key, jwe)
            .map_err(|e| MsalError::CryptoFail(format!("Failed to decipher Jwe: {}", e)))
    }

    fn sign<V: JwsSignable>(
        &self,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
        jws: &V,
    ) -> Result<V::Signed, MsalError> {
        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            tpm,
            transport_key,
            &self.session_key_jwe,
        )
        .map_err(|e| MsalError::CryptoFail(format!("Unable to decipher session_key_jwe: {}", e)))?;
        session_key
            .sign(tpm, transport_key, jws)
            .map_err(|e| MsalError::CryptoFail(format!("Failed signing jwk: {}", e)))
    }
}

struct ClientApplication {
    client: Client,
    client_id: String,
    authority: String,
}

impl ClientApplication {
    fn new(client_id: &str, authority: Option<&str>) -> Self {
        ClientApplication {
            client: reqwest::Client::new(),
            client_id: client_id.to_string(),
            authority: match authority {
                Some(authority) => authority.to_string(),
                None => "https://login.microsoftonline.com/common".to_string(),
            },
        }
    }

    async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", &scopes_str),
            ("username", username),
            ("password", password),
            ("grant_type", "password"),
            ("client_info", "1"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!("{}/oauth2/v2.0/token", self.authority))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: UserToken = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;

            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", &scopes_str),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_info", "1"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client
            .post(format!("{}/oauth2/v2.0/token", self.authority))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: UserToken = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;

            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }
}

pub struct PublicClientApplication {
    app: ClientApplication,
}

impl PublicClientApplication {
    /// Create an instance of an application.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Your app has a client_id after you register it on
    ///   AAD.
    ///
    /// * `authority` - A URL that identifies a token authority. It should
    ///   be of the format <https://login.microsoftonline.com/your_tenant> By
    ///   default, we will use <https://login.microsoftonline.com/common>.
    pub fn new(client_id: &str, authority: Option<&str>) -> Self {
        PublicClientApplication {
            app: ClientApplication::new(client_id, authority),
        }
    }

    fn client(&self) -> &Client {
        &self.app.client
    }

    fn client_id(&self) -> &str {
        &self.app.client_id
    }

    fn authority(&self) -> &str {
        &self.app.authority
    }

    /// Gets a token for a given resource via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        self.app
            .acquire_token_by_username_password(username, password, scopes)
            .await
    }

    /// Acquire token(s) based on a refresh token (RT) obtained from elsewhere.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `scopes` - The scopes associated with this old RT.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken, which means migration was successful.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
    ) -> Result<UserToken, MsalError> {
        self.app
            .acquire_token_by_refresh_token(refresh_token, scopes)
            .await
    }

    /// Initiate a Device Flow instance, which will be used in
    /// acquire_token_by_device_flow.
    ///
    /// # Arguments
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// # Returns
    ///
    /// * Success: A DeviceAuthorizationResponse containing a user_code key,
    ///   among others
    /// * Failure: An MsalError, indicating the failure.
    pub async fn initiate_device_flow(
        &self,
        scopes: Vec<&str>,
    ) -> Result<DeviceAuthorizationResponse, MsalError> {
        let mut all_scopes = vec!["openid", "profile", "offline_access"];
        all_scopes.extend(scopes);
        let scopes_str = all_scopes.join(" ");

        let params = [("client_id", self.client_id()), ("scope", &scopes_str)];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/v2.0/devicecode", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: DeviceAuthorizationResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Ok(json_resp)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    /// Obtain token by a device flow object, with customizable polling effect.
    ///
    /// # Arguments
    ///
    /// * `flow` - A DeviceAuthorizationResponse previously generated by
    /// initiate_device_flow.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_device_flow(
        &self,
        flow: DeviceAuthorizationResponse,
    ) -> Result<UserToken, MsalError> {
        let params = [
            ("client_id", self.client_id()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &flow.device_code),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, url_encode(v)))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/v2.0/token", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let token: UserToken = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;

            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }
}

#[cfg(feature = "broker")]
pub struct EnrollAttrs {
    device_display_name: String,
    device_type: String,
    join_type: u32,
    os_version: String,
    target_domain: String,
}

#[cfg(feature = "broker")]
impl EnrollAttrs {
    /// Initialize attributes for device enrollment
    ///
    /// # Arguments
    ///
    /// * `target_domain` - The domain to be enrolled in.
    ///
    /// * `device_display_name` - An optional chosen display name for the
    ///   enrolled device. Defaults to the system hostname.
    ///
    /// * `device_type` - An optional device type. Defaults to 'Linux'. This
    ///   effects which Intune policies are distributed to the client.
    ///
    /// * `join_type` - An optional join type. Defaults to 0. Possible values
    ///   are:
    ///     - 0: Azure AD join.
    ///     - 4: Azure AD register only.
    ///     - 6: Azure AD hybrid join.
    ///     - 8: Azure AD join.
    ///
    /// * `os_version` - An optional OS version. Defaults to the contents of
    ///   /etc/os-release.
    ///
    /// * Success: A new EnrollAttrs for device enrollment.
    /// * Failure: An MsalError, indicating the failure.
    pub fn new(
        target_domain: String,
        device_display_name: Option<String>,
        device_type: Option<String>,
        join_type: Option<u32>,
        os_version: Option<String>,
    ) -> Result<Self, MsalError> {
        let device_display_name_int = match device_display_name {
            Some(device_display_name) => device_display_name,
            None => match hostname::get()
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?
                .to_str()
            {
                Some(host) => String::from(host),
                None => {
                    return Err(MsalError::GeneralFailure(
                        "Failed to get machine hostname for enrollment".to_string(),
                    ))
                }
            },
        };
        let device_type_int = match device_type {
            Some(device_type) => device_type,
            None => "Linux".to_string(),
        };
        let join_type_int = join_type.unwrap_or(0);
        let os_version_int = match os_version {
            Some(os_version) => os_version,
            None => {
                let os_release =
                    OsRelease::new().map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
                format!("{} {}", os_release.pretty_name, os_release.version_id)
            }
        };
        Ok(EnrollAttrs {
            device_display_name: device_display_name_int,
            device_type: device_type_int,
            join_type: join_type_int,
            os_version: os_version_int,
            target_domain,
        })
    }
}

#[cfg(feature = "broker")]
#[derive(Zeroize, ZeroizeOnDrop)]
struct BcryptRsaKeyBlob {
    bit_length: u32,
    exponent: Vec<u8>,
    modulus: Vec<u8>,
}

#[cfg(feature = "broker")]
impl BcryptRsaKeyBlob {
    fn new(bit_length: u32, exponent: &[u8], modulus: &[u8]) -> Self {
        BcryptRsaKeyBlob {
            bit_length,
            exponent: exponent.to_vec(),
            modulus: modulus.to_vec(),
        }
    }
}

#[cfg(feature = "broker")]
impl TryInto<Vec<u8>> for BcryptRsaKeyBlob {
    type Error = MsalError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut cng_blob = b"RSA1".to_vec(); // Magic
        cng_blob.extend_from_slice(&self.bit_length.to_le_bytes()); // BitLength
        let exponent_len: u32 = self.exponent.len().try_into().map_err(|e| {
            MsalError::GeneralFailure(format!("Exponent len into u32 failed: {:?}", e))
        })?;
        cng_blob.extend_from_slice(&exponent_len.to_le_bytes()); // cbPublicExpLength
        let modulus_len: u32 = self.modulus.len().try_into().map_err(|e| {
            MsalError::GeneralFailure(format!("Modulus len into u32 failed: {:?}", e))
        })?;
        cng_blob.extend_from_slice(&modulus_len.to_le_bytes()); // cbModulusLength

        // MS reserves spots for P and Q lengths, but doesn't permit P and Q in
        // the blob itself. Requests will be rejected if P and Q are specified.
        let prime1_len: u32 = 0;
        cng_blob.extend_from_slice(&prime1_len.to_le_bytes()); // cbPrime1Length
        let prime2_len: u32 = 0;
        cng_blob.extend_from_slice(&prime2_len.to_le_bytes()); // cbPrime2Length

        cng_blob.extend_from_slice(self.exponent.as_slice()); // cbPublicExp
        cng_blob.extend_from_slice(self.modulus.as_slice()); // cbModulus
        Ok(cng_blob)
    }
}

#[cfg(feature = "broker")]
pub struct BrokerClientApplication {
    app: PublicClientApplication,
    transport_key: Option<LoadableMsOapxbcRsaKey>,
    cert_key: Option<LoadableIdentityKey>,
}

#[cfg(feature = "broker")]
impl BrokerClientApplication {
    /// Create an instance of an application.
    ///
    /// # Arguments
    ///
    /// * `authority` - A URL that identifies a token authority. It should
    ///   be of the format <https://login.microsoftonline.com/your_tenant> By
    ///   default, we will use <https://login.microsoftonline.com/common>.
    ///
    /// * `transport_key` - An optional LoadableMsOapxbcRsaKey transport key
    ///   from enrolling the device.
    ///
    /// * `cert_key` - An optional LoadableIdentityKey which was used to create
    ///   the enrollment CSR.
    ///
    /// NOTE: If `transport_key` and `cert_key` are not provided from a previous
    /// device enrollment, then enrollment will be required.
    pub fn new(
        authority: Option<&str>,
        transport_key: Option<LoadableMsOapxbcRsaKey>,
        cert_key: Option<LoadableIdentityKey>,
    ) -> Self {
        BrokerClientApplication {
            app: PublicClientApplication::new(BROKER_APP_ID, authority),
            transport_key,
            cert_key,
        }
    }

    fn client(&self) -> &Client {
        self.app.client()
    }

    fn authority(&self) -> &str {
        self.app.authority()
    }

    fn transport_key(
        &self,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<MsOapxbcRsaKey, MsalError> {
        match &self.transport_key {
            Some(transport_key) => {
                let transport_key = tpm.msoapxbc_rsa_key_load(machine_key, transport_key)
            .map_err(|e| {
                MsalError::TPMFail(format!("Failed to load IdentityKey: {:?}", e))
            })?;
                Ok(transport_key)
            },
            None => Err(MsalError::ConfigError("The transport key was not found. Please provide the transport key during initialize of the BrokerClientApplication, or enroll the device.".to_string())),
        }
    }

    /// Set the enrollment transport key
    ///
    /// # Arguments
    ///
    /// * `transport_key` - An optional LoadableMsOapxbcRsaKey transport key
    ///   from enrolling the device.
    pub fn set_transport_key(&mut self, transport_key: Option<LoadableMsOapxbcRsaKey>) {
        self.transport_key = transport_key;
    }

    fn cert_key(
        &self,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<IdentityKey, MsalError> {
        match &self.cert_key {
            Some(cert_key) => {
                let cert_key = tpm.identity_key_load(machine_key, cert_key)
            .map_err(|e| {
                MsalError::TPMFail(format!("Failed to load IdentityKey: {:?}", e))
            })?;
                Ok(cert_key)
            },
            None => Err(MsalError::ConfigError("The certificate key was not found. Please provide the certificate key during initialize of the BrokerClientApplication, or enroll the device.".to_string())),
        }
    }

    /// Set the enrollment certificate key
    ///
    /// # Arguments
    ///
    /// * `cert_key` - An optional LoadableIdentityKey which was used to create
    ///   the enrollment CSR.
    pub fn set_cert_key(&mut self, cert_key: Option<LoadableIdentityKey>) {
        self.cert_key = cert_key;
    }

    /// Enroll the device in the directory.
    ///
    /// # Arguments
    ///
    /// * `token` - Token obtained via either
    ///   acquire_token_by_username_password_for_device_enrollment
    ///   or acquire_token_by_device_flow.
    ///
    /// * `domain` - The domain the device is to be enrolled in.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    ///
    /// * Success: A LoadableMsOapxbcRsaKey transport key, a LoadableIdentityKey certificate key,
    /// and a `device_id`.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn enroll_device(
        &mut self,
        token: &UserToken,
        attrs: EnrollAttrs,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<(LoadableMsOapxbcRsaKey, LoadableIdentityKey, String), MsalError> {
        // Create the transport and cert keys
        let loadable_cert_key = tpm
            .identity_key_create(machine_key, KeyAlgorithm::Rsa2048)
            .map_err(|e| MsalError::TPMFail(format!("Failed creating certificate key: {:?}", e)))?;
        let loadable_transport_key = tpm
            .msoapxbc_rsa_key_create(machine_key)
            .map_err(|e| MsalError::TPMFail(format!("Failed creating tranport key: {:?}", e)))?;
        self.transport_key = Some(loadable_transport_key.clone());

        // Create the CSR
        let csr_der = match tpm.identity_key_certificate_request(
            machine_key,
            &loadable_cert_key,
            "7E980AD9-B86D-4306-9425-9AC066FB014A",
        ) {
            Ok(csr_der) => csr_der,
            Err(e) => return Err(MsalError::TPMFail(format!("Failed creating CSR: {:?}", e))),
        };

        // Load the transport key
        let transport_key = match tpm.msoapxbc_rsa_key_load(machine_key, &loadable_transport_key) {
            Ok(transport_key) => transport_key,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed loading id key: {:?}",
                    e
                )))
            }
        };
        let transport_key_der = match tpm.msoapxbc_rsa_public_as_der(&transport_key) {
            Ok(transport_key_pem) => transport_key_pem,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed getting transport key as der: {:?}",
                    e
                )))
            }
        };
        let transport_key_rsa = Rsa::public_key_from_der(&transport_key_der)
            .map_err(|e| MsalError::TPMFail(format!("{}", e)))?;

        let (cert, device_id) = match &token.access_token {
            Some(access_token) => {
                self.enroll_device_internal(access_token, attrs, &transport_key_rsa, &csr_der)
                    .await?
            }
            None => {
                return Err(MsalError::GeneralFailure(
                    "Access token not found".to_string(),
                ))
            }
        };

        let new_loadable_cert_key = match tpm.identity_key_associate_certificate(
            machine_key,
            &loadable_cert_key,
            &cert
                .to_der()
                .map_err(|e| MsalError::TPMFail(format!("{}", e)))?,
        ) {
            Ok(loadable_cert_key) => loadable_cert_key,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed creating loadable identity key: {:?}",
                    e
                )))
            }
        };

        self.cert_key = Some(new_loadable_cert_key.clone());
        Ok((
            loadable_transport_key,
            new_loadable_cert_key,
            device_id.to_string(),
        ))
    }

    async fn enroll_device_internal(
        &self,
        access_token: &str,
        attrs: EnrollAttrs,
        transport_key: &Rsa<Public>,
        csr_der: &Vec<u8>,
    ) -> Result<(X509, String), MsalError> {
        let enrollment_services =
            discover_enrollment_services(self.client(), access_token, &attrs.target_domain).await?;
        let (join_endpoint, service_version) = match enrollment_services.device_join_service {
            Some(device_join_service) => {
                let join_endpoint = match device_join_service.endpoint {
                    Some(join_endpoint) => join_endpoint,
                    None => format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
                };
                let service_version = match device_join_service.service_version {
                    Some(service_version) => service_version,
                    None => "2.0".to_string(),
                };
                (join_endpoint, service_version)
            }
            None => (
                format!("{}/EnrollmentServer/device/", DISCOVERY_URL).to_string(),
                "2.0".to_string(),
            ),
        };

        let url = Url::parse_with_params(&join_endpoint, &[("api-version", service_version)])
            .map_err(|e| MsalError::URLFormatFailed(format!("{}", e)))?;

        let transport_key_blob: Vec<u8> = BcryptRsaKeyBlob::new(
            2048,
            &transport_key.e().to_vec(),
            &transport_key.n().to_vec(),
        )
        .try_into()?;

        let payload = json!({
            "CertificateRequest": {
                "Type": "pkcs10",
                "Data": STANDARD.encode(csr_der)
            },
            "DeviceDisplayName": attrs.device_display_name,
            "DeviceType": attrs.device_type,
            "JoinType": attrs.join_type,
            "OSVersion": attrs.os_version,
            "TargetDomain": attrs.target_domain,
            "TransportKey": STANDARD.encode(transport_key_blob),
            "Attributes": {
                "ReuseDevice": "true",
                "ReturnClientSid": "true"
            }
        });
        if let Ok(pretty) = to_string_pretty(&payload) {
            debug!("POST {}: {}", url, pretty);
        }
        let resp = self
            .client()
            .post(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::CONTENT_TYPE, "application/json")
            .header(DRS_CLIENT_NAME_HEADER_FIELD, env!("CARGO_PKG_NAME"))
            .header(DRS_CLIENT_VERSION_HEADER_FIELD, env!("CARGO_PKG_VERSION"))
            .header(header::ACCEPT, "application/json, text/plain, */*")
            .json(&payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let res: DRSResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            let cert = X509::from_pem(
                format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                    res.certificate.raw_body
                )
                .as_bytes(),
            )
            .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
            let subject_name = cert.subject_name();
            let device_id = match subject_name.entries().next() {
                Some(entry) => entry
                    .data()
                    .as_utf8()
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
                None => {
                    return Err(MsalError::GeneralFailure(
                        "The device id was missing from the certificate response".to_string(),
                    ))
                }
            };
            Ok((cert, device_id.to_string()))
        } else {
            Err(MsalError::GeneralFailure(
                resp.text()
                    .await
                    .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?,
            ))
        }
    }

    /// Gets a token for a given resource via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `scopes` - Scopes requested to access a protected API (a resource).
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_username_password(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<UserToken, MsalError> {
        let prt = self
            .acquire_user_prt_by_username_password_internal(username, password, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        let session_key = prt.session_key()?;
        let mut token = self
            .exchange_prt_for_access_token_internal(
                &prt,
                scopes.clone(),
                tpm,
                machine_key,
                &transport_key,
                &session_key,
                None,
            )
            .await?;
        token.client_info = prt.client_info.clone();
        token.prt = Some(self.seal_user_prt(&prt, tpm, &transport_key)?);
        Ok(token)
    }

    /// Acquire token(s) based on a refresh token (RT) obtained from elsewhere.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `scopes` - The scopes associated with this old RT.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: A UserToken, which means migration was successful.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_refresh_token(
        &self,
        refresh_token: &str,
        scopes: Vec<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<UserToken, MsalError> {
        let prt = self
            .acquire_user_prt_by_refresh_token_internal(refresh_token, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        let session_key = prt.session_key()?;
        let mut token = self
            .exchange_prt_for_access_token_internal(
                &prt,
                scopes.clone(),
                tpm,
                machine_key,
                &transport_key,
                &session_key,
                None,
            )
            .await?;
        token.client_info = prt.client_info.clone();
        token.prt = Some(self.seal_user_prt(&prt, tpm, &transport_key)?);
        Ok(token)
    }

    /// Gets a token for enrollment via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_username_password_for_device_enrollment(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserToken, MsalError> {
        let drs_scope = format!("{}/.default", DRS_APP_ID);
        self.app
            .acquire_token_by_username_password(username, password, vec![&drs_scope])
            .await
    }

    /// Gets a token for enrollment via refresh token.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_refresh_token_for_device_enrollment(
        &self,
        refresh_token: &str,
    ) -> Result<UserToken, MsalError> {
        let drs_scope = format!("{}/.default", DRS_APP_ID);
        self.app
            .acquire_token_by_refresh_token(refresh_token, vec![&drs_scope])
            .await
    }

    /// Initiate a Device Flow instance for enrollment, which will be
    /// used in acquire_token_by_device_flow.
    ///
    /// # Returns
    ///
    /// * Success: A DeviceAuthorizationResponse containing a user_code key,
    ///   among others
    /// * Failure: An MsalError, indicating the failure.
    pub async fn initiate_device_flow_for_device_enrollment(
        &self,
    ) -> Result<DeviceAuthorizationResponse, MsalError> {
        let drs_scope = format!("{}/.default", DRS_APP_ID);
        self.app.initiate_device_flow(vec![&drs_scope]).await
    }

    /// Obtain token for enrollment by a device flow object, with customizable
    /// polling effect.
    ///
    /// # Arguments
    ///
    /// * `flow` - A DeviceAuthorizationResponse previously generated by
    /// initiate_device_flow.
    ///
    /// # Returns
    ///
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_token_by_device_flow(
        &self,
        flow: DeviceAuthorizationResponse,
    ) -> Result<UserToken, MsalError> {
        self.app.acquire_token_by_device_flow(flow).await
    }

    async fn request_nonce(&self) -> Result<String, MsalError> {
        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .body("grant_type=srv_challenge")
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: Nonce = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Ok(json_resp.nonce)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    async fn build_jwt_by_username_password(
        &self,
        username: &str,
        password: &str,
        cert: Option<&X509>,
    ) -> Result<Jws, MsalError> {
        let nonce = self.request_nonce().await?;

        let mut builder = JwsBuilder::from(
            serde_json::to_vec(&UsernamePasswordAuthenticationPayload::new(
                username, password, &nonce,
            ))
            .map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing UsernamePassword JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"));

        if let Some(cert) = cert {
            builder = builder.set_x5c(Some(vec![cert
                .to_der()
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?]));
        }

        Ok(builder.build())
    }

    /// Gets a Primary Refresh Token (PRT) via user credentials.
    ///
    /// # Arguments
    ///
    /// * `username` - Typically a UPN in the form of an email address.
    ///
    /// * `password` - The password.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_user_prt_by_username_password(
        &self,
        username: &str,
        password: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<SealedData, MsalError> {
        let prt = self
            .acquire_user_prt_by_username_password_internal(username, password, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        self.seal_user_prt(&prt, tpm, &transport_key)
    }

    async fn acquire_user_prt_by_username_password_internal(
        &self,
        username: &str,
        password: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let jwt = self
            .build_jwt_by_username_password(username, password, None)
            .await?;
        let signed_jwt = self.sign_jwt(&jwt, tpm, machine_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    async fn build_jwt_by_refresh_token(
        &self,
        refresh_token: &str,
        cert: Option<&X509>,
    ) -> Result<Jws, MsalError> {
        let nonce = self.request_nonce().await?;

        let mut builder = JwsBuilder::from(
            serde_json::to_vec(&RefreshTokenAuthenticationPayload::new(
                refresh_token,
                &nonce,
            ))
            .map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing RefreshToken JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"));

        if let Some(cert) = cert {
            builder = builder.set_x5c(Some(vec![cert
                .to_der()
                .map_err(|e| MsalError::CryptoFail(format!("{}", e)))?]));
        }

        Ok(builder.build())
    }

    /// Gets a Primary Refresh Token (PRT) via a refresh token (RT) obtained
    /// previously.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The old refresh token, as a string.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// # Returns
    /// * Success: An encrypted PrimaryRefreshToken, containing a refresh_token and tgt.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn acquire_user_prt_by_refresh_token(
        &self,
        refresh_token: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<SealedData, MsalError> {
        let prt = self
            .acquire_user_prt_by_refresh_token_internal(refresh_token, tpm, machine_key)
            .await?;
        let transport_key = self.transport_key(tpm, machine_key)?;
        self.seal_user_prt(&prt, tpm, &transport_key)
    }

    async fn acquire_user_prt_by_refresh_token_internal(
        &self,
        refresh_token: &str,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let jwt = self.build_jwt_by_refresh_token(refresh_token, None).await?;
        let signed_jwt = self.sign_jwt(&jwt, tpm, machine_key).await?;

        self.acquire_user_prt_jwt(&signed_jwt).await
    }

    async fn sign_jwt(
        &self,
        jwt: &Jws,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
    ) -> Result<String, MsalError> {
        let cert_key = self.cert_key(tpm, machine_key)?;
        let mut jws_tpm_signer = match JwsTpmSigner::new(tpm, &cert_key) {
            Ok(jws_tpm_signer) => jws_tpm_signer,
            Err(e) => {
                return Err(MsalError::TPMFail(format!(
                    "Failed loading tpm signer: {}",
                    e
                )))
            }
        };

        let signed_jwt = match jws_tpm_signer.sign(jwt) {
            Ok(signed_jwt) => signed_jwt,
            Err(e) => return Err(MsalError::TPMFail(format!("Failed signing jwk: {}", e))),
        };

        Ok(format!("{}", signed_jwt))
    }

    async fn acquire_user_prt_jwt(
        &self,
        signed_jwt: &str,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        // [MS-OAPXBC] 3.2.5.1.2 POST (Request for Primary Refresh Token)
        let params = [
            ("windows_api_version", "2.0"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("request", &signed_jwt),
            ("client_info", "1"),
            ("tgt", "true"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let json_resp: PrimaryRefreshToken = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Ok(json_resp)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    async fn sign_session_key_jwt(
        &self,
        jwt: &Jws,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        session_key: &SessionKey,
    ) -> Result<String, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let signed_jwt = session_key.sign(tpm, &transport_key, jwt)?;

        Ok(format!("{}", signed_jwt))
    }

    /// Given the primary refresh token, this method requests an access token.
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `scope` - The scope that the client requests for the access token.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// * `request_resource` - A resource for obtaining an access token.
    ///   Default is the MS Graph API (00000002-0000-0000-c000-000000000000).
    ///
    /// # Returns
    /// * Success: A UserToken containing an access_token.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn exchange_prt_for_access_token(
        &self,
        sealed_prt: &SealedData,
        scope: Vec<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        request_resource: Option<String>,
    ) -> Result<UserToken, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        let session_key = prt.session_key()?;
        self.exchange_prt_for_access_token_internal(
            &prt,
            scope,
            tpm,
            machine_key,
            &transport_key,
            &session_key,
            request_resource,
        )
        .await
    }

    async fn exchange_prt_for_access_token_internal(
        &self,
        prt: &PrimaryRefreshToken,
        scope: Vec<&str>,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        transport_key: &MsOapxbcRsaKey,
        session_key: &SessionKey,
        request_resource: Option<String>,
    ) -> Result<UserToken, MsalError> {
        let resource = match request_resource {
            Some(resource) => resource,
            None => "00000002-0000-0000-c000-000000000000".to_string(),
        };
        let nonce = self.request_nonce().await?;
        let jwt = JwsBuilder::from(
            serde_json::to_vec(&ExchangePRTPayload::new(
                prt,
                &scope,
                &nonce,
                Some(resource),
                false,
            )?)
            .map_err(|e| {
                MsalError::InvalidJson(format!("Failed serializing ExchangePRT JWT: {}", e))
            })?,
        )
        .set_typ(Some("JWT"))
        .build();
        let signed_jwt = self
            .sign_session_key_jwt(&jwt, tpm, machine_key, session_key)
            .await?;

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("windows_api_version", "2.2"),
            ("request", &signed_jwt),
            ("client_info", "1"),
        ];
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let enc = resp
                .text()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
            let jwe = JweCompact::from_str(&enc)
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
            let token: UserToken = json_from_str(
                std::str::from_utf8(
                    session_key
                        .decipher_prt_v2(tpm, transport_key, &jwe)?
                        .payload(),
                )
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?,
            )
            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Ok(token)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    /// Given the primary refresh token, this method requests a new primary
    /// refresh token
    ///
    /// # Arguments
    ///
    /// * `sealed_prt` -  An encrypted primary refresh token that was
    ///   previously received from the server.
    ///
    /// * `tpm` - The tpm object.
    ///
    /// * `machine_key` - The TPM MachineKey associated with this application.
    ///
    /// * `request_tgt` - Whether to include a request for a TGT.
    ///
    /// # Returns
    /// * Success: An encrypted PrimaryRefreshToken, containing a refresh_token
    ///   and optionally a tgt. The session key is copied from the old PRT.
    /// * Failure: An MsalError, indicating the failure.
    pub async fn exchange_prt_for_prt(
        &self,
        sealed_prt: &SealedData,
        tpm: &mut BoxedDynTpm,
        machine_key: &MachineKey,
        request_tgt: bool,
    ) -> Result<SealedData, MsalError> {
        let transport_key = self.transport_key(tpm, machine_key)?;
        let prt = self.unseal_user_prt(sealed_prt, tpm, &transport_key)?;
        let session_key = prt.session_key()?;
        let nonce = self.request_nonce().await?;
        let jwt = JwsBuilder::from(
            serde_json::to_vec(&ExchangePRTPayload::new(&prt, &[], &nonce, None, true)?).map_err(
                |e| MsalError::InvalidJson(format!("Failed serializing ExchangePRT JWT: {}", e)),
            )?,
        )
        .set_typ(Some("JWT"))
        .build();
        let signed_jwt = self
            .sign_session_key_jwt(&jwt, tpm, machine_key, &session_key)
            .await?;

        let mut params = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("windows_api_version", "2.2"),
            ("request", &signed_jwt),
            ("client_info", "1"),
        ];
        if request_tgt {
            params.push(("tgt", "true"));
        }
        let payload = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");

        let resp = self
            .client()
            .post(format!("{}/oauth2/token", self.authority()))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(payload)
            .send()
            .await
            .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
        if resp.status().is_success() {
            let enc = resp
                .text()
                .await
                .map_err(|e| MsalError::GeneralFailure(format!("{}", e)))?;
            let jwe = JweCompact::from_str(&enc)
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?;
            let mut new_prt: PrimaryRefreshToken = json_from_str(
                std::str::from_utf8(
                    session_key
                        .decipher_prt_v2(tpm, &transport_key, &jwe)?
                        .payload(),
                )
                .map_err(|e| MsalError::InvalidParse(format!("{}", e)))?,
            )
            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            prt.clone_session_key(&mut new_prt);
            self.seal_user_prt(&new_prt, tpm, &transport_key)
        } else {
            let json_resp: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
            Err(MsalError::AcquireTokenFailed(json_resp))
        }
    }

    fn seal_user_prt(
        &self,
        prt: &PrimaryRefreshToken,
        tpm: &mut BoxedDynTpm,
        key: &MsOapxbcRsaKey,
    ) -> Result<SealedData, MsalError> {
        let prt_data = json_to_vec(prt)
            .map_err(|e| MsalError::InvalidJson(format!("Failed serializing PRT {:?}", e)))?;
        tpm.msoapxbc_rsa_seal_data(key, &prt_data)
            .map_err(|e| MsalError::TPMFail(format!("Failed sealing PRT {:?}", e)))
    }

    fn unseal_user_prt(
        &self,
        sealed_data: &SealedData,
        tpm: &mut BoxedDynTpm,
        key: &MsOapxbcRsaKey,
    ) -> Result<PrimaryRefreshToken, MsalError> {
        let prt_data = tpm
            .msoapxbc_rsa_unseal_data(key, sealed_data)
            .map_err(|e| MsalError::TPMFail(format!("Failed unsealing PRT {:?}", e)))?;
        json_from_slice(&prt_data)
            .map_err(|e| MsalError::InvalidJson(format!("Failed deserializing PRT {:?}", e)))
    }
}
