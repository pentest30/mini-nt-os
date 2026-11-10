//! L'emprunt d'identité d'un client local par un serveur
//! (SeCreateClientSecurity puis SeImpersonateClientEx ;
//! `ntoskrnl/se/client.c` de ReactOS comme spécification) : quel jeton, à
//! quel niveau, et si seuls ses groupes et privilèges actifs comptent.

use alloc::sync::Arc;

use abi::lpc::SecurityQualityOfService32;
use abi::ntstatus::{NtStatus, STATUS_BAD_IMPERSONATION_LEVEL, STATUS_INVALID_PARAMETER};
use abi::security::{SECURITY_DELEGATION, SECURITY_IMPERSONATION, SECURITY_STATIC_TRACKING, TOKEN_TYPE_IMPERSONATION};
use ob::Object;

use crate::Token;

/// Le jeton effectif d'un thread client (PsReferenceEffectiveToken) : celui
/// dont il emprunte lui-même l'identité, ou le jeton primaire de son
/// processus.
pub struct ClientToken {
    pub token: Arc<Object<Token>>,
    /// Le niveau et l'« effectif seul » de son propre emprunt, s'il emprunte.
    pub impersonating: Option<(u32, bool)>,
}

/// Ce que le serveur emprunte.
pub struct ClientSecurity {
    pub token: Arc<Object<Token>>,
    /// SECURITY_* : celui de la qualité de service.
    pub level: u32,
    pub effective_only: bool,
}

/// SeCreateClientSecurity puis SeImpersonateClientEx, pour un client local,
/// d'après la qualité de service `qos` : en suivi statique, une copie du jeton
/// du client, de type emprunt d'identité, au niveau demandé, avec l'« effectif
/// seul » demandé ; en suivi dynamique, le jeton lui-même, l'« effectif seul »
/// étant celui demandé ou, pour un client qui emprunte, aussi le sien.
///
/// # Errors
/// `STATUS_INVALID_PARAMETER` pour un niveau inconnu ;
/// `STATUS_BAD_IMPERSONATION_LEVEL` pour un niveau au-delà de celui du
/// client qui emprunte, ou un client qui n'emprunte qu'au niveau Anonymous
/// ou Identification.
///
/// # IRQL
/// <= DISPATCH_LEVEL.
pub fn client_security(client: ClientToken, qos: &SecurityQualityOfService32) -> Result<ClientSecurity, NtStatus> {
    if qos.impersonation_level > SECURITY_DELEGATION {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let asked = qos.effective_only != 0;
    let direct_effective_only = match client.impersonating {
        None => asked,
        Some((level, effective_only)) => {
            if qos.impersonation_level > level || level < SECURITY_IMPERSONATION {
                return Err(STATUS_BAD_IMPERSONATION_LEVEL);
            }
            effective_only || asked
        }
    };
    let (token, effective_only) = if qos.context_tracking_mode == SECURITY_STATIC_TRACKING {
        (client.token.duplicate(TOKEN_TYPE_IMPERSONATION, qos.impersonation_level), asked)
    } else {
        (client.token, direct_effective_only)
    };
    Ok(ClientSecurity { token, level: qos.impersonation_level, effective_only })
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::security::{SECURITY_ANONYMOUS, SECURITY_DYNAMIC_TRACKING, SECURITY_IDENTIFICATION, TOKEN_TYPE_PRIMARY};

    fn qos(level: u32, tracking: u8, effective_only: bool) -> SecurityQualityOfService32 {
        SecurityQualityOfService32 {
            length: 12,
            impersonation_level: level,
            context_tracking_mode: tracking,
            effective_only: u8::from(effective_only),
            padding: [0; 2],
        }
    }

    fn primary() -> ClientToken {
        ClientToken { token: Token::system(), impersonating: None }
    }

    #[test]
    fn static_tracking_copies_the_client_token() {
        let client = primary();
        let original = client.token.token_id();
        let security = client_security(client, &qos(SECURITY_IMPERSONATION, SECURITY_STATIC_TRACKING, false)).unwrap();
        assert_ne!(security.token.token_id(), original, "a copy");
        assert_eq!(security.token.token_type(), TOKEN_TYPE_IMPERSONATION);
        assert_eq!(
            (security.token.impersonation_level(), security.level),
            (SECURITY_IMPERSONATION, SECURITY_IMPERSONATION)
        );
        assert!(!security.effective_only);
    }

    #[test]
    fn dynamic_tracking_keeps_the_token_itself() {
        let client = primary();
        let token = client.token.clone();
        let security = client_security(client, &qos(SECURITY_IDENTIFICATION, SECURITY_DYNAMIC_TRACKING, true)).unwrap();
        assert!(Arc::ptr_eq(&security.token, &token), "the client's own");
        assert_eq!(security.token.token_type(), TOKEN_TYPE_PRIMARY);
        assert_eq!(security.level, SECURITY_IDENTIFICATION, "the level asked");
        assert!(security.effective_only, "as asked");
    }

    #[test]
    fn an_impersonating_client_limits_the_level() {
        let impersonating = |level: u32, effective_only: bool| ClientToken {
            token: Token::system().duplicate(TOKEN_TYPE_IMPERSONATION, level),
            impersonating: Some((level, effective_only)),
        };
        let dynamic = |level: u32| qos(level, SECURITY_DYNAMIC_TRACKING, false);
        let over = client_security(impersonating(SECURITY_IMPERSONATION, false), &dynamic(SECURITY_DELEGATION));
        assert_eq!(over.err(), Some(STATUS_BAD_IMPERSONATION_LEVEL), "above its own level");
        let low = client_security(impersonating(SECURITY_IDENTIFICATION, false), &dynamic(SECURITY_ANONYMOUS));
        assert_eq!(low.err(), Some(STATUS_BAD_IMPERSONATION_LEVEL), "a client at Identification");
        let kept = client_security(impersonating(SECURITY_DELEGATION, true), &dynamic(SECURITY_IMPERSONATION)).unwrap();
        assert!(kept.effective_only, "its own effective-only, in dynamic tracking");
        let copied = client_security(
            impersonating(SECURITY_DELEGATION, true),
            &qos(SECURITY_IMPERSONATION, SECURITY_STATIC_TRACKING, false),
        )
        .unwrap();
        assert!(!copied.effective_only, "the QoS's, in static tracking");
    }

    #[test]
    fn an_unknown_level_is_refused() {
        let unknown = client_security(primary(), &qos(SECURITY_DELEGATION + 1, SECURITY_STATIC_TRACKING, false));
        assert_eq!(unknown.err(), Some(STATUS_INVALID_PARAMETER));
    }
}
