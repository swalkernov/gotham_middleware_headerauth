/*
 * The contents of this middleware were uniquely written, but the following sources were
 * leaned on heavily as examples:
 *  - https://github.com/gotham-rs/gotham/tree/master/middleware/template (10/11/2021)
 *  - https://github.com/PrivateRookie/gotham-middleware-basicauth (10/11/2021)
 */

//! This is a simple convenience middleware for extracting authentication information
//! when a Gotham framework web service (https://gotham.rs) is sitting behind a separate
//! service (e.g., reverse proxy like Apache) where the separate service performs
//! authentication and populates authentication information into request headers.
//!
//! In normal use, it reads the request headers and puts an `AuthAssertion` into the
//! Gotham state data which can be accessed by request handlers or other middleware.
//!
//! This middleware expects that client restrictions, authentication and firewalling
//! is handled by the reverse proxy and network configuration. However, it includes
//! convenience features for handling unusual or misconfiguration situations.
//!
//! In order of processing:
//! 1. Optionally, if a development mode override is set the AuthAssertion supplied
//!     with that will be put into the Gotham request state data and no further
//!     checks or processing will take place. This to bypass the middleware transparently
//!     during software development.
//! 2. Optionally, if a white list of client IP addresses is supplied and the request
//!     did not come from one of those addresses, the request will fail.
//! 3. If the header for the user id is not present, the request will fail.
//! 4. If an optional name for a header containing a list of group memberships is given
//!     and the header is not present, the request will fail.
//! 5. Otherwise, the AuthAssertion is added to the Gotham request state data.
//!
//! Additionally, if any header values read by this middleware contain non-UTF8 data,
//! the request will fail.
//!
//! Request failure behaviour is amounts to returning a Gotham `HandlerError` chaining
//! a `HeaderAuthMiddlewareError`. You may elect to catch some specific errors and
//! implement a 307 redirect in your application to direct your user to an authentication
//! page.
//!
//! Tip: if testing/developing, you can use browser add-ons like https://mybrowseraddon.com/modify-header-value.html
//! inject headers and simulate output from the authentication reverse proxy.
//!
//! To use this middleware in your code, instantiate a `HeaderAuthMiddleware` and
//! then attach it to your pipeline, e.g., with `new_pipeline().add()`.

#![warn(missing_docs, deprecated)]
#![doc(test(no_crate_inject, attr(deny(warnings))))]
// TODO: Remove this when it's a hard error by default (error E0446).
// See Rust issue #34537 <https://github.com/rust-lang/rust/issues/34537>
#![deny(private_in_public)]

use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr};
use std::pin::Pin;

use futures_util::future::{self, FutureExt};

use gotham::handler::{HandlerError, HandlerFuture};
use gotham::hyper::{HeaderMap, StatusCode};
use gotham::middleware::{Middleware};
use gotham::state::{client_addr, FromState, State};
use gotham_derive::NewMiddleware;
use gotham_derive::StateData;

/// Sources of errors emitted by HeaderAuthMiddleWare.
#[derive(Debug)]
pub enum HeaderAuthMiddlewareError {
    /// Some header data was received as part of the request, but it could not be
    /// parsed because it was in an invalid format.
    DataInvalid,
    /// A header asserting the IP address of the client was expected, however, it was absent from
    /// the request.
    ClientAddressAssertionAbsent,
    /// A header asserting the name of the user was expected, however, it was absent from the
    /// request.
    UserAssertionAbsent,
    /// A header asserting a list of groups that the user is a member of was expected, however, it
    /// was absent from the request.
    GroupAssertionAbsent,
    /// The request did not come from a client in the configured list of white-listed IP addresses.
    ClientAddressNotMatched,
}

impl Display for HeaderAuthMiddlewareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderAuthMiddlewareError::DataInvalid => write!(f, "Invalid Data"),
            HeaderAuthMiddlewareError::ClientAddressAssertionAbsent => write!(f, "Client Address Assertion Absent"),
            HeaderAuthMiddlewareError::UserAssertionAbsent => write!(f, "Auth Assertion Absent"),
            HeaderAuthMiddlewareError::GroupAssertionAbsent => write!(f, "Group Assertion Absent"),
            HeaderAuthMiddlewareError::ClientAddressNotMatched => write!(f, "Client Address Not Matched"),
        }
    }
}

impl std::error::Error for HeaderAuthMiddlewareError {}

/// The struct for the middleware, which holds the configuration for it.
#[derive(NewMiddleware, Clone)]
pub struct HeaderAuthMiddleware {
    /// The name of the HTTP request header which contains the authenticated user ID
    /// supplied by the reverse proxy.
    pub user_id_header: String,

    /// The name of the HTTP request header which contains the list of group memberships
    /// supplied by the reverse proxy.
    pub group_header: Option<String>,

    /// An optional list of IP addresses which act a whitelist for permitted source
    /// addresses. If None, then no source IP addresses are check in requests. If a
    /// list of addresses is provided, then the middleware ensures that the request
    /// came from at one of the addresses on the list, otherwise it will fail the
    /// request.
    pub restrict_source_ips: Option<Vec<IpAddr>>,

    /// For software development only. If set to None, the middleware will behave as
    /// described. Optionally, if an AuthAssertion is provided the middleware will
    /// automatically put the supplied AuthAssertion into the Gotham request state
    /// data. This setting overrides all other settings and behaviours.
    pub dev_mode_override: Option<AuthAssertion>,

    /// If set to true, the middleware will react to request failures by silently
    /// failing and not returning a redirect or an error response. Instead, it will
    /// allow the request to pass but not add an AuthAssertion to the Gotham state.
    /// If set to false, the redirect_url_on_failure value is used to determine the
    /// response to the failure.
    pub silent_fail: bool,
}

/// The AuthAssertion contains the extracted authentication results from the reverse
/// proxy read via request headers.
#[derive(Clone, Debug, StateData)]
pub struct AuthAssertion {
    /// The extracted user id.
    pub user_id: String,

    /// A possible list of groups. If this middleware is configured with group_header set
    /// to None, then group_memberships will be None. Otherwise, it reads a space separated
    /// list of group names and provides them here as a Vec<String>.
    pub group_memberships: Option<Vec<String>>,
}

impl Middleware for HeaderAuthMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Pin<Box<HandlerFuture>>
    where
        Chain: FnOnce(State) -> Pin<Box<HandlerFuture>>,
    {
        //println!("[{}] pre chain", request_id(&state));

        let assertion;
        match &self.dev_mode_override {
            None => {
                // Optionally, check that the request comes from a whitelisted IP
                // address.
                if let Some(white_list) = &self.restrict_source_ips {
                    match client_addr(&state) {
                        None => {
                            // Some requests can come without a client address, so we
                            // reject them when whitelisting of the source of a request
                            // is enabled.
                            return auth_error(HeaderAuthMiddlewareError::ClientAddressAssertionAbsent, state);
                        }
                        Some(addr) => {
                            let client_ip = addr.ip();

                            if !white_list.contains(&client_ip) {
                                return auth_error(HeaderAuthMiddlewareError::ClientAddressNotMatched, state);
                            }
                        }
                    }
                }

                let headers = HeaderMap::borrow_from(&state);

                // Check and extract the user id into the assertion
                let asserted_user_id = if let Some(x) = headers.get(&self.user_id_header) {
                    match x.to_str() {
                        Ok(safe_utf) => {
                            safe_utf
                        }
                        Err(_e) => {
                            // Non-UTF compatible user id
                            return auth_error(HeaderAuthMiddlewareError::DataInvalid, state);
                        }
                    }
                } else {
                    return auth_error(HeaderAuthMiddlewareError::UserAssertionAbsent, state);
                };

                // Bail out - empty string means misconfiguration
                if asserted_user_id.is_empty() {
                    return auth_error(HeaderAuthMiddlewareError::DataInvalid, state);
                }

                // Optionally, check and extract group memberships
                let asserted_groups;
                match &self.group_header {
                    None => {
                        asserted_groups = None;
                    }
                    Some(group_header_name) => {
                        match headers.get(group_header_name) {
                            None => {
                                // A header name for list group memberships was configured, but it
                                // was not found.
                                return auth_error(HeaderAuthMiddlewareError::GroupAssertionAbsent, state);
                            }
                            Some(header_value) => match header_value.to_str() {
                                Ok(membership_list) => {
                                    let split_list = membership_list
                                        .split(' ')
                                        .map(|s| s.to_string())
                                        .collect::<Vec<String>>();
                                    asserted_groups = Some(split_list);
                                }
                                Err(_) => {
                                    return auth_error(HeaderAuthMiddlewareError::DataInvalid, state);
                                }
                            },
                        }
                    }
                }

                // Build the assertion and put it in the state
                assertion = AuthAssertion {
                    user_id: asserted_user_id.to_string(),
                    group_memberships: asserted_groups,
                };
            }
            Some(assertion_override) => {
                assertion = (*assertion_override).clone();
            }
        }

        state.put(assertion);

        chain(state).boxed()
    }
}

fn auth_error(error: HeaderAuthMiddlewareError, state: State) -> Pin<Box<HandlerFuture>> {

    let handler_error = HandlerError::from(error).with_status(StatusCode::UNAUTHORIZED);
    future::err((state, handler_error)).boxed()

}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
