---
title: "Fast HTTP Message Signatures for WIMSE"
abbrev: "WIMSE Fast HTTPSig"
category: std

docname: draft-sheffer-wimse-fast-httpsig-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "Workload Identity in Multi System Environments"
keyword:
 - workload
 - identity
 - HTTP Message Signatures
venue:
  group: "Workload Identity in Multi System Environments"
  type: "Working Group"
  mail: "wimse@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/wimse/"
  github: "yaronf/draft-sheffer-wimse-fast-httpsig"
  latest: "https://yaronf.github.io/draft-sheffer-wimse-fast-httpsig/draft-sheffer-wimse-fast-httpsig.html"

author:
 -
    fullname: "Yaron Sheffer"
    organization: Independent
    email: "yaronf.ietf@gmail.com"
 -
    fullname: "Joe Salowey"
    organization: "Palo Alto Networks"
    email: "joe@salowey.net"

informative:
  IANA.HTTP.MESSAGE.SIGNATURE:
    title: "HTTP Message Signature"
    target: https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-metadata-parameters

--- abstract

The WIMSE HTTP Message Signatures profile authenticates each HTTP request
with a Workload Identity Token (WIT) and an asymmetric signature.
Carrying and validating the WIT dominates that cost.
This document defines an optional extension that reduces that cost:
peers run a short handshake to establish shared MAC keys, then authenticate
later requests and responses between the same workloads without the WIT.


--- middle

# Introduction

{{!I-D.ietf-wimse-http-signature}} protects each HTTP message with a WIT
{{!I-D.ietf-wimse-workload-creds}} and a signature under the private key associated with the WIT.
The WIT is large relative to typical service requests.
Asymmetric verification is secondary to that byte and parsing cost.

This document defines an optional extension of that profile.
The peers run one WIT-authenticated request/response exchange that also
performs an ephemeral key establishment.
Later messages in the same session are authenticated with HTTP Message Signatures
{{!RFC9421}} using `hmac-sha256` and an HPKE-exported session identifier,
optionally with compact tickets.
The WIT is omitted from those messages.

Goals:

* Amortize WIT carriage and asymmetric signature and verification over many
  calls between the same workloads.
* Extend the base profile; remain verifiable across TLS-terminating intermediaries, as in the base profile.
* Keep the wire format open to a future post-quantum KEM without a redesign.


# Conventions and Definitions

Terminology follows {{?I-D.ietf-wimse-arch}} and {{I-D.ietf-wimse-http-signature}}.

{::boilerplate bcp14-tagged}


# Overview {#overview}

A session begins with one handshake request and its handshake response,
both signed under the base profile.
The peers run HPKE {{!RFC9180}} in Base mode and use only the Export interface:
the client is the HPKE recipient and sends an ephemeral recipient public key;
the server is the HPKE sender and returns the encapsulated key `enc`.
Both values are opaque `wimse-kem` byte sequences.
Both sides export two MAC keys (one per direction) and a session identifier from
the HPKE context.
The server MAY issue an opaque ticket on the handshake response.
The client MAY issue an opaque ticket on its first session request, after key export;
see {{ticket}}.
The client confirms possession of the exported keys by MACing its next request.
Further requests and responses use `hmac-sha256` and carry the session identifier;
when tickets were issued, they carry those ticket parameters as well.
There is no session rehandshake: when the session ends, the peers start a new handshake.
A pair of workloads MAY hold concurrent sessions; the session identifier distinguishes them.


# Handshake {#handshake}

The handshake request and response MUST otherwise conform to {{I-D.ietf-wimse-http-signature}},
including WIT validation and the `wimse-workload-to-workload` tag.
The handshake response MUST be signed.
Clients that require this extension MUST include `wimse-sign-response` on the handshake request.

## Key Establishment

The handshake uses HPKE {{!RFC9180}} in Base mode
({{Section 5.1.1 of RFC9180}}) and obtains session secrets only through the Export
interface ({{Section 5.3 of RFC9180}}).

An HPKE ciphersuite is the triple `(kem_id, kdf_id, aead_id)` of two-octet identifiers
from {{RFC9180}}.
The mandatory ciphersuite is:

* `kem_id` = `0x0010` (DHKEM(P-256, HKDF-SHA256)),
* `kdf_id` = `0x0001` (HKDF-SHA256),
* `aead_id` = `0xFFFF` (Export-Only) ({{Section 7.3 of RFC9180}}).

On the wire, that triple is the six-octet sequence
`I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`
({{Section 4 of RFC9180}}, big-endian).
Other ciphersuites are not defined by this document; the parameters below are designed so a
later document can add them without changing message layout.

Both sides use the same HPKE `info` value:

~~~
info = "wimse-httpsig-session" || 0x00 ||
       suite || 0x00 ||
       req_nonce || 0x00 || resp_nonce || 0x00 ||
       SHA-256(client_WIT) ||
       SHA-256(server_WIT)
~~~

where:

* `suite` is the six-octet ciphersuite value from `wimse-kem-suite`.
* `req_nonce` / `resp_nonce` are the parsed handshake `nonce` values
  ({{Section 2.3 of RFC9421}}) as UTF-8 octets and without the surrounding quotes.
* `client_WIT` / `server_WIT` are the handshake request and response
  `Workload-Identity-Token` header field values (JWTs), as ASCII octets.
* `SHA-256(...)` denotes the 32-octet SHA-256 hash of those octets.

The server constructs `info` when creating the handshake response (it chooses
`resp_nonce` and knows both WIT values).
The client constructs the same `info` after receiving that response.

The client is the HPKE recipient and the server is the HPKE sender:

* The client runs `GenerateKeyPair()` and obtains a recipient key pair `(skR, pkR)`.
* When generating the handshake response, the server runs `SetupBaseS(pkR, info)`,
  which returns `(enc, context_S)`.
* After receiving that response, the client runs `SetupBaseR(enc, skR, info)` and
  obtains `context_R`.
* Both sides export session secrets from their context as specified in {{key-derivation}}.

Public keys and `enc` are encoded as specified by the selected HPKE KEM.
Peers MUST validate KEM public-key inputs as required by the selected HPKE KEM
before `SetupBaseS` or `SetupBaseR`.
For the mandatory suite, that validation is {{Section 7.1.4 of RFC9180}}.

The handshake request MUST include the signature parameters:

* `wimse-kem-suite`: Byte Sequence; MUST be the six octets
  `0x00 0x10 0x00 0x01 0xFF 0xFF`.
* `wimse-kem`: Byte Sequence; the serialized recipient public key `pkR`.

The handshake request MUST NOT include `wimse-ticket-client` or `wimse-ticket-server`.

The handshake response MUST include:

* `wimse-kem-suite`: Byte Sequence; MUST equal the request's `wimse-kem-suite`.
* `wimse-kem`: Byte Sequence; `enc` from `SetupBaseS(pkR, info)`.

The handshake response MAY also include `wimse-ticket-server`; see {{ticket}}.
The handshake response MUST NOT include `wimse-ticket-client`.

Those parameters are covered by `@signature-params` as usual for {{RFC9421}}.
The private key associated with the WIT is used only to sign.
It MUST NOT be used as an HPKE recipient key.


# Key Export {#key-derivation}

Both sides export MAC keys and a session identifier from the HPKE context
established in {{handshake}}:

~~~
OKM = Context.Export("session-keys", 80)
k_req = OKM[0..31]
k_res = OKM[32..63]
session_id = OKM[64..79]
~~~

where:

* `Context` is `context_S` on the server and `context_R` on the client.
* `Context.Export` is the HPKE secret export interface
  ({{Section 5.3 of RFC9180}}) with `exporter_context` equal to the ASCII string
  `session-keys`.

`k_req` MACs session requests.
`k_res` MACs session responses.
`session_id` is the session identifier carried as `wimse-session-id` in {{session}}.
Both peers compute it from the HPKE export; it is not sent on the handshake.


# Session Messages {#session}

After the handshake response, messages MAY use a session signature instead of a WIT signature.

Session messages MUST NOT carry a Workload Identity Token or a `Workload-Identity-Token` header.

A session signature on a request or response:

* MUST use `tag` = `wimse-httpsig-session`.
* MUST use the HTTP Message Signatures algorithm `hmac-sha256`.
* MUST include `wimse-session-id`: Byte Sequence; the `session_id` value exported in
  {{key-derivation}}.
* Ticket parameters follow {{ticket}}: `wimse-ticket-server` when established on the
  handshake response; `wimse-ticket-client` when established on a prior or current
  session request.
* MUST include the same signature parameters as the base profile for requests or responses,
  as applicable; `expires` MUST NOT be after the bound in {{lifetime}}.
* MUST cover the same components as the base profile for requests or responses, as applicable,
  except that `Workload-Identity-Token` is not covered because it is absent.
* MUST NOT be combined with a `wimse-workload-to-workload` signature on the same message.

The sender MACs requests with `k_req` and responses with `k_res`.
The recipient selects the session with `wimse-session-id`.
A client replica MAY open `wimse-ticket-client` to obtain MAC keys; a server replica MAY open
`wimse-ticket-server` (see {{ticket}}).
Otherwise the recipient looks up MAC keys from local session state keyed by
`wimse-session-id`.
The recipient verifies accordingly.

Recipients recognize a WIMSE session signature solely by `tag` = `wimse-httpsig-session`.
If more than one signature has that tag, the recipient MUST reject the message.


# Session Lifetime {#lifetime}

Let `session_exp` be the earlier of the two handshake WIT `exp` values.
Peers MUST NOT use `k_req` or `k_res` after `session_exp`.
Senders MUST NOT set `expires` after `session_exp`.
Recipients MUST reject a session signature if `expires` is after `session_exp`,
or if the current time is after `session_exp`.
Comparisons against `session_exp` use the same clock-skew policy the deployment
applies when validating WIT `exp` claims {{I-D.ietf-wimse-workload-creds}}.

Per-message `expires` remains as in the base profile and is typically much shorter.
`session_exp` only caps how long handshake authority may be reused as MAC keys.

This document does not define rehandshake inside a session.
Peers that need a fresh session run a new handshake.
Each session has its own `session_id`, key material, and, when issued, its own tickets.


# Tickets {#ticket}

Tickets are optional per session and issuer-specific.
`wimse-session-id` identifies the session on the wire in {{session}};
its value is exported in {{key-derivation}}.
A peer that keeps session keys in local (or shared) state keyed by `session_id`
MAY omit its ticket.
A ticket is useful when a replica of that issuer must recover session keys without that
shared state.

This document defines two signature parameters, each an opaque Byte Sequence:

* `wimse-ticket-client`: issued by the client; only the client deployment opens it.
* `wimse-ticket-server`: issued by the server; only the server deployment opens it.

Issuance happens only after the issuer can populate the ticket with the exported
MAC keys ({{key-derivation}}) and `session_exp` ({{lifetime}}):

* The server MAY include `wimse-ticket-server` on the handshake response.
* The client MUST NOT include `wimse-ticket-client` on the handshake request.
  The client MAY include `wimse-ticket-client` on a session request after key export
  (typically the first session request).
* Once `wimse-ticket-server` has been established, session requests and responses MUST
  echo that same value and MUST NOT change it for the rest of the session.
* Once the client has sent `wimse-ticket-client`, later session requests MUST echo that
  same value and MUST NOT change it for the rest of the session.
* A session response MUST echo `wimse-ticket-client` when the corresponding request
  carried it, using that same value.
  Concurrent requests may still be in flight without the ticket when another request
  first establishes it; a response to a request that omitted `wimse-ticket-client` MAY
  omit it.
* Senders MUST NOT include a ticket parameter that has not been established.

A peer that already has the keys from {{key-derivation}} (or from local session state)
need not open a ticket; it only echoes parameters it must carry.

This document does not specify ticket format or how each deployment manages
ticket-opening keys.
Those keys are not shared across the two deployments.
When a ticket carries session key material, the issuer MUST protect that material with
authenticated encryption, or with equivalent confidentiality and integrity protection,
under keys known only to that deployment.

A ticket implementation needs enough data for a replica of the issuing peer to obtain
`k_req` and `k_res` and to enforce {{lifetime}}.
The following content is RECOMMENDED inside the protected ticket material:

* `session_id`,
* `k_req` and `k_res` (or equivalent key material),
* client and server `sub` values,
* `wimse-aud`,
* `session_exp`.

A recipient that uses a ticket to obtain keys MUST reject it if the ticket cannot be
decoded or authenticated under current local policy.
If a session message carries `wimse-session-id` and an opened ticket decodes to a
different `session_id`, the recipient MUST reject the message.


# Negotiating the Extension {#negotiate}

Unknown signature parameters do not by themselves fail {{RFC9421}} verification,
and {{I-D.ietf-wimse-http-signature}} does not require rejecting them.
A base-profile-only server may therefore accept a request that carries `wimse-kem-suite`
and `wimse-kem` while ignoring those parameters.

The client treats the extension as negotiated only if the handshake response includes
`wimse-kem-suite` and `wimse-kem` as required in {{handshake}}.
Otherwise the client MUST NOT use session signatures from this exchange and continues
with the base profile.


# Examples {#examples}

The following messages illustrate one handshake and the first session exchange
between the same peers.
The `nonce` values are illustrative and do not meet the entropy requirement of the
base profile. Some values are truncated for readability.

~~~ http
{::include includes/fast-hs-request.txt.out}
~~~
{: title="Handshake Request"}

~~~ http
{::include includes/fast-hs-response.txt.out}
~~~
{: title="Handshake Response"}

~~~ http
{::include includes/fast-sess-request.txt.out}
~~~
{: title="Session Request"}

~~~ http
{::include includes/fast-sess-response.txt.out}
~~~
{: title="Session Response"}


# Security Considerations {#security}

The base profile's considerations in {{I-D.ietf-wimse-http-signature}} apply to the handshake.

An attacker that breaks the HPKE KEM for a recorded handshake can forge session MACs
until `session_exp`; see {{lifetime}}.
Authentication of the handshake itself remains the WIT signature algorithms
(`ES256`, `Ed25519`, and others allowed by {{I-D.ietf-wimse-workload-creds}}).
Those algorithms are not post-quantum.
This document's HPKE ciphersuite codepoints and opaque `wimse-kem` layout are intended
so a future HPKE KEM can harden the exported session secret without changing the message
pattern; that does not by itself make workload authentication post-quantum.

HPKE export secrets are determined by the HPKE context.
A replayed `enc` with the same `info` yields the same exported keys
({{Section 5.3 of RFC9180}}).
The WIT-signed handshake and its `nonce` values bind that context to a single
authenticated exchange; session-message `nonce` values still apply as in the base
profile.

The first session request is the client's key-confirmation message.
A peer that sees only the handshake response may not hold `k_req`.

Separate ticket issuers confine minting: an opening key for one deployment does not
open the other deployment's tickets.
Whoever can mint tickets for a deployment can forge session MACs that its replicas
accept after opening the ticket.

A recommended ticket carries both `k_req` and `k_res`.
An attacker who opens a captured ticket recovers both MAC keys and can forge to either
peer, including one that uses ordinary session state.
Retained old opening keys keep previously issued tickets openable, which defeats
forward secrecy for the enclosed MAC keys until `session_exp`.
Rotate opening keys at least as often as the maximum WIT lifetime the deployment
accepts, and minimize retention of old keys.

Session messages omit the WIT.
Revocation or status checks that require the WIT apply at handshake time only.
After that, authority to speak in the session is carried by the MAC keys
and `wimse-session-id` until `session_exp`; see {{lifetime}}.

`session_id` is taken from the same Export output as the MAC keys but is carried in
cleartext.
It identifies the session; it is not a secret authenticator.
Possession of `session_id` alone does not allow forging session MACs.

Replay of session messages is unchanged from the base profile:
`nonce` and optional replay caches help, and caches that are not shared across replicas
leave cross-replica replay possible.

TLS-terminating intermediaries see `wimse-session-id`, ticket parameters (when present),
and MAC values in cleartext.
With the ticket protection required in {{ticket}}, they see ciphertext rather than
`k_req` and `k_res`.
They cannot alter covered components without failing verification.
They can attempt capture-and-replay within `expires`.


# IANA Considerations {#iana}

## HTTP Signature Metadata Parameters

IANA is requested to register the following entries in the
"HTTP Signature Metadata Parameters" registry {{IANA.HTTP.MESSAGE.SIGNATURE}},
per {{Section 6.3.1 of RFC9421}}:

### `wimse-kem-suite`

* Name: `wimse-kem-suite`
* Description: Byte Sequence; HPKE ciphersuite `kem_id || kdf_id || aead_id` for a WIMSE
  fast HTTP signature handshake.
* Reference: RFC XXX, {{handshake}}.

### `wimse-kem`

* Name: `wimse-kem`
* Description: Byte Sequence; HPKE recipient public key on the handshake request, or HPKE
  `enc` on the handshake response.
* Reference: RFC XXX, {{handshake}}.

### `wimse-session-id`

* Name: `wimse-session-id`
* Description: Byte Sequence; HPKE-exported session identifier for WIMSE fast HTTP
  signature session messages.
* Reference: RFC XXX, {{key-derivation}}, {{session}}.

### `wimse-ticket-client`

* Name: `wimse-ticket-client`
* Description: Byte Sequence; optional opaque client-issued session ticket for WIMSE fast
  HTTP signature session messages (issued after key export).
* Reference: RFC XXX, {{ticket}}.

### `wimse-ticket-server`

* Name: `wimse-ticket-server`
* Description: Byte Sequence; optional opaque server-issued session ticket for WIMSE fast
  HTTP signature handshake responses and session messages.
* Reference: RFC XXX, {{ticket}}.


# Open Issues {#open-issues}

* Error responses when the ticket is rejected and when session MAC verification fails.
* Whether a session needs an explicit cleanup hint so peers can drop ticket and MAC state
  before `session_exp` (see {{lifetime}}), rather than waiting for that bound alone.


--- back

# Document History
<cref>RFC Editor: please remove before publication.</cref>

## draft-sheffer-wimse-fast-httpsig-00

* Initial version.

# Acknowledgments
{:numbered="false"}

TODO.
