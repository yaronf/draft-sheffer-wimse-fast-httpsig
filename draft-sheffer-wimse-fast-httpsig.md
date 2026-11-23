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
  SECG1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    author:
      - org: Standards for Efficient Cryptography Group
    date: 2009

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
performs an ephemeral key agreement.
Later messages in the same session are authenticated with HTTP Message Signatures
{{!RFC9421}} using `hmac-sha256` and a transcript-derived session identifier,
optionally with compact tickets.
The WIT is omitted from those messages.

Goals:

* Amortize WIT carriage over many calls between the same workloads.
* Extend the base profile; remain verifiable across TLS-terminating intermediaries, as in the base profile.
* Keep the wire format open to a future post-quantum KEM without a redesign.


# Conventions and Definitions

Terminology follows {{?I-D.ietf-wimse-arch}} and {{I-D.ietf-wimse-http-signature}}.

{::boilerplate bcp14-tagged}


# Overview {#overview}

A session begins with one handshake request and its handshake response,
both signed under the base profile.
The peers run an ephemeral HPKE DHKEM {{!RFC9180}}: the client sends a fresh KEM
public value, and the server returns a KEM ciphertext, both as opaque `wimse-kem`
byte sequences.
Both sides derive two MAC keys (one per direction) and a session identifier using HKDF {{!RFC5869}}.
The server MAY issue an opaque ticket on the handshake response.
The client MAY issue an opaque ticket on its first session request, after key derivation;
see {{ticket}}.
The client confirms possession of the derived keys by MACing its next request.
Further requests and responses use `hmac-sha256` and carry the session identifier;
when tickets were issued, they carry those ticket parameters as well.
There is no session rehandshake: when the session ends, the peers start a new handshake.
A pair of workloads MAY hold concurrent sessions; the session identifier distinguishes them.


# Handshake {#handshake}

The handshake request and response MUST otherwise conform to {{I-D.ietf-wimse-http-signature}},
including WIT validation and the `wimse-workload-to-workload` tag.
The handshake response MUST be signed.
Clients that require this extension MUST include `wimse-sign-response` on the handshake request.

## Key Agreement

The mandatory KEM suite is DHKEM(P-256, HKDF-SHA256) as defined in {{!RFC9180}}.
The suite identifier on the wire is the string `dhkem-p256-hkdf-sha256`.
Other suites are not defined by this document; the parameters below are designed so a later
document can add them without changing message layout.

The handshake uses one DHKEM operation with a fresh key pair on each side
({{Section 4.1 of RFC9180}}).
In HPKE/DHKEM terms the client is the recipient and the server encapsulates to the
client's public key:

* The client generates an ephemeral P-256 recipient key pair `(skR, pkR)`.
* The server runs `Encap(pkR)`, which generates an ephemeral key pair `(skE, pkE)`
  and returns `(shared_secret, enc)` with `enc = SerializePublicKey(pkE)`.
* The client runs `Decap(enc, skR)` and obtains the same `shared_secret`.

For this suite, `SerializePublicKey` is the uncompressed SEC 1 {{SECG1}} point encoding
(`0x04 || X || Y`, 65 octets).
Both `pkR` and `enc` use that encoding.
Peers MUST validate KEM public-key inputs as required for DHKEM(P-256, HKDF-SHA256) in
{{Section 7.1.4 of RFC9180}} before `Encap` or `Decap`.

The handshake request MUST include the signature parameters:

* `wimse-kem-suite`: String; MUST be `dhkem-p256-hkdf-sha256`.
* `wimse-kem`: Byte Sequence; `SerializePublicKey(pkR)`.

The handshake request MUST NOT include `wimse-ticket-client` or `wimse-ticket-server`.

The handshake response MUST include:

* `wimse-kem-suite`: String; MUST equal the request's suite.
* `wimse-kem`: Byte Sequence; `enc` from `Encap(pkR)`.

The handshake response MAY also include `wimse-ticket-server`; see {{ticket}}.
The handshake response MUST NOT include `wimse-ticket-client`.

Those parameters are covered by `@signature-params` as usual for {{RFC9421}}.
The private key associated with the WIT is used only to sign.
It MUST NOT be used as a KEM key.


# Key Derivation {#key-derivation}

Both sides compute:

~~~
PRK = HKDF-Extract(salt=32 zero octets, IKM=shared_secret)
info = "wimse-httpsig-session" || 0x00 ||
       suite || 0x00 ||
       req_nonce || 0x00 || resp_nonce || 0x00 ||
       SHA-256(client_WIT) ||
       SHA-256(server_WIT)
OKM = HKDF-Expand(PRK, info, 80)
k_req = OKM[0..31]
k_res = OKM[32..63]
session_id = OKM[64..79]
~~~

where:

* `shared_secret` is the DHKEM output of `Encap` / `Decap` from {{handshake}}.
* `suite` is the ASCII suite identifier.
* `req_nonce` / `resp_nonce` are the parsed handshake `nonce` values
  ({{Section 2.3 of RFC9421}}) as ASCII octets and without the surrounding quotes.
* `client_WIT` / `server_WIT` are the handshake request and response
  `Workload-Identity-Token` header field values (compact JWS serialization),
  as ASCII octets.
* `SHA-256(...)` denotes the 32-octet SHA-256 hash of those octets.

`k_req` MACs session requests.
`k_res` MACs session responses.
`session_id` is the session identifier carried as `wimse-session-id` in {{session}}.
Both peers compute it from the handshake transcript; it is not sent on the handshake.


# Session Messages {#session}

After the handshake response, messages MAY use a session signature instead of a WIT signature.

Session messages MUST NOT carry a Workload Identity Token or a `Workload-Identity-Token` header.

A session signature on a request or response:

* MUST use `tag` = `wimse-httpsig-session`.
* MUST use the HTTP Message Signatures algorithm `hmac-sha256`.
* MUST include `wimse-session-id`: Byte Sequence; the `session_id` value computed in
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
`wimse-session-id` identifies the session; see {{session}} and {{key-derivation}}.
A peer that keeps session keys in local (or shared) state keyed by `session_id`
MAY omit its ticket.
A ticket is useful when a replica of that issuer must recover session keys without that
shared state.

This document defines two signature parameters, each an opaque Byte Sequence:

* `wimse-ticket-client`: issued by the client; only the client deployment opens it.
* `wimse-ticket-server`: issued by the server; only the server deployment opens it.

Issuance happens only after the issuer can populate the ticket with derived session
material; see {{key-derivation}} and {{lifetime}}:

* The server MAY include `wimse-ticket-server` on the handshake response.
* The client MUST NOT include `wimse-ticket-client` on the handshake request.
  The client MAY include `wimse-ticket-client` on a session request after key derivation
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
* `session_exp`,
* KEM suite identifier.

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
base profile. Some values are
truncated for readability.

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

An attacker that breaks P-256 ECDH for a recorded handshake can forge session MACs
until `session_exp`; see {{lifetime}}.
Authentication of the handshake itself remains the WIT signature algorithms
(`ES256`, `Ed25519`, and others allowed by {{I-D.ietf-wimse-workload-creds}}).
Those algorithms are not post-quantum.
This document's suite identifier and opaque `wimse-kem` layout are intended so a
future KEM can harden the session secret without changing the message pattern;
that does not by itself make workload authentication post-quantum.

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

`session_id` is derived from the same PRK as the MAC keys but is carried in cleartext.
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
* Description: String; KEM suite identifier for a WIMSE fast HTTP signature handshake.
* Reference: RFC XXX, {{handshake}}.

### `wimse-kem`

* Name: `wimse-kem`
* Description: Byte Sequence; ephemeral KEM public share for a WIMSE fast HTTP signature handshake.
* Reference: RFC XXX, {{handshake}}.

### `wimse-session-id`

* Name: `wimse-session-id`
* Description: Byte Sequence; transcript-derived session identifier for WIMSE fast HTTP
  signature session messages.
* Reference: RFC XXX, {{key-derivation}}, {{session}}.

### `wimse-ticket-client`

* Name: `wimse-ticket-client`
* Description: Byte Sequence; optional opaque client-issued session ticket for WIMSE fast
  HTTP signature session messages (issued after key derivation).
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
