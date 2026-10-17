# Changelog

## 0.2.1

- Accept the Hermes keyword-only `connect(*, is_reconnect=False)` lifecycle argument; retain idempotent connection behavior and clean reconnection after shutdown.
- Support Nextcloud 32 XML OCS responses alongside JSON, including successful empty acknowledgements without a returned message ID.
- Report empty acknowledgement IDs as `None`, not a synthetic `"0"`. Continue rejecting missing data fields, invalid IDs and malformed nonempty acknowledgements.
- Bound XML responses, reject DTDs/entities and ambiguous envelopes, and turn XML parse errors into controlled unconfirmed-send results without retrying the POST.
- Normalize XML room-type metadata and preserve lookup failure backoff.
- Add offline reconnect, XML success/error, empty acknowledgement, entity rejection and metadata regression coverage.
- Generalize public documentation, make the test SDK path configurable and add a catalog submission manifest.

## 0.2.0

- Authenticate before bounded nonce/event dedupe; release reservations after failed gateway admission.
- Validate headers and message shapes; filter bot actors by default with configurable opt-in and explicit metadata.
- Preserve standard Hermes authorization and command dispatch, including inline command admission receipts.
- Use profile-scoped configuration and secrets, lifecycle-owned HTTP sessions, explicit deadlines, exclusive listeners and partial-start cleanup.
- Validate OCS acknowledgements without blind uncertain-send retries or plain-text fallback.
- Cache room metadata with bounded storage and failure backoff; allow operation without metadata credentials.
- Add standalone, isolated tests against the real Hermes SDK and loopback HTTP servers.

Compatibility notes: bot messages are ignored by default; malformed/plain-text nested content is rejected; disconnected sends fail; each adapter uses a single bot secret. Dedupe remains bounded, in-memory and non-durable.
