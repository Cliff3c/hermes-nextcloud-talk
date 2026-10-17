# Nextcloud Talk for Hermes

A community platform adapter connecting [Hermes Agent](https://hermes-agent.nousresearch.com/) to Nextcloud Talk through signed bot webhooks. Version **0.2.1**.

## Features

- Receive human text messages and send signed bot replies, including outbound `replyTo`.
- Preserve Hermes authorization, session handling and standard gateway commands.
- Ignore bot actors by default; optionally forward them with bot metadata.
- Authenticate before replay tracking; bound nonce/event caches and retry failed gateway admission.
- Support JSON OCS responses and the XML/empty acknowledgements returned by Nextcloud 32.
- Support the Hermes `connect(*, is_reconnect=False)` lifecycle contract.
- Use profile-scoped secrets, explicit HTTP timeouts, exclusive listener ownership and clean shutdown.

**Text only:** attachments, reactions and inbound reply-context reconstruction are not implemented. Rich-object placeholders remain text. This is an independent community integration, not an official Nextcloud product.

## Requirements

- Hermes with the platform adapter API, scoped secret helpers, admission receipts and base send retry hooks. Run the offline tests against the Hermes version you intend to use; no minimum version is claimed without verification.
- `aiohttp>=3.9,<4` in the **Hermes Python environment**.
- A Nextcloud Talk installation supporting bots, administrative access for bot registration, and an HTTPS callback URL reachable by Nextcloud.

## Installation and configuration

This repository's installable plugin is the `plugin/` directory, not the repository root. For a manual installation, copy that directory as `nextcloud-talk` under the intended Hermes profile's `plugins/` directory. Install its declared dependencies in Hermes's environment. Do not run two copies of the same bot identity. Back up an existing installation before replacing it.

Once this repository is published, obtain the source with:

```sh
git clone https://github.com/Cliff3c/hermes-nextcloud-talk.git
cd hermes-nextcloud-talk
```

Review the source and select a reviewed commit before installation. Follow the manual installation procedure above; do not overwrite an existing live installation without a backup and maintenance window. The catalog draft is not an installable catalog entry yet.

Configure secrets through Hermes's owning-profile secret configuration. Do not commit credentials. The registered platform ID is **`nextcloud_talk`**; the plugin/catalog name is **`nextcloud-talk`**. The owning profile's environment takes precedence over the corresponding `PlatformConfig.extra` values.

| Environment variable | `extra` key | Purpose / default |
|---|---|---|
| `NC_TALK_BASE_URL` | `base_url` | Required Nextcloud base URL, e.g. `https://cloud.example.com` |
| `NC_TALK_BOT_SECRET` | `bot_secret` | Required shared secret for the registered Talk bot |
| `NC_TALK_WEBHOOK_HOST` | `webhook_host` | Bind address: `0.0.0.0`; prefer `127.0.0.1` behind a local reverse proxy |
| `NC_TALK_WEBHOOK_PORT` | `webhook_port` | Listener port: `8788` |
| `NC_TALK_WEBHOOK_PATH` | `webhook_path` | Callback path: `/nextcloud-talk-webhook` |
| `NC_TALK_IGNORE_BOTS` | `ignore_bots` | `true`; set `false` to forward bot actors |
| `NC_TALK_API_USER` | `api_user` | Optional Nextcloud account for room-type lookup |
| `NC_TALK_API_PASSWORD` | `api_password` | Optional app password for that account |
| `NC_TALK_HOME_ROOM` | — | Optional room token for default scheduled delivery |

1. Register and enable the bot for a test room using the [Nextcloud Talk bot instructions](https://nextcloud-talk.readthedocs.io/en/latest/bots/). Consult `occ help talk:bot:install` for the options supported by your server version.
2. Configure the same bot secret in the owning Hermes profile. One adapter uses one bot secret for both directions.
3. Route the HTTPS callback to the configured listener/path. Preserve the request body and inbound `X-Nextcloud-Talk-Random` / `X-Nextcloud-Talk-Signature` headers unchanged. The `X-Nextcloud-Talk-Bot-*` headers are used for outbound bot replies, not inbound webhooks. Do not expose the plain HTTP listener directly to the Internet.
4. Enable the platform in Hermes and configure the gateway's normal user authorization rules. Human actor IDs lose only their leading `users/` prefix; guest and bot namespaces remain intact.
5. Start or reload the gateway during your own maintenance window. Test a human message and `/help` in the dedicated room before broadening access.

Optional room metadata credentials distinguish direct chats from group rooms. Without them, or on lookup failure, the adapter safely treats rooms as groups. Bot opt-in does not override Hermes's own authorization/bot policy. Automation posted through an ordinary human account still appears human.

## Delivery and security contract

- Inbound HMAC-SHA256 signs **random + raw body**. Authentication precedes replay mutation. Malformed authentication headers return 401; signed malformed JSON/message shapes return 400. Request/response bodies are limited to 1 MiB.
- Nonces are opaque 32–256 visible-ASCII characters, not necessarily hexadecimal. Nonce and `(room, message ID)` caches hold at most 4096 entries each, with 5-minute and 1-hour lifetimes. At most 128 handoffs may be pending.
- Failed gateway admission releases reservations for retry; pending duplicates return 503. A 200 means admission or deliberate filtering, **not completion of an agent response**. Caches are in-memory: expiry, eviction or restart can permit redelivery. This is not exactly-once delivery, and a 503 cannot force the sender to retry.
- Outbound HMAC signs **random + message text**. Confirmation requires HTTP 200/201 and a valid OCS success envelope (`status=ok`, code 100/200/201). Returned IDs must be positive decimal IDs. A valid explicit empty acknowledgement is confirmed with `message_id=None`; no ID is invented. Missing or malformed fields remain unconfirmed.
- XML responses are size-limited and reject DTDs/entities and ambiguous envelope fields. JSON remains supported. XML room-type values are normalized before validation.
- Uncertain sends are **not automatically retried** and have no plain-text fallback. Timeouts or malformed acknowledgements may follow an actual delivery; check the destination before manually resending. HTTP 4xx is rejected; transport errors, 5xx and redirects are conservatively unknown.
- One lifecycle-owned HTTP session uses a 20-second outbound deadline (5-second connect, 15-second read). Metadata lookup has a 5-second deadline, a bounded 15-minute cache and 30–300-second failure backoff. Redirects and ambient proxy credentials are disabled. Listener sharing via `reuse_port` is disabled.

### Runtime disclosure

The adapter runs an HTTP webhook listener while connected and makes requests to the configured Nextcloud server for messages and optional room metadata. Use an **HTTPS `NC_TALK_BASE_URL` in production**, especially when optional account credentials are configured: HTTP does not encrypt messages or those credentials. The adapter accepts HTTP for local development and loopback tests; it does not enforce HTTPS. Protect the inbound listener with an HTTPS reverse proxy as described above.

It reads configuration and scoped credentials through Hermes helpers, and uses Hermes's bot-identity lock mechanism. It does not run shell commands, inspect external credential stores, self-update, or send telemetry. Messages handed to Hermes remain subject to Hermes's configured model/provider and logging policies; installing this adapter does not make model processing local.

## Offline verification

From the repository root, use the Python environment containing Hermes and its dependencies:

```sh
python -B -W error::ResourceWarning tests/test_hardening.py
python -B tests/check_package.py
```

If the Hermes source checkout is not importable from that interpreter, supply its location explicitly:

```sh
HERMES_SOURCE=/path/to/hermes-agent python -B -W error::ResourceWarning tests/test_hardening.py
HERMES_SOURCE=/path/to/hermes-agent python -B tests/check_package.py
```

The standalone suite imports the real SDK and registers through `PluginContext`. It replaces the environment before Hermes imports, uses temporary profile/lock state, disables bytecode writes and denies non-loopback socket/DNS traffic. All HTTP servers and credentials are local synthetic fixtures. No models, production sends or full Hermes test suite are involved.

`check_package.py` checks syntax and package/catalog metadata only. Run the dependency-aware Hermes validator as a separate release gate in an isolated development environment:

```sh
hermes plugins validate ./plugin --install-deps --json
```

This command may download and install dependencies and executes a registration probe. Do not run dependency-install validation in a production runtime. A successful local validator result is not catalog acceptance or a live Nextcloud test.

Coverage includes signed/malformed requests, replay and event dedupe, human/bot behavior, commands, failed admission retries, OCS validation, NC 32 XML and empty acknowledgements, malformed XML/DTD rejection, metadata backoff, timeouts, keyword reconnect and session cleanup. Offline tests do not establish end-to-end compatibility with every Nextcloud/reverse-proxy deployment.

## Troubleshooting

- **Webhook receives 401:** check the bot secret and ensure the proxy preserves the signed raw body and headers.
- **Webhook arrives but no reply:** check Hermes authorization, bot filtering and gateway handler readiness. Inspect gateway logs without exposing secrets or signed request bodies.
- **Delivery unconfirmed:** check the room before resending. Do not enable blind POST retries.
- **Room appears as a group:** configure optional metadata credentials if DM classification is required; check account permissions and allow failure backoff to expire.
- **Listener fails to start:** check port ownership, bind address and duplicate bot instances. Do not enable shared-port binding as a workaround.

## Catalog submission

`../plugin-catalog/nextcloud-talk.yaml` is the catalog submission manifest. It pins a reviewed 40-character source commit and uses `subdir: plugin` to preserve this repository layout. This project is MIT licensed; see `../LICENSE`. Follow the [Hermes catalog submission guide](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission); do not advertise catalog installation until the entry has been accepted.
