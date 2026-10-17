# Nextcloud Talk for Hermes

A signed-webhook text integration between Hermes Agent and Nextcloud Talk.

- [Plugin documentation, configuration and security contract](plugin/README.md)
- [Changelog](plugin/CHANGES.md)
- [Offline regression tests](tests/test_hardening.py)
- [Catalog submission draft](plugin-catalog/nextcloud-talk.yaml)

The installable plugin lives in `plugin/`; the catalog entry uses `subdir: plugin`.

## Before publication

Review the plugin and run the standalone tests documented in its README. The intended public repository is `Cliff3c/hermes-nextcloud-talk`; after publication, pin the exact reviewed commit in the catalog draft. The draft deliberately has an invalid SHA until a real reviewed commit exists. No catalog approval or installation from a published repository is claimed.

Only the plugin, tests and submission documentation belong in the public repository. The root `.gitignore` uses an allowlist to exclude unrelated workspace files. Inspect the actual Git staging area before committing or publishing.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Cliff3c.
