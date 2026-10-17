# Nextcloud Talk for Hermes

A signed-webhook text integration between Hermes Agent and Nextcloud Talk.

- [Plugin documentation, configuration and security contract](plugin/README.md)
- [Changelog](plugin/CHANGES.md)
- [Offline regression tests](tests/test_hardening.py)
- [Catalog submission manifest](plugin-catalog/nextcloud-talk.yaml)

The installable plugin lives in `plugin/`; the catalog entry uses `subdir: plugin`.

## Publication and catalog status

This repository is published. Review the plugin and run the standalone tests documented in its README before proposing changes. `plugin-catalog/nextcloud-talk.yaml` pins an exact reviewed source commit for the Hermes catalog submission; catalog availability still requires review and merge by a Hermes maintainer. Until that happens, no catalog installation or approval is claimed.

Only the plugin, tests and submission documentation belong in the public repository. The root `.gitignore` uses an allowlist to exclude unrelated workspace files. Inspect the actual Git staging area before committing or publishing.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Cliff3c.
