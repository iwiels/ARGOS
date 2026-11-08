# Upstream provenance

Argos is derived in part from [OpenCode](https://github.com/sst/opencode), which is distributed under the MIT License. Argos preserves the upstream copyright and license notices; see [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Argos-specific changes and components are also distributed under the terms in [LICENSE](LICENSE), except where a separate third-party license applies.

Some inherited internal identifiers still use the `opencode` name for storage, protocol, environment-variable, or migration compatibility. Those identifiers do not change the product name. Renaming them requires an explicit compatibility and migration plan.

## Upstream maintenance

- Review security advisories and fixes that affect retained upstream code before preparing a release.
- Apply relevant security fixes while preserving upstream notices.
- Evaluate upstream features and broad refactors individually; they are not synchronized automatically.
- Keep Argos-specific functionality in its own modules where practical so provenance and future maintenance remain understandable.

This file records source provenance and maintenance policy; it does not claim that Argos tracks every upstream release.
