# Releasing

This project publishes the `ksf` Go library following Semantic Versioning. Releases are coordinated via GitHub pull requests and automated GitHub Actions workflows.

## Release Checklist

1. **Plan the version**
   - Determine the next SemVer tag (`vMAJOR.MINOR.PATCH`).
   - Open or update an issue/PR describing notable changes.

2. **Update documentation**
   - Add release notes to [CHANGELOG.md](../CHANGELOG.md) under a new version heading.
   - Move entries from `[Unreleased]` to the new version section.
   - Verify README snippets and policy docs still apply.

3. **Run validation locally**

   Run the validation suite as described in [CONTRIBUTING.md §5](../.github/CONTRIBUTING.md#5-quality-checks).

4. **Tag and publish a new release**
   ```bash
   make -C .github release tag=vX.Y.Z
   ```

5. **Let automation publish artifacts**
   - Pushing the tag triggers `.github/workflows/wf-release.yaml`.
   - The workflow delegates release packaging and provenance tasks to a pinned reusable SLSA workflow.
   - Monitor the workflow run for success and confirm the expected release assets and attestations are attached (for example source archive, SBOM, and provenance `.intoto.jsonl` assets).

6. **Publish notes**
   - If the automated release does not include human-readable notes, edit the GitHub release, paste the `CHANGELOG.md` entry, and save.

7. **Post-release follow-up**
   - Announce the release in the relevant issue or discussion.
   - Triage any downstream reports and start planning the next iteration.

## Emergency Releases

For high-severity security issues, coordinate privately via the process in [.github/SECURITY.md](../.github/SECURITY.md). Patch branches should include only the minimal changes required to resolve the issue.
