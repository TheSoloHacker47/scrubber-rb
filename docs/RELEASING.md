# Releasing scrubber_rb

Two things have to be set up once, before the first release. After that a
release is one tag push.

---

## One-time: add the Trusted Publisher on RubyGems

Trusted Publishing lets GitHub Actions publish the gem using a short-lived OIDC
token instead of a long-lived API key stored in repository secrets. There is no
credential to leak, and no credential to rotate.

Because `scrubber_rb` has never been published, use the **pending** publisher
flow — it reserves the name and authorises the workflow in one step.

1. Sign in at <https://rubygems.org> (the account that will own the gem).
2. Go to **<https://rubygems.org/profile/oidc/pending_trusted_publishers/new>**
   — or: profile menu → *Trusted Publishers* → *Create pending publisher*.
3. Fill in exactly these values:

   | Field | Value |
   |---|---|
   | RubyGems gem name | `scrubber_rb` |
   | Publisher type | GitHub Actions |
   | Repository owner | `TheSoloHacker47` |
   | Repository name | `scrubber-rb` |
   | Workflow filename | `release.yml` |
   | Environment | `release` |

   Note the two names differ on purpose: the **gem** is `scrubber_rb`
   (underscore, because that is the Ruby convention), the **repository** is
   `scrubber-rb` (hyphen). Getting these backwards is the most common reason a
   first publish fails.

   The environment field must match the `environment: name: release` block in
   `.github/workflows/release.yml`. If you leave it blank on RubyGems, delete
   the `environment:` block from the workflow too — they have to agree.

4. Save.

### Then create the matching GitHub environment

RubyGems will only accept a token minted from the environment you named.

1. **<https://github.com/TheSoloHacker47/scrubber-rb/settings/environments>**
2. *New environment* → name it `release` → *Configure environment*.
3. Recommended, not required:
   - **Deployment branches and tags**: restrict to *Selected* and add the tag
     rule `v*`. This means a token for this environment can only ever be minted
     by a run triggered from a version tag.
   - **Required reviewers**: add yourself. Publishing then waits for one click,
     which is a cheap undo button for a mistaken tag.

After the first successful publish the pending publisher converts into a normal
Trusted Publisher on the gem, and you can manage it at
<https://rubygems.org/gems/scrubber_rb/trusted_publishers>.

---

## One-time: check the repository settings

- **Actions permissions** — Settings → Actions → General → Workflow permissions.
  The release job asks for `id-token: write` and `contents: write` explicitly,
  so the default read-only token setting is fine and preferred.
- **Branch protection on `main`** — require the `CI` checks to pass, require a
  PR, and enable squash-merge only. The release workflow re-runs the whole
  suite anyway, but this keeps a broken commit off `main` in the first place.

---

## Every release

```bash
# 1. Bump the version
$EDITOR lib/scrubber/version.rb        # VERSION = "0.1.0"

# 2. Move the Unreleased section into a dated release heading
$EDITOR CHANGELOG.md

# 3. Regenerate the benchmark table if the engine changed
bundle exec rake benchmark             # paste the table between the
                                       # BENCHMARK:START/END markers in README.md

# 4. Prove it green locally
bundle exec rake ci

# 5. Commit
git add -A && git commit -m "Release v0.1.0"
git push origin main
```

Then tag. The tag must match `Scrubber::VERSION` exactly — the workflow checks
this and fails the release rather than shipping a mislabelled gem:

```bash
git tag -a v0.1.0 -m "scrubber_rb 0.1.0"
```

```bash
git push origin v0.1.0
```

That tag push is what starts the release. It will:

1. Re-run fmt, clippy, cargo test, compile, spec and rubocop.
2. Verify the tag matches `Scrubber::VERSION`.
3. Cross-compile a platform gem for `x86_64-linux`, `x86_64-linux-musl`,
   `aarch64-linux`, `aarch64-linux-musl`, `x86_64-darwin`, `arm64-darwin`, and
   `x64-mingw-ucrt` (still marked allowed-to-fail, though it has in fact built
   cleanly on every dry run so far).
4. Build the source gem and prove it installs and works from the `.gem` file.
5. Wait for the `release` environment approval, if you configured reviewers.
6. `gem push` every gem via Trusted Publishing, then cut a GitHub release with
   the gems attached.

### Dry run first

Before the very first real release, build everything without publishing:

```bash
gh workflow run release.yml --repo TheSoloHacker47/scrubber-rb -f dry_run=true
```

That runs steps 1–4 and uploads the gems as workflow artifacts. Download one
and check it installs before you push a tag you cannot take back.

---

## If a release goes wrong

**A gem version on RubyGems cannot be replaced.** You can `gem yank` it, but the
version number is burned — yanking frees nothing, and re-pushing the same
version is refused. So fix forward: bump the patch version and release again.

```bash
gem yank scrubber_rb -v 0.1.0            # only if it is actively harmful
```

If the tag was wrong but nothing was published, delete it and re-tag:

```bash
git push origin :refs/tags/v0.1.0 && git tag -d v0.1.0
```

Common first-publish failures:

| Symptom | Cause |
|---|---|
| `401 Unauthorized` on `gem push` | Publisher fields don't match. Check `scrubber_rb` vs `scrubber-rb` and the workflow filename. |
| Job never starts | The `release` environment doesn't exist, or its branch/tag rule excludes `v*`. |
| `id-token` error | The `publish` job lost its `permissions: id-token: write`. |
| Tag mismatch failure | `lib/scrubber/version.rb` was not bumped before tagging. Working as intended. |
| `cannot produce cdylib ... does not support these crate types` | A musl build lost `-C target-feature=-crt-static`. The Rakefile sets it; check it still detects the target (`RUBY_TARGET`). |
| `is missing native libraries for: 3.4` | rake-compiler matches cross-rubies by **exact patch version**, and the resolver step drifted from what the image holds. Read the resolver's `resolved:` line against the image's actual `ruby-*` directories. |
| A build image behaving as if it predates a Ruby release | The image is cached under `$HOME/.cache/rb-sys-<version>`. Bump `cache-version:` on the `cross-gem` step to evict it. |

### What the dry run is for

The first nine dry runs of this workflow found, in order: a musl linker
configuration that silently produced no library at all; gems that shipped with
no Ruby 3.4 support and would have raised `LoadError` on every 3.4 install; and
a build image cached from before Ruby 3.4 existed. Every one of those would have
been a burned version number, because a published gem version cannot be
replaced.

Run the dry run. It is free and the version number is not.
