## What this changes

<!-- One or two sentences. -->

## Why

<!-- The problem, not the patch. -->

## Checklist

- [ ] `bundle exec rake ci` passes locally (fmt, clippy, cargo test, compile, spec, rubocop)
- [ ] New behaviour has a test that fails without the change

### If this touches a detector

- [ ] Test vectors are public or generated, never real credentials
- [ ] False-positive analysis included (what else in a log has this shape?)
- [ ] Checksum / validity check added, if the format has one
- [ ] Matching rule added to `benchmark/pure_ruby_reference.rb`
- [ ] `spec/benchmark_reference_spec.rb` still passes (the two implementations agree)
- [ ] Region-specific? Then it is in an opt-in pack, not `DEFAULTS`

### If this touches the Rust core

- [ ] No `magnus` types below `lib.rs`
- [ ] Nothing runs inside `without_gvl` that touches a Ruby `VALUE`
- [ ] Pattern is backtracking-free (no lookaround, no backreferences)
