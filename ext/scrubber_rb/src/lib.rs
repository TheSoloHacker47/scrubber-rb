//! Ruby bindings for the scrubber_rb engine.
//!
//! This file is the only place that touches Ruby objects. Everything below it
//! is plain Rust that knows nothing about VALUEs, which is what makes the
//! engine testable with `cargo test` and safe to run with the GVL released.
//!
//! Encoding is handled on the Ruby side: we take and return byte strings and
//! `lib/scrubber/instance.rb` restores the caller's encoding. That keeps the
//! FFI surface to bytes and integers.

mod detectors;
mod engine;
mod nogvl;
mod offsets;
mod pattern;
mod replace;

use magnus::{
    exception::ExceptionClass, function, method, prelude::*, value::ReprValue, Error, RArray,
    RModule, RString, Ruby, Value,
};

use engine::{BuildError, CustomSpec, Engine};
use nogvl::GVL_THRESHOLD;

/// The `Scrubber::Native` object: an immutable compiled engine.
#[magnus::wrap(class = "Scrubber::Native", free_immediately, size)]
struct Native {
    engine: Engine,
}

impl Native {
    /// `Scrubber::Native.new(detectors, customs, replacement, hash_salt)`
    ///
    /// * `detectors` - array of detector-key strings
    /// * `customs`   - array of `[name, regexp_source, regexp_options]` triples
    /// * `replacement` - `"label"` / `"mask"` / `"hash"` / `"remove"`
    /// * `hash_salt` - string, or nil
    fn new(
        detectors: Vec<String>,
        customs: Vec<(String, String, i32)>,
        replacement: String,
        hash_salt: Option<String>,
    ) -> Result<Native, Error> {
        let specs: Vec<CustomSpec> = customs
            .into_iter()
            .map(|(name, source, options)| CustomSpec {
                name,
                source,
                options,
            })
            .collect();

        let engine = Engine::build(&detectors, &specs, &replacement, hash_salt)
            .map_err(build_error_to_ruby)?;
        Ok(Native { engine })
    }

    /// Redact `input`, returning a new binary string, or `nil` when nothing
    /// matched so the caller can skip rebuilding an identical string.
    fn scrub(ruby: &Ruby, rb_self: &Native, input: RString) -> Result<Value, Error> {
        // Copy out of Ruby memory first: everything after this point may run
        // without the GVL, and may not touch a VALUE.
        let bytes = unsafe { input.as_slice() }.to_vec();
        let engine = &rb_self.engine;

        let outcome = if bytes.len() >= GVL_THRESHOLD {
            nogvl::without_gvl(|| engine.scrub(&bytes))
        } else {
            nogvl::guarded(|| engine.scrub(&bytes))
        };

        match outcome {
            Ok(Some(out)) => Ok(ruby.str_from_slice(&out).as_value()),
            Ok(None) => Ok(ruby.qnil().as_value()),
            Err(panic) => Err(internal_error(ruby, &nogvl::panic_message(panic.as_ref()))),
        }
    }

    /// Locate matches without replacing them.
    ///
    /// Returns `[[type, begin, end, preview], ...]`. Offsets are character
    /// offsets when `char_offsets` is true (the caller checked the string is
    /// UTF-8) and byte offsets otherwise, which for single-byte encodings is
    /// the same thing.
    fn detect(
        ruby: &Ruby,
        rb_self: &Native,
        input: RString,
        char_offsets: bool,
    ) -> Result<RArray, Error> {
        let bytes = unsafe { input.as_slice() }.to_vec();
        let engine = &rb_self.engine;

        let outcome = if bytes.len() >= GVL_THRESHOLD {
            nogvl::without_gvl(|| collect_matches(engine, &bytes, char_offsets))
        } else {
            nogvl::guarded(|| collect_matches(engine, &bytes, char_offsets))
        };

        let found = match outcome {
            Ok(found) => found,
            Err(panic) => return Err(internal_error(ruby, &nogvl::panic_message(panic.as_ref()))),
        };

        let out = ruby.ary_new_capa(found.len());
        for (kind, begin, end, preview) in found {
            let row = ruby.ary_new_capa(4);
            row.push(ruby.str_new(&kind))?;
            row.push(begin)?;
            row.push(end)?;
            row.push(ruby.str_new(&preview))?;
            out.push(row)?;
        }
        Ok(out)
    }

    /// How many compiled patterns this engine holds. Used by specs and
    /// `Scrubber::Instance#inspect`.
    fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }
}

/// Pure-Rust half of `detect`, safe to run without the GVL.
fn collect_matches(
    engine: &Engine,
    bytes: &[u8],
    char_offsets: bool,
) -> Vec<(String, usize, usize, String)> {
    let hits = engine.scan(bytes);
    if hits.is_empty() {
        return Vec::new();
    }

    let positions: Vec<usize> = if char_offsets {
        let mut wanted = Vec::with_capacity(hits.len() * 2);
        for hit in &hits {
            wanted.push(hit.start);
            wanted.push(hit.end);
        }
        // `wanted` is already ascending: hits are in document order and
        // non-overlapping.
        offsets::to_char_offsets(bytes, &wanted)
    } else {
        hits.iter().flat_map(|h| [h.start, h.end]).collect()
    };

    hits.iter()
        .enumerate()
        .map(|(i, hit)| {
            (
                engine.kind_of(hit).to_string(),
                positions[i * 2],
                positions[i * 2 + 1],
                engine.preview(bytes, hit),
            )
        })
        .collect()
}

fn error_class(ruby: &Ruby, name: &str) -> ExceptionClass {
    ruby.class_object()
        .const_get::<_, RModule>("Scrubber")
        .and_then(|m| m.const_get::<_, ExceptionClass>(name))
        .unwrap_or_else(|_| ruby.exception_runtime_error())
}

fn internal_error(ruby: &Ruby, message: &str) -> Error {
    Error::new(
        error_class(ruby, "InternalError"),
        format!(
            "{message}. This is a bug in scrubber_rb - please report it at \
             https://github.com/TheSoloHacker47/scrubber-rb/issues (redact your input first)."
        ),
    )
}

fn build_error_to_ruby(err: BuildError) -> Error {
    let Ok(ruby) = Ruby::get() else {
        // Unreachable from a Ruby thread; keeps the signature total.
        return Error::new(
            magnus::exception::runtime_error(),
            "scrubber_rb: no Ruby VM on this thread",
        );
    };
    let class = match &err {
        BuildError::UnknownDetector { .. } => "UnknownDetectorError",
        BuildError::UnsupportedPattern { .. } | BuildError::InvalidPattern { .. } => {
            "UnsupportedPatternError"
        }
        BuildError::UnknownStrategy { .. } => "ConfigurationError",
    };
    Error::new(error_class(&ruby, class), err.to_string())
}

/// Detector keys, so Ruby doesn't have to keep a second copy of the list in
/// sync with the registry.
fn default_detectors(ruby: &Ruby) -> Result<RArray, Error> {
    let out = ruby.ary_new_capa(detectors::DEFAULTS.len());
    for key in detectors::DEFAULTS {
        out.push(ruby.str_new(key))?;
    }
    Ok(out)
}

fn india_detectors(ruby: &Ruby) -> Result<RArray, Error> {
    let out = ruby.ary_new_capa(detectors::INDIA.len());
    for key in detectors::INDIA {
        out.push(ruby.str_new(key))?;
    }
    Ok(out)
}

fn all_detectors(ruby: &Ruby) -> Result<RArray, Error> {
    let keys = detectors::all_keys();
    let out = ruby.ary_new_capa(keys.len());
    for key in keys {
        out.push(ruby.str_new(key))?;
    }
    Ok(out)
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("Scrubber")?;

    // Error hierarchy lives here so the native extension can raise it before
    // any Ruby file has been loaded.
    let base = module.define_error("Error", ruby.exception_standard_error())?;
    module.define_error("UnknownDetectorError", base)?;
    module.define_error("UnsupportedPatternError", base)?;
    module.define_error("ConfigurationError", base)?;
    module.define_error("InternalError", base)?;

    let native = module.define_class("Native", ruby.class_object())?;
    native.define_singleton_method("new", function!(Native::new, 4))?;
    native.define_method("scrub", method!(Native::scrub, 1))?;
    native.define_method("detect", method!(Native::detect, 2))?;
    native.define_method("rule_count", method!(Native::rule_count, 0))?;

    native.define_singleton_method("default_detectors", function!(default_detectors, 0))?;
    native.define_singleton_method("india_detectors", function!(india_detectors, 0))?;
    native.define_singleton_method("all_detectors", function!(all_detectors, 0))?;

    Ok(())
}
