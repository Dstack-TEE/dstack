// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! A compact spec language for validating string values such as environment
//! variables.
//!
//! A spec is an integer spec, a decimal spec or a regex:
//!
//! | Spec | Accepts |
//! | --- | --- |
//! | `int` | any integer |
//! | `int(1..=65535)` | integers from 1 to 65535 |
//! | `int(0..<256)` | integers from 0 to 255 |
//! | `int(0\|1024..=65535)` | 0, or integers from 1024 to 65535 |
//! | `float` | any decimal |
//! | `float(0<..=1)` | numbers above 0, up to 1 |
//! | `float(..<0\|0.5..)` | numbers below 0, or from 0.5 |
//! | `/[a-z]{1,8}/` | values the regex matches in full |
//!
//! A range is `start..=end`, where either side may be omitted to leave it
//! unbounded. Writing `<` instead of `=` excludes the end, and `<` after the
//! start excludes the start.
//!
//! A trailing `?` makes any spec accept the empty string as well, as in
//! `int(1..=65535)?`.
//!
//! Numbers are canonical decimals: no `+`, no leading zeros, no negative zero,
//! no exponent, no whitespace, at most 64 bytes. Integers are bounded by `i128`
//! and numbers are compared exactly. The regex is everything between the first
//! and the last `/`, in the dialect of the [`regex`] crate.
//!
//! Specs and values may come from untrusted input. A spec is at most 4096
//! bytes and its regex compiles to at most 10 MiB, so parsing a spec is bounded
//! and matching takes time linear in the value.
//!
//! ```
//! use value_spec::ValueSpec;
//!
//! let port: ValueSpec = "int(0|1024..=65535)".parse().unwrap();
//! assert!(port.matches("0"));
//! assert!(port.matches("8080"));
//! assert!(!port.matches("80"));
//! assert!(!port.matches("08080"));
//! assert!(!port.matches("8080.5"));
//!
//! let ratio: ValueSpec = "float(0<..=1)".parse().unwrap();
//! assert!(ratio.matches("0.25"));
//! assert!(!ratio.matches("0"));
//!
//! let key: ValueSpec = "/[A-Za-z0-9_-]{1,128}/".parse().unwrap();
//! assert!(key.matches("abc_123"));
//! assert!(!key.matches("abc/123"));
//!
//! let optional: ValueSpec = "int(1..=65535)?".parse().unwrap();
//! assert!(optional.matches(""));
//! assert!(optional.matches("8080"));
//! assert!(!optional.matches("0"));
//! ```

use std::ops::Bound::{self, Excluded, Included, Unbounded};
use std::ops::RangeBounds;
use std::str::FromStr;

use bigdecimal::{BigDecimal, Zero};
use regex::{Regex, RegexBuilder};
use thiserror::Error;
use winnow::ascii::{digit0, digit1};
use winnow::combinator::{
    alt, cut_err, empty, eof, fail, opt, peek, preceded, separated, terminated,
};
use winnow::error::StrContext::{Expected, Label};
use winnow::error::StrContextValue::Description;
use winnow::error::{ContextError, ErrMode};
use winnow::token::{one_of, rest};
use winnow::{ModalResult, Parser};

/// The error returned when a spec fails to parse.
#[derive(Debug, Error)]
#[error("invalid value spec at offset {offset}: {message}")]
pub struct ParseError {
    offset: usize,
    message: String,
}

/// A parsed spec. Build one with [`str::parse`].
#[derive(Debug, Clone)]
pub struct ValueSpec {
    kind: Kind,
    optional: bool,
}

#[derive(Debug, Clone)]
enum Kind {
    Int(Vec<Range<i128>>),
    Float(Vec<Range<BigDecimal>>),
    Regex(Regex),
}

const MAX_NUMBER_LEN: usize = 64;
const MAX_SPEC_LEN: usize = 4096;
const MAX_REGEX_SIZE: usize = 10 << 20;

type Range<T> = (Bound<T>, Bound<T>);

type Number<T> = fn(&mut &str) -> ModalResult<T>;

impl ValueSpec {
    /// Returns whether `value` satisfies the spec.
    pub fn matches(&self, value: &str) -> bool {
        if self.optional && value.is_empty() {
            return true;
        }
        match &self.kind {
            Kind::Int(ranges) => contains(ranges, int, value),
            Kind::Float(ranges) => contains(ranges, decimal, value),
            Kind::Regex(regex) => regex.is_match(value),
        }
    }
}

impl FromStr for ValueSpec {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_SPEC_LEN {
            return Err(ParseError {
                offset: MAX_SPEC_LEN,
                message: format!("spec is longer than {MAX_SPEC_LEN} bytes"),
            });
        }
        let spec = alt((
            regex.map(Kind::Regex),
            ranges("int", int)
                .verify(|ranges: &Vec<_>| ranges.iter().all(has_int))
                .map(Kind::Int),
            ranges("float", decimal).map(Kind::Float),
            fail.context(Expected(Description("`int`, `float` or `/regex/`"))),
        ));
        let (s, optional) = s.strip_suffix('?').map_or((s, false), |s| (s, true));
        terminated(spec, eof.context(Expected(Description("end of spec"))))
            .map(|kind| Self { kind, optional })
            .parse(s)
            .map_err(|e| ParseError {
                offset: e.offset(),
                message: e.inner().to_string(),
            })
    }
}

fn contains<T: PartialOrd>(ranges: &[Range<T>], mut number: Number<T>, value: &str) -> bool {
    number
        .parse(value)
        .is_ok_and(|n| ranges.iter().any(|range| range.contains(&n)))
}

fn int(input: &mut &str) -> ModalResult<i128> {
    alt(("0", (opt('-'), one_of('1'..='9'), digit0).take()))
        .verify(|s: &str| s.len() <= MAX_NUMBER_LEN)
        .try_map(str::parse)
        .context(Label("int"))
        .parse_next(input)
}

fn decimal(input: &mut &str) -> ModalResult<BigDecimal> {
    let integer = alt(("0", (one_of('1'..='9'), digit0).take()));
    (opt('-'), integer, opt(('.', digit1)))
        .take()
        .verify(|s: &str| s.len() <= MAX_NUMBER_LEN)
        .try_map(|s: &str| s.parse::<BigDecimal>().map(|n| (s, n)))
        .verify_map(|(s, n)| (!(s.starts_with('-') && n.is_zero())).then_some(n))
        .context(Label("float"))
        .parse_next(input)
}

fn ranges<'a, T: Clone + PartialOrd>(
    name: &'static str,
    number: Number<T>,
) -> impl Parser<&'a str, Vec<Range<T>>, ErrMode<ContextError>> {
    let single = number.map(|n| (Included(n.clone()), Included(n)));
    let item = alt((
        terminated(single, peek(one_of(['|', ')']))),
        cut_err(range(number)),
    ));
    let items = terminated(separated(1.., item, '|'), ')');
    let any = eof.value(vec![(Unbounded, Unbounded)]);
    preceded(name, alt((preceded('(', cut_err(items)), any))).context(Label(name))
}

fn range<'a, T: Clone + PartialOrd>(
    number: Number<T>,
) -> impl Parser<&'a str, Range<T>, ErrMode<ContextError>> {
    let start = alt((
        (number, opt('<')).map(|(n, open)| open.map_or(Included(n.clone()), |_| Excluded(n))),
        empty.value(Unbounded),
    ));
    let end = alt((
        preceded('=', cut_err(number)).map(Included),
        preceded('<', cut_err(number)).map(Excluded),
        empty.value(Unbounded),
    ));
    (terminated(start, ".."), end)
        .verify(|(start, end)| match (start, end) {
            (Included(start), Included(end)) => start <= end,
            (Included(start) | Excluded(start), Included(end) | Excluded(end)) => start < end,
            _ => true,
        })
        .context(Expected(Description("number or non-empty range")))
}

/// Whether any integer lies in the range, which `1<..<2` has none of.
fn has_int((start, end): &Range<i128>) -> bool {
    let first = match *start {
        Included(n) => Some(n),
        Excluded(n) => n.checked_add(1),
        Unbounded => Some(i128::MIN),
    };
    let last = match *end {
        Included(n) => Some(n),
        Excluded(n) => n.checked_sub(1),
        Unbounded => Some(i128::MAX),
    };
    first.zip(last).is_some_and(|(first, last)| first <= last)
}

fn regex(input: &mut &str) -> ModalResult<Regex> {
    let pattern = rest.verify_map(|s: &str| s.strip_suffix('/'));
    preceded('/', cut_err(pattern.try_map(anchored)))
        .context(Label("regex"))
        .parse_next(input)
}

fn anchored(pattern: &str) -> Result<Regex, regex::Error> {
    // Reject patterns that are only valid once wrapped, such as `a)|(b`.
    let build = |pattern: &str| {
        RegexBuilder::new(pattern)
            .size_limit(MAX_REGEX_SIZE)
            .build()
    };
    build(pattern)?;
    build(&format!(r"\A(?:{pattern})\z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INT_MIN: &str = "-170141183460469231731687303715884105728";
    const INT_MAX: &str = "170141183460469231731687303715884105727";
    const INT_OVERFLOW: &str = "170141183460469231731687303715884105728";
    const INT_UNDERFLOW: &str = "-170141183460469231731687303715884105729";

    fn check(spec: &str, accepted: &[&str], rejected: &[&str]) {
        let spec: ValueSpec = spec.parse().unwrap();
        for value in accepted {
            assert!(spec.matches(value), "{spec:?} should accept {value:?}");
        }
        for value in rejected {
            assert!(!spec.matches(value), "{spec:?} should reject {value:?}");
        }
    }

    fn check_invalid(specs: &[&str]) {
        for spec in specs {
            assert!(spec.parse::<ValueSpec>().is_err(), "{spec:?} should fail");
        }
    }

    #[test]
    fn int_ranges() {
        check("int(1..=65535)", &["1", "65535"], &["0", "65536", "-1"]);
        check("int(0..<256)", &["0", "255"], &["-1", "256"]);
        check("int(0<..=256)", &["1", "256"], &["0", "257"]);
        check("int(0<..<256)", &["1", "255"], &["0", "256"]);
        check("int(-5..=-1)", &["-5", "-1"], &["-6", "0"]);
        check("int(-1..=1)", &["-1", "0", "1"], &["-2", "2"]);
        check("int(1..)", &["1", INT_MAX], &["0", INT_MIN]);
        check("int(0<..)", &["1", INT_MAX], &["0"]);
        check("int(..<0)", &["-1", INT_MIN], &["0"]);
        check("int(..=0)", &["0", INT_MIN], &["1"]);
        check("int(..)", &["0", INT_MIN, INT_MAX], &["a"]);
        check("int(5..=5)", &["5"], &["4", "6"]);
        check("int(4<..<6)", &["5"], &["4", "6"]);
    }

    #[test]
    fn int_singles_and_unions() {
        check("int(0)", &["0"], &["1", "-1", "00"]);
        check("int(-7)", &["-7"], &["7"]);
        check("int(0|1024..=65535)", &["0", "1024"], &["1", "1023"]);
        check("int(80|443|8000..<9000)", &["80", "443", "8999"], &["9000"]);
        check("int(..=-1|1..)", &["-1", "1"], &["0"]);
        check("int(1..=5|3..=8)", &["1", "4", "8"], &["0", "9"]);
        check("int(1|1)", &["1"], &["2"]);
    }

    #[test]
    fn int_is_bounded_by_i128() {
        check(
            "int",
            &["0", INT_MIN, INT_MAX],
            &[INT_OVERFLOW, INT_UNDERFLOW],
        );
        check(
            &format!("int({INT_MIN}..={INT_MAX})"),
            &[INT_MIN, INT_MAX],
            &[],
        );
        check(&format!("int({INT_MAX})"), &[INT_MAX], &[INT_MIN]);
        check(&format!("int(..<{INT_MAX})"), &[INT_MIN], &[INT_MAX]);
        check(&format!("int({INT_MIN}<..)"), &[INT_MAX], &[INT_MIN]);
        check_invalid(&[
            &format!("int({INT_OVERFLOW})"),
            &format!("int(..={INT_OVERFLOW})"),
            &format!("int({INT_UNDERFLOW}..)"),
            &format!("int(..<{INT_MIN})"),
            &format!("int({INT_MAX}<..)"),
        ]);
    }

    #[test]
    fn int_rejects_decimals() {
        check("int", &[], &["1.0", "1.5", "0.0", "-1.0", "1."]);
        check_invalid(&["int(1.5)", "int(1.0)", "int(1..=1.5)", "int(0.5..=1)"]);
    }

    #[test]
    fn float_ranges() {
        check(
            "float(0<..=1)",
            &["0.001", "1", "1.0"],
            &["0", "0.0", "1.001"],
        );
        check("float(0.5..<1.5)", &["0.5", "1", "1.49"], &["0.49", "1.5"]);
        check(
            "float(-1.5..=-0.5)",
            &["-1.5", "-1", "-0.5"],
            &["-1.6", "0"],
        );
        check("float(0.5..)", &["0.5", "1000000"], &["0.4999", "-1"]);
        check("float(0.5<..)", &["0.5001"], &["0.5", "0.50"]);
        check("float(..<0.5)", &["0.4999", "-3"], &["0.5"]);
        check("float(..=0.5)", &["0.5", "0.500"], &["0.5001"]);
        check("float(..)", &["0", "-7.5"], &["a"]);
        check("float(1..=2)", &["1", "1.5", "2", "2.0"], &["0.9", "2.1"]);
        check("float(0.50..=0.5)", &["0.5", "0.50"], &["0.51"]);
    }

    #[test]
    fn float_singles_and_unions() {
        check(
            "float(0.1|0.25)",
            &["0.1", "0.10", "0.25"],
            &["0.2", "0.11"],
        );
        check("float(1)", &["1", "1.0", "1.000"], &["1.001"]);
        check("float(..<0|0.5..)", &["-0.1", "0.5", "7"], &["0", "0.4"]);
        check("float(0|0.5<..<1)", &["0", "0.0", "0.75"], &["0.5", "1"]);
    }

    #[test]
    fn float_compares_exactly() {
        check(
            "float(0.1<..<0.3)",
            &["0.2", "0.10000000000000000000000000000000000000001"],
            &["0.1", "0.3", "0.30000000000000000000000000000000000000001"],
        );
        // 0.1 + 0.2 is 0.30000000000000004 in binary floating point.
        check("float(0.3)", &["0.3", "0.30"], &["0.30000000000000004"]);
        check(
            "float(9007199254740993)",
            &["9007199254740993"],
            &["9007199254740992", "9007199254740994"],
        );
        check(
            "float",
            &[
                INT_OVERFLOW,
                INT_UNDERFLOW,
                "1234567890123456789012345678901234567890.5",
            ],
            &[],
        );
        check(
            &format!("float({INT_OVERFLOW}<..)"),
            &[&format!("{INT_OVERFLOW}.1")],
            &[INT_OVERFLOW, INT_MAX],
        );
    }

    #[test]
    fn ranges_agree_with_rust() {
        let accepts = |spec: String, value: &str| {
            let spec = spec.parse::<ValueSpec>().ok();
            spec.is_some_and(|spec| spec.matches(value))
        };
        for (kind, scale) in [("int", 1.0), ("float", 4.0)] {
            let n = |i: i32| f64::from(i) / scale;
            for a in (-3..=3).map(n) {
                for v in (-5..=5).map(n) {
                    let accepts =
                        |range: String| accepts(format!("{kind}({range})"), &v.to_string());
                    for b in (-3..=3).map(n) {
                        assert_eq!(accepts(format!("{a}..={b}")), (a..=b).contains(&v));
                        assert_eq!(accepts(format!("{a}..<{b}")), (a..b).contains(&v));
                        assert_eq!(accepts(format!("{a}<..={b}")), a < v && v <= b);
                        assert_eq!(accepts(format!("{a}<..<{b}")), a < v && v < b);
                        assert_eq!(accepts(format!("{a}|{b}")), a == v || b == v);
                        assert_eq!(accepts(format!("..<{a}|{b}..")), v < a || v >= b);
                    }
                    assert_eq!(accepts(format!("{a}..")), (a..).contains(&v));
                    assert_eq!(accepts(format!("{a}<..")), a < v);
                    assert_eq!(accepts(format!("..={a}")), (..=a).contains(&v));
                    assert_eq!(accepts(format!("..<{a}")), (..a).contains(&v));
                    assert_eq!(accepts(a.to_string()), a == v);
                }
            }
        }
    }

    #[test]
    fn empty_ranges_are_rejected() {
        check_invalid(&[
            "int(5..<5)",
            "int(5<..=5)",
            "int(5<..<5)",
            "int(5<..<6)",
            "int(5..=4)",
            "int(5..<4)",
            "int(1|5..=4)",
            "float(0.5..<0.5)",
            "float(0.5<..=0.5)",
            "float(0.5<..<0.5)",
            "float(0.50..<0.5)",
            "float(0.5..=0.4)",
            "float(1..=0.99)",
        ]);
        check("float(5<..<6)", &["5.5"], &["5", "6"]);
    }

    #[test]
    fn values_must_be_canonical() {
        let common = [
            "", "-", "--7", "+7", "+0", "07", "-07", "-0", "00", " 7", "7 ", "7\n", "\t7", "7\0",
            "- 7", "7-", "0x7", "0b1", "0o7", "1e3", "1E3", "1_000", "1,000", "1 000", "٧", "７",
            "a", "true", "∞",
        ];
        check("int", &["0", "7", "-7", "10", "-10"], &common);
        check("float", &["0", "7", "-7", "10", "-10"], &common);
        check(
            "float",
            &[
                "7.0", "0.5", "-0.5", "0.50", "0.05", "10.01", "0.0", "0.000",
            ],
            &[
                "7.", ".5", "-.5", "-0.0", "-0.000", "00.5", "-00.5", "1.2.3", "1..2", "1.5e3",
                "1.5E-3", "1.٥", "1.5 ", "1,5", "inf", "-inf", "infinity", "NaN", "nan",
            ],
        );
    }

    #[test]
    fn numbers_are_length_limited() {
        let (fits, long) = (
            format!("0.{}", "1".repeat(MAX_NUMBER_LEN - 2)),
            format!("0.{}", "1".repeat(MAX_NUMBER_LEN - 1)),
        );
        let (digits, more_digits) = ("1".repeat(MAX_NUMBER_LEN), "1".repeat(MAX_NUMBER_LEN + 1));
        let negative = format!("-{digits}");
        check(
            "float",
            &[&fits, &digits],
            &[&long, &more_digits, &negative],
        );
        check("int", &[], &[&digits, &more_digits, &"1".repeat(1 << 20)]);
        check("float", &[], &[&format!("0.{}", "1".repeat(1 << 20))]);
        check(&format!("float({fits}..={digits})"), &[&fits], &[]);
        check_invalid(&[
            &format!("float({long}..)"),
            &format!("float(..={more_digits})"),
            &format!("float({more_digits})"),
            &format!("int({more_digits})"),
        ]);
    }

    #[test]
    fn regex_matches_in_full() {
        check(
            "/[a-z]+/",
            &["abc"],
            &["", "abc1", "1abc", "abc\n", "\nabc"],
        );
        check("/a/", &["a"], &["", "aa", "ba", "ab", "A"]);
        check("/^a$/", &["a"], &["aa", "a\n"]);
        check("/(?m)^a$/", &["a"], &["a\na", "a\n"]);
        check("/a|ab/", &["a", "ab"], &["abc", "b"]);
        check("/ab|a/", &["a", "ab"], &["abc"]);
        check("/a*?/", &["", "a", "aaa"], &["b"]);
        check("//", &[""], &["a", "\n"]);
        check("/.*/", &["", "any thing"], &["two\nlines"]);
        check("/(?s).*/", &["", "two\nlines"], &[]);
    }

    #[test]
    fn regex_enumerations_and_lengths() {
        check(
            "/mainnet|testnet|devnet/",
            &["mainnet", "testnet", "devnet"],
            &[
                "",
                "main",
                "mainnets",
                "xdevnet",
                "Mainnet",
                "mainnet|testnet",
            ],
        );
        check(
            "/(?i)true|false/",
            &["true", "FALSE", "True"],
            &["yes", "truefalse"],
        );
        check("/v1\\.0|v2\\.0/", &["v1.0", "v2.0"], &["v1x0"]);
        check("/.{1,8}/", &["a", "12345678", "é"], &["", "123456789"]);
        check(
            "/[A-Za-z0-9_-]{1,128}/",
            &["abc_123", &"a".repeat(128)],
            &["", "abc/123", "abc 123", &"a".repeat(129)],
        );
        check(
            "/0x[0-9a-fA-F]{40}/",
            &[&format!("0x{}", "aB".repeat(20))],
            &["0x12"],
        );
    }

    #[test]
    fn specs_are_size_limited() {
        let enumeration = |len: usize| format!("/{}/", "a".repeat(len - 2));
        check(
            &enumeration(MAX_SPEC_LEN),
            &[&"a".repeat(MAX_SPEC_LEN - 2)],
            &["a"],
        );
        let items = |n: usize| format!("int({})", vec!["1"; n].join("|"));
        assert_eq!(items(2046).len(), MAX_SPEC_LEN);
        check(&items(2046), &["1"], &["2"]);
        check_invalid(&[
            &enumeration(MAX_SPEC_LEN + 1),
            &items(2047),
            &"?".repeat(1 << 20),
            "/(?:a{1000}){1000}/",
            "/\\pL{1000}/",
            &format!("/{}/", "(".repeat(300) + &")".repeat(300)),
        ]);
    }

    #[test]
    fn regex_cannot_escape_its_anchors() {
        check_invalid(&[
            "/a)|(b/",
            "/a)|(?:b/",
            "/(?x)a # b/",
            "/(?x)a|b #/",
            "/a\\/",
            "/[a/",
        ]);
        check("/(?x)a # b\n/", &["a"], &["ab", "a # b"]);
        check("/(?x) a | b /", &["a", "b"], &["ab", " a "]);
        check("/(?m)a/", &["a"], &["a\n", "\na", "b\na\nb"]);
        check("/(?m)^a$/", &["a"], &["a\n", "\na", "b\na\nb"]);
        check("/(?s)a.?/", &["a", "a\n"], &["a\n\n", "\na"]);
        check("/a|b/", &["a", "b"], &["ab", "a\n", "xa", "bx"]);
        check("/a*/", &["", "aaa"], &["\n", "a\n", "a\0", "\0"]);
    }

    #[test]
    fn hostile_values_are_rejected() {
        let huge = "9".repeat(1 << 20);
        let values = [
            "8080\n",
            "\n8080",
            " 8080",
            "8080 ",
            "8080\0",
            "+8080",
            "٨٠٨٠",
            "８０８０",
            "0x10",
            "1e3",
            "1_000",
            "8080\r",
            &huge,
        ];
        check("int", &[], &values);
        check("float", &[], &values);
        check("int(1..=65535)?", &[""], &values);
        check(
            "/[0-9]+/",
            &[&huge],
            &["8080\n", "٨٠٨٠", "８０８０", " 8080"],
        );
    }

    #[test]
    fn regex_slashes_and_unicode() {
        check(
            "/https://[^/]+/v2/",
            &["https://rpc.example/v2"],
            &["https://a/b/v2", "https://rpc.example/v2/"],
        );
        check("///", &["/"], &["", "//"]);
        check("/\\//", &["/"], &["\\/"]);
        check("/a/b/", &["a/b"], &["a", "b"]);
        check("/\\p{Han}+/", &["中文"], &["abc", ""]);
        check("/\\d+/", &["123", "٧"], &["a"]);
        check("/(?-u:\\d)+/", &["123"], &["٧"]);
        check("/int(1..=5)/", &["int1..=5"], &["3"]);
    }

    #[test]
    fn invalid_regexes() {
        check_invalid(&[
            "/",
            "/a",
            "a/",
            "/a/ ",
            "/a/i",
            "/(/",
            "/)/",
            "/[/",
            "/*/",
            "/a{2,1}/",
            "/a\\/",
            "/a)|(b/",
            "/(?x)a # comment/",
            "/(a)\\1/",
            "/a(?=b)/",
            "/(?<!a)b/",
            "/\\p{Nope}/",
        ]);
    }

    #[test]
    fn optional_specs_accept_empty() {
        check("int?", &["", "0", "-1"], &[" ", "a", "1.5"]);
        check("int(1..=65535)?", &["", "1", "65535"], &["0", " ", "?"]);
        check("int(0|5..)?", &["", "0", "5"], &["1"]);
        check("float?", &["", "0.5"], &[".", "-"]);
        check("float(0<..=1)?", &["", "1", "0.5"], &["0", "1.5"]);
        check("/a|b/?", &["", "a", "b"], &["c", "ab"]);
        check("/a?/", &["", "a"], &["aa", "?"]);
        check("/a/?/", &["a/", "a"], &["", "a/?"]);
        check("/a+/", &["a"], &[""]);
        for spec in ["int", "int(0..)", "float", "float(..)", "/.+/"] {
            check(spec, &[], &[""]);
        }
        check_invalid(&[
            "?",
            "int??",
            "int(1)??",
            "int?(1)",
            "int(1?)",
            "int(1..=2?)",
            "/a?",
            "/?",
            "/a/??",
            "int ?",
            "int(1)?x",
            "float(?)",
        ]);
    }

    #[test]
    fn invalid_specs() {
        check_invalid(&[
            "",
            " ",
            "1",
            "1..=5",
            "..",
            "a",
            "string",
            "integer",
            "integer(1)",
            "ints",
            "decimal",
            "decimal(1)",
            "floats",
            "number(1)",
            "INT",
            "Int(1)",
            "FLOAT",
            " int",
            "int ",
            "int\n",
            "int()",
            "int(",
            "int)",
            "int(1",
            "int(1))",
            "int((1))",
            "int(1)x",
            "int(1)(2)",
            "int (1)",
            "int( 1)",
            "int(1 )",
            "int(1 ..=5)",
            "int(1.. =5)",
            "int(1...5)",
            "int(1.=5)",
            "int(1..5)",
            "int(..5)",
            "int(1..=)",
            "int(1..<)",
            "int(1..==5)",
            "int(1..=<5)",
            "int(1..<=5)",
            "int(1..>5)",
            "int(1<)",
            "int(<1)",
            "int(<..5)",
            "int(<..)",
            "int(1<5)",
            "int(1<<..5)",
            "int(1<=..5)",
            "int(1=..5)",
            "int(1..=5..=9)",
            "int(a..<5)",
            "int(1..=a)",
            "int(1..=+5)",
            "int(+1..=5)",
            "int(01..<5)",
            "int(1..=05)",
            "int(-0..=5)",
            "int(1-5)",
            "int(1,5)",
            "int(1, 2)",
            "int(1|)",
            "int(|1)",
            "int(|)",
            "int(1||2)",
            "int(1|2",
            "int(1)|int(2)",
            "int(1)|/a/",
            "int|float",
            "int(/a/)",
            "float()",
            "float(1.)",
            "float(.5)",
            "float(.5..)",
            "float(1..=.5)",
            "float(-0.0..)",
            "float(1e3)",
            "float(1.5e3..)",
            "float(inf)",
            "float(..=NaN)",
            "float(0.1..0.5)",
            "float(0.1 ..=0.5)",
        ]);
    }

    #[test]
    fn errors_point_at_the_problem() {
        let error = |spec: &str| spec.parse::<ValueSpec>().unwrap_err();
        assert_eq!(error("string").offset, 0);
        assert_eq!(error("int(1)x").offset, 6);
        assert_eq!(error("int(1..=x)").offset, 8);
        assert_eq!(error("int(1|a)").offset, 6);
        assert_eq!(error("/(/").offset, 1);
        let message = error("string").to_string();
        assert!(
            message.starts_with("invalid value spec at offset 0: "),
            "{message}"
        );
        assert!(message.contains("`int`, `float` or `/regex/`"), "{message}");
        assert!(error("/(/").to_string().contains("unclosed group"));
    }
}
