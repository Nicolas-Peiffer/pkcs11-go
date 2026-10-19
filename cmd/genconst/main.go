// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

// Command genconst translates the #define constants in the OASIS PKCS #11 type
// header (pkcs11t.h) into a Go source file of untyped constants, together with
// the CKR_ and CKA_ name tables behind Error.Error and AttributeName.
//
// It is an independent implementation: it parses the OASIS header directly and
// applies the C-to-Go value rewrites required by the spec's value forms. Run it
// via `go generate ./cryptoki/...`; the produced file is committed to the repo.
//
// Usage:
//
//	go run ./cmd/genconst -header internal/headers/pkcs11t.h -out cryptoki/zconst.go -pkg cryptoki
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// A define is one accepted "#define CK... value /* comment */" line.
type define struct {
	name    string // the C macro name, e.g. CKM_ML_KEM
	value   string // the Go-ready right-hand side
	comment string // trailing // comment text, without markers (may be empty)
}

// defineRE matches an object-like macro whose name begins with "CK". Group 1 is
// the name, group 2 is the raw value (up to a comment or end of line).
var defineRE = regexp.MustCompile(`^#define\s+(CK[0-9A-Z_a-z]*)\s+([^/]+?)\s*(?:/\*(.*)$)?$`)

// intSuffixRE strips C integer suffixes (U, L, UL, ULL, ...) from a numeric
// literal while leaving identifiers and operators untouched.
var intSuffixRE = regexp.MustCompile(`\b(0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]+\b`)

// valueRE is the allowlist of characters permitted in a translated macro value.
// It admits integer literals, CK_* identifiers, the boolean literals, and the C
// operators that survive translation. It deliberately excludes the characters
// that could terminate the constant and begin a new Go statement or comment
// (; { } " ' ` \ and newlines), so a tampered header cannot inject code into the
// generated source (M-P1).
var valueRE = regexp.MustCompile("^[0-9A-Za-z_()|&^~+*/<> \t-]+$")

// callRE matches an identifier immediately followed by "(", i.e. a function
// call. The only call form the header legitimately produces is the all-ones
// word "^uint(0)"; every other call is rejected (M-P1).
var callRE = regexp.MustCompile(`[0-9A-Za-z_]\s*\(`)

func main() {
	var headerPath, outPath, errPath, attrPath, pkg string
	flag.StringVar(&headerPath, "header", "internal/headers/pkcs11t.h", "path to OASIS pkcs11t.h")
	flag.StringVar(&outPath, "out", "cryptoki/zconst.go", "path to the generated constants file")
	flag.StringVar(&errPath, "errout", "cryptoki/zerror.go", "path to the generated CKR name table")
	flag.StringVar(&attrPath, "attrout", "cryptoki/zattr.go", "path to the generated CKA name table")
	flag.StringVar(&pkg, "pkg", "cryptoki", "package name for the generated files")
	flag.Parse()

	defines, err := parse(headerPath)
	if err != nil {
		log.Fatalf("genconst: %v", err)
	}

	src, err := render(pkg, headerPath, defines)
	if err != nil {
		log.Fatalf("genconst: rendering %s: %v", outPath, err)
	}
	// #nosec G306 -- generated Go source is committed to the repo, so 0644 is
	// required (world-readable, not a secret).
	if err := os.WriteFile(outPath, src, 0o644); err != nil {
		log.Fatalf("genconst: writing %s: %v", outPath, err)
	}
	log.Printf("genconst: wrote %d constants to %s", len(defines), outPath)

	errSrc, n, err := renderErrors(pkg, headerPath, defines)
	if err != nil {
		log.Fatalf("genconst: rendering %s: %v", errPath, err)
	}
	// #nosec G306 -- generated Go source is committed to the repo, so 0644 is
	// required (world-readable, not a secret).
	if err := os.WriteFile(errPath, errSrc, 0o644); err != nil {
		log.Fatalf("genconst: writing %s: %v", errPath, err)
	}
	log.Printf("genconst: wrote %d CKR names to %s", n, errPath)

	attrSrc, n, err := renderAttributes(pkg, headerPath, defines)
	if err != nil {
		log.Fatalf("genconst: rendering %s: %v", attrPath, err)
	}
	// #nosec G306 -- generated Go source is committed to the repo, so 0644 is
	// required (world-readable, not a secret).
	if err := os.WriteFile(attrPath, attrSrc, 0o644); err != nil {
		log.Fatalf("genconst: writing %s: %v", attrPath, err)
	}
	log.Printf("genconst: wrote %d CKA names to %s", n, attrPath)
}

// parse reads every accepted CK* object-like macro from the header.
func parse(path string) ([]define, error) {
	// #nosec G304 -- path is a build-time CLI flag pointing at the vendored
	// OASIS header; this is a code generator, not a network-facing handler.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []define
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		m := defineRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		value := translate(m[1], m[2])
		if err := validateValue(m[1], value); err != nil {
			return nil, fmt.Errorf("%s: %w", m[1], err)
		}
		out = append(out, define{
			name:    m[1],
			value:   value,
			comment: cleanComment(m[3]),
		})
	}
	return out, sc.Err()
}

// validateValue rejects a translated value that is not a safe constant
// expression. It is the build-time guard against code injection through a
// tampered pkcs11t.h: the generator splices the value verbatim into a Go const
// block, so anything outside the constant grammar (a string, a call, a
// statement, a comment introducer) must fail the build rather than be emitted
// (M-P1).
func validateValue(name, v string) error {
	if v == "" {
		return fmt.Errorf("%s: empty value", name)
	}
	if !valueRE.MatchString(v) {
		return fmt.Errorf("%s: value %q contains characters outside the constant grammar", name, v)
	}
	if strings.Contains(v, "//") || strings.Contains(v, "/*") {
		return fmt.Errorf("%s: value %q contains a comment introducer", name, v)
	}
	if v != "^uint(0)" && callRE.MatchString(v) {
		return fmt.Errorf("%s: value %q contains a function call", name, v)
	}
	return nil
}

// translate rewrites a C macro value into an equivalent Go expression.
func translate(name, raw string) string {
	v := strings.TrimSpace(raw)
	switch name {
	case "CK_TRUE":
		return "true"
	case "CK_FALSE":
		return "false"
	}
	// (~0UL) and friends denote an all-ones unsigned word; Go spells unary
	// bitwise complement as ^ and needs an explicit unsigned operand.
	if collapse(v) == "(~0)" {
		return "^uint(0)"
	}
	// Drop C integer suffixes wherever they appear (also inside parens).
	v = intSuffixRE.ReplaceAllString(v, "$1")
	// Tidy spacing around a bitwise-OR alias such as (CKF_ARRAY_ATTRIBUTE|0x211).
	if strings.HasPrefix(v, "(") && strings.Contains(v, "|") {
		v = strings.ReplaceAll(v, "|", " | ")
		v = strings.Join(strings.Fields(v), " ")
	}
	return v
}

// collapse removes whitespace and integer suffixes so value forms can be
// compared structurally (e.g. "( ~0UL )" -> "(~0)").
func collapse(v string) string {
	v = intSuffixRE.ReplaceAllString(v, "$1")
	return strings.Join(strings.Fields(v), "")
}

// cleanComment turns a raw trailing C comment body into a Go comment text.
func cleanComment(c string) string {
	c = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(c), "*/"))
	return strings.TrimSpace(c)
}

// render emits gofmt'd source for the parsed defines, grouping by macro prefix.
func render(pkg, header string, defines []define) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors\n")
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n\n")
	fmt.Fprintf(&b, "// Code generated by \"go run ./cmd/genconst\"; DO NOT EDIT.\n")
	fmt.Fprintf(&b, "// Source: %s (OASIS PKCS #11 v3.2). See the repository-root NOTICE.md.\n\n", header)
	fmt.Fprintf(&b, "package %s\n\n", pkg)
	fmt.Fprintf(&b, "const (\n")

	prevPrefix := ""
	for _, d := range defines {
		if p := prefix(d.name); p != prevPrefix {
			if prevPrefix != "" {
				b.WriteByte('\n')
			}
			prevPrefix = p
		}
		if d.comment != "" {
			fmt.Fprintf(&b, "\t%s = %s // %s\n", d.name, d.value, d.comment)
		} else {
			fmt.Fprintf(&b, "\t%s = %s\n", d.name, d.value)
		}
	}
	fmt.Fprintf(&b, ")\n")

	return format.Source(b.Bytes())
}

// renderErrors emits a map from every CKR_ return value to its symbolic name,
// used by (cryptoki.Error).Error. It returns the source and the entry count.
func renderErrors(pkg, header string, defines []define) ([]byte, int, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors\n")
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n\n")
	fmt.Fprintf(&b, "// Code generated by \"go run ./cmd/genconst\"; DO NOT EDIT.\n")
	fmt.Fprintf(&b, "// Source: %s (OASIS PKCS #11 v3.2). See the repository-root NOTICE.md.\n\n", header)
	fmt.Fprintf(&b, "package %s\n\n", pkg)
	fmt.Fprintf(&b, "// ckrNames maps a Cryptoki CK_RV return value to its CKR_ symbol.\n")
	fmt.Fprintf(&b, "var ckrNames = map[Error]string{\n")

	n := 0
	for _, d := range defines {
		if !strings.HasPrefix(d.name, "CKR_") {
			continue
		}
		fmt.Fprintf(&b, "\t%s: %q,\n", d.name, d.name)
		n++
	}
	fmt.Fprintf(&b, "}\n")

	src, err := format.Source(b.Bytes())
	return src, n, err
}

// renderAttributes emits a map from every CK_ATTRIBUTE_TYPE value the header
// defines to the one CKA_ symbol cryptoki.AttributeName reports for it. It
// returns the source and the entry count.
//
// Two header names can share a value, and a Go map literal cannot hold the same
// key twice, so each value gets exactly one name:
//
//   - A define whose value is another macro's name is an alias kept for source
//     compatibility (CKA_SUB_PRIME_BITS is CKA_SUBPRIME_BITS); it never takes
//     the value over from the name it aliases.
//   - Otherwise a later define supersedes an earlier one with the same value,
//     which is how the header introduces a replacement name: CKA_EC_PARAMS
//     follows the deprecated CKA_ECDSA_PARAMS.
func renderAttributes(pkg, header string, defines []define) ([]byte, int, error) {
	values, err := evaluate(defines)
	if err != nil {
		return nil, 0, err
	}

	names := map[uint64]string{}
	var order []uint64
	for _, d := range defines {
		if !strings.HasPrefix(d.name, "CKA_") {
			continue
		}
		v := values[d.name]
		if _, seen := names[v]; !seen {
			order = append(order, v)
		} else if isIdentifier(d.value) {
			continue
		}
		names[v] = d.name
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors\n")
	fmt.Fprintf(&b, "// SPDX-License-Identifier: MIT\n\n")
	fmt.Fprintf(&b, "// Code generated by \"go run ./cmd/genconst\"; DO NOT EDIT.\n")
	fmt.Fprintf(&b, "// Source: %s (OASIS PKCS #11 v3.2). See the repository-root NOTICE.md.\n\n", header)
	fmt.Fprintf(&b, "package %s\n\n", pkg)
	fmt.Fprintf(&b, "// ckaNames maps a CK_ATTRIBUTE_TYPE to the CKA_ symbol AttributeName reports\n")
	fmt.Fprintf(&b, "// for it. A value the header gives two names maps to the current one.\n")
	fmt.Fprintf(&b, "var ckaNames = map[uint]string{\n")
	for _, v := range order {
		fmt.Fprintf(&b, "\t%s: %q,\n", names[v], names[v])
	}
	fmt.Fprintf(&b, "}\n")

	src, err := format.Source(b.Bytes())
	return src, len(order), err
}

// evaluate computes the numeric value of every define whose translated value is
// an integer literal, another define's name, or a parenthesised "|" of those,
// which are the forms pkcs11t.h uses for constants. It fails if a CKA_ define
// has any other form, so that a header change cannot silently drop an attribute
// from the generated name table.
func evaluate(defines []define) (map[string]uint64, error) {
	values := map[string]uint64{}
	for _, d := range defines {
		if v, ok := evalExpr(d.value, values); ok {
			values[d.name] = v
		} else if strings.HasPrefix(d.name, "CKA_") {
			return nil, fmt.Errorf("%s: cannot evaluate value %q", d.name, d.value)
		}
	}
	return values, nil
}

// evalExpr evaluates one translated define value against the values known so
// far. It reports false for any form other than a literal, a name or "|".
func evalExpr(expr string, known map[string]uint64) (uint64, bool) {
	e := strings.TrimSpace(expr)
	if strings.HasPrefix(e, "(") && strings.HasSuffix(e, ")") {
		e = e[1 : len(e)-1]
	}
	var total uint64
	for _, term := range strings.Split(e, "|") {
		term = strings.TrimSpace(term)
		if v, err := strconv.ParseUint(term, 0, 64); err == nil {
			total |= v
			continue
		}
		v, ok := known[term]
		if !ok {
			return 0, false
		}
		total |= v
	}
	return total, true
}

// identRE matches a bare C macro name.
var identRE = regexp.MustCompile(`^[A-Za-z_][0-9A-Za-z_]*$`)

// isIdentifier reports whether a translated define value is a bare macro name,
// that is, whether the define is an alias for another one.
func isIdentifier(v string) bool {
	return identRE.MatchString(strings.TrimSpace(v))
}

// prefix returns the leading token of a macro name up to its first underscore,
// e.g. "CKM" for "CKM_ML_KEM". It is used only to insert blank-line grouping.
func prefix(name string) string {
	if i := strings.IndexByte(name, '_'); i >= 0 {
		return name[:i]
	}
	return name
}
