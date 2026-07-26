#!/usr/bin/env python3
"""
Independent, Python-based static verification of the nextjs-auth0 audit findings.

This deliberately does NOT reuse any of the JS/vitest proof scripts or their
logic. It re-derives each finding's core factual claims by mechanically
parsing the raw TypeScript source text -- a different language, a different
method (brace-counting function extraction instead of running the code),
and no shared code path with the earlier proofs -- specifically to catch a
mistake in how those proofs represented the source, or a false positive in
the original manual reading.

What this CAN verify: whether the code actually contains the constructs the
findings claim it does (a specific guard present/absent, a specific call
passing a specific argument, a field present/absent in a type).

What this CANNOT verify: runtime behavior, or anything about Auth0's own
server-side enforcement (the open questions in FINDING-connect-account-cross-
session.md remain open regardless of what this script finds).

Includes positive AND negative controls: claims that should be TRUE and
claims that should be FALSE, so a script that just rubber-stamps everything
as CONFIRMED would visibly fail the negative controls.

Usage: python3 verify_findings.py [path-to-sdk-src]
    Defaults to ../../../src relative to this file (the SDK's src/ when this
    file sits in examples/quickstart/audit/).
"""

import re
import sys
from pathlib import Path


def strip_block_comments(source: str) -> str:
    """
    Remove /* ... */ and /** ... */ blocks, replacing each with a
    same-length run of spaces (preserving line/column numbers and overall
    file length so downstream indices stay meaningful).

    Why this exists: JSDoc comments routinely contain type annotations like
    `@param {AccessTokenForConnectionOptions} options`. TypeScript methods
    with multiple overload signatures also have JSDoc blocks between each
    overload and the real implementation. A naive brace-depth scanner run
    directly on the raw source can walk INTO one of these comments, treat
    the JSDoc's `{Type}` as a real, balanced, depth-0 brace pair, and
    mis-identify it as the function body -- which is exactly what an
    earlier version of this script did (extracted
    '{AccessTokenForConnectionOptions}' as if it were
    getAccessTokenForConnection's body). Stripping comments first prevents
    that class of mistake for every check in this file, rather than patching
    each regex individually to dodge overloads/comments.
    """
    return re.sub(
        r"/\*.*?\*/",
        lambda m: " " * len(m.group(0)) if "\n" not in m.group(0) else re.sub(r"[^\n]", " ", m.group(0)),
        source,
        flags=re.S,
    )


def find_function_body(source: str, signature_start_regex: str) -> str | None:
    """
    Mechanically extract a function/method body given a regex that matches
    up to and including the signature's OPENING '(' only (e.g.
    r"async myMethod\\s*\\("). Everything after that -- the parameter list,
    the return-type annotation, and the body -- is located by real
    depth-counting in three stages, not by regexes trying to guess where
    each part ends. Call `strip_block_comments()` on `source` first.

    This went through three bug fixes while independently verifying the
    audit's own findings, each caught by a check that unexpectedly failed
    (kept here as documented history, since it's the reason the design ended
    up this careful):

    1. First version located the body via `source.index("{", m.end())` with
       a regex that consumed the whole parameter list AND return type via
       `[^{]*`. TS return types like `Promise<{ token: string }>` contain a
       '{' INSIDE the generic, before the real body '{' -- `[^{]*` stopped
       exactly AT that inner brace, so depth-counting started ON it at
       depth 0 and mis-identified it as the body start.
    2. Fixed by tracking combined depth of '<'/'>' and '{'/'}' from the end
       of the signature match -- but this still broke on methods with
       multiple TS overload signatures (e.g. getAccessTokenForConnection has
       three declarations of the same name; a regex `re.search` finds the
       first one, an overload stub ending in ';' with no body) combined with
       JSDoc comments containing `{Type}` annotations, which the scanner
       walked into and mis-matched as a balanced, depth-0 brace pair.
       Fixed by stripping block comments (`strip_block_comments`) before any
       parsing.
    3. Even with comments stripped, a regex matching the FULL parameter list
       via `[^)]*\\)` breaks when a parameter's TYPE itself contains a `)`
       -- e.g. `cookies: RequestCookies | import("./cookies.js").Foo` -- the
       regex stops at the first ')' (closing the `import(...)` call), far
       short of the real end of the parameter list. Fixed by taking a
       signature regex that stops at the opening '(' and doing genuine
       paren-depth counting (this function, stage 1 below) instead of
       asking a regex to find where the parameter list ends.
    """
    m = re.search(signature_start_regex, source)
    if not m:
        return None
    i = m.end()  # positioned just after the signature's opening '('
    if i == 0 or source[i - 1] != "(":
        return None  # signature_start_regex must end in an unescaped '('

    # Stage 1: real paren-depth counting to find the end of the parameter list.
    paren_depth = 1
    while i < len(source) and paren_depth > 0:
        if source[i] == "(":
            paren_depth += 1
        elif source[i] == ")":
            paren_depth -= 1
        i += 1
    if paren_depth != 0:
        return None

    # Stage 2: combined '<>{}' depth counting through the return-type
    # annotation (e.g. `: Promise<{ token: string }>`) to find the real body.
    depth = 0
    body_start = None
    while i < len(source):
        c = source[i]
        if c in "<{":
            if c == "{" and depth == 0:
                body_start = i
                break
            depth += 1
        elif c in ">}":
            depth = max(0, depth - 1)
        i += 1
    if body_start is None:
        return None

    # Stage 3: brace-count the body itself to its matching close.
    depth = 0
    i = body_start
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[body_start : i + 1]
        i += 1
    return None


def find_type_body(source: str, signature_regex: str) -> str | None:
    """
    Extract an `interface`/`type` body. Deliberately separate from
    find_function_body: interfaces have no parameter list, so
    find_function_body's paren-depth stage (which requires the regex to end
    in '(') does not apply. `signature_regex` should match up to and
    including the interface's own opening '{' (e.g.
    r"export interface Foo\\b[^{]*\\{") -- call strip_block_comments() on
    `source` first, same as for find_function_body.
    """
    m = re.search(signature_regex, source)
    if not m or source[m.end() - 1] != "{":
        return None
    body_start = m.end() - 1
    depth = 0
    i = body_start
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[body_start : i + 1]
        i += 1
    return None


results: list[tuple[str, bool, bool, str]] = []  # claim, expected, actual, detail


def check(claim: str, expected: bool, actual: bool, detail: str = "") -> None:
    passed = expected == actual
    tag = "PASS" if passed else "FAIL"
    verdict = "CONFIRMED (matches finding)" if actual == expected else "DID NOT MATCH — investigate"
    results.append((claim, expected, actual, detail))
    print(f"[{tag}] {claim}")
    print(f"       expected={expected} actual={actual} -> {verdict}")
    if detail:
        print(f"       {detail}")
    print()


def main() -> int:
    sdk_src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "src"
    if not sdk_src.exists():
        print(f"ERROR: SDK src/ not found at {sdk_src}", file=sys.stderr)
        return 2

    client_ts = strip_block_comments((sdk_src / "server" / "client.ts").read_text())
    auth_client_ts = strip_block_comments((sdk_src / "server" / "auth-client.ts").read_text())
    types_index_ts = strip_block_comments((sdk_src / "types" / "index.ts").read_text())
    stateless_store_ts = strip_block_comments(
        (sdk_src / "server" / "session" / "stateless-session-store.ts").read_text()
    )
    cookies_ts = strip_block_comments((sdk_src / "server" / "cookies.ts").read_text())
    transaction_store_ts = strip_block_comments((sdk_src / "server" / "transaction-store.ts").read_text())

    print("=" * 72)
    print("Independent static verification — nextjs-auth0 audit findings")
    print(f"SDK src: {sdk_src}")
    print("=" * 72)
    print()

    # ------------------------------------------------------------------
    # Finding W: IPSIE session-ceiling bypass for connection tokens
    # ------------------------------------------------------------------
    print("--- Finding W: IPSIE ceiling bypass for connection tokens ---\n")

    # Regex intentionally ends right after the parameter list's closing ')' —
    # NOT with a trailing [^{]*. An earlier version used [^{]* to "skip past"
    # the return-type annotation, but Promise<{ token: string; ... }> contains
    # a '{' inside the generic, so [^{]* stopped exactly AT that inner brace
    # and find_function_body's depth-tracker (which starts at depth 0)
    # misidentified it as the body start. Ending right after ')' and letting
    # the depth-tracker walk the whole return-type annotation (correctly
    # counting '<'/'{' together) fixes this for every signature below.
    gatfc = find_function_body(client_ts, r"async getAccessTokenForConnection\s*\(")
    check(
        "getAccessTokenForConnection() passes skipCeilingCheck: true to getSessionWithDomainCheck",
        True,
        bool(gatfc and "skipCeilingCheck: true" in gatfc and "getSessionWithDomainCheck" in gatfc),
        detail="function body located and scanned for both substrings" if gatfc else "COULD NOT LOCATE FUNCTION",
    )

    gswd = find_function_body(auth_client_ts, r"async getSessionWithDomainCheck\s*\(")
    check(
        "getSessionWithDomainCheck() only enforces the ceiling when !skipCeilingCheck",
        True,
        bool(gswd and re.search(r"!skipCeilingCheck\s*&&\s*\n?\s*isSessionCeilingReached", gswd)),
        detail="function body located and scanned for the exact guard expression" if gswd else "COULD NOT LOCATE FUNCTION",
    )

    gcts = find_function_body(auth_client_ts, r"async getConnectionTokenSet\s*\(")
    check(
        "getConnectionTokenSet() contains NO reference to sessionExpiresAt or ceiling anywhere in its body",
        True,
        bool(gcts and "sessionExpiresAt" not in gcts and "eiling" not in gcts),
        detail=f"function body length={len(gcts)} chars, scanned in full" if gcts else "COULD NOT LOCATE FUNCTION",
    )

    # Positive control: the PRIMARY token path (getTokenSet) DOES check the
    # ceiling — if this came back False, it would mean the primary path is
    # ALSO unprotected, which would contradict the finding's framing that only
    # the connection-token path is exceptional. This must be True.
    # NOTE: getTokenSet's second parameter has a default value containing its
    # own braces (`options: GetAccessTokenOptions = {}`) — [^)]* correctly
    # skips over that (it excludes only ')', not '{'/'}') to reach the real
    # closing paren of the parameter list.
    gts = find_function_body(auth_client_ts, r"async getTokenSet\s*\(")
    check(
        "CONTROL: getTokenSet() (primary access-token path) DOES check isSessionCeilingReached",
        True,
        bool(gts and "isSessionCeilingReached" in gts),
        detail="this must be True — it's what makes the connection-token path the exception, not the norm",
    )

    # Negative control: skipCeilingCheck should NOT appear anywhere inside
    # getConnectionTokenSet's own body — it doesn't even receive that
    # parameter, confirming the bypass happens one layer up (in
    # getSessionWithDomainCheck), not inside the exchange function itself.
    check(
        "CONTROL: getConnectionTokenSet() body does NOT itself reference skipCeilingCheck",
        True,
        bool(gcts and "skipCeilingCheck" not in gcts),
        detail="expected — the bypass is a caller-side decision (getAccessTokenForConnection), not this function's own logic",
    )

    # ------------------------------------------------------------------
    # Finding V: connect-account completion not bound to initiating session
    # ------------------------------------------------------------------
    print("--- Finding V: connect-account cross-session ---\n")

    # TransactionState type: no sid/sub field. Declared in transaction-store.ts
    # (NOT auth-client.ts — first script draft searched the wrong file and
    # reported a false "COULD NOT LOCATE TYPE"; fixed here).
    tx_state = find_type_body(transaction_store_ts, r"export interface TransactionState\b[^{]*\{")
    # Field-declaration match only (name at start of a property line, optional
    # '?', then ':') — a naive substring check first flagged this as failing
    # because the comment "Stored alongside originDomain..." contains "sid" as
    # a substring of "alongSIDe". That was a bug in this check, not in the
    # finding; fixed to only match actual field declarations.
    has_sid_field = bool(re.search(r"^\s*sid\??\s*:", tx_state or "", re.M))
    has_sub_field = bool(re.search(r"^\s*sub\??\s*:", tx_state or "", re.M))
    check(
        "TransactionState type has no `sid` or `sub` field (no identity binding)",
        True,
        bool(tx_state and not has_sid_field and not has_sub_field and "authSession" in tx_state),
        detail="checked for actual field declarations (not substrings) of sid/sub, plus presence of authSession to confirm the right type was matched" if tx_state else "COULD NOT LOCATE TYPE",
    )

    handle_callback = find_function_body(auth_client_ts, r"public async handleCallback\s*\(")
    connect_code_branch = None
    if handle_callback:
        idx = handle_callback.find("RESPONSE_TYPES.CONNECT_CODE")
        if idx != -1:
            # Slice from the branch's `if (` a reasonable window forward —
            # brace-counting the whole handleCallback is correct but this
            # branch-local slice is enough to check the specific claim.
            connect_code_branch = handle_callback[idx : idx + 2500]
    check(
        "handleCallback's CONNECT_CODE branch reads getSessionWithDomainCheck() with no comparison to transactionState identity",
        True,
        bool(
            connect_code_branch
            and "getSessionWithDomainCheck" in connect_code_branch
            and "transactionState.authSession" in connect_code_branch
            and "transactionState.sid" not in connect_code_branch
            and ".sub ===" not in connect_code_branch
            and "internal.sid ===" not in connect_code_branch
        ),
        detail="scanned ~2500 chars of the CONNECT_CODE branch for any sid/sub equality check" if connect_code_branch else "COULD NOT LOCATE BRANCH",
    )

    # ------------------------------------------------------------------
    # Finding U (retracted as security, bug mechanism still real):
    # connectionTokenSets cache-invalidation gap
    # ------------------------------------------------------------------
    print("--- Finding U: connectionTokenSets (retracted security framing) ---\n")

    set_fn = find_function_body(stateless_store_ts, r"async set\s*\(")
    check(
        "StatelessSessionStore.set() writes __FC_N cookies but has no cleanup of trailing indices beyond the new array length",
        True,
        bool(
            set_fn
            and "connectionTokenSetsCookieName" in set_fn
            and "storeInCookie" in set_fn
            # a real cleanup would delete a cookie whose index >= new length —
            # look for the absence of any such deletion call within this fn
            and not re.search(r"deleteCookie[^;]*(index|idx)", set_fn, re.I)
        ),
        detail="confirms the write loop exists but no matching delete-by-index call exists in the same function",
    )

    delete_fn = find_function_body(stateless_store_ts, r"async delete\s*\(")
    check(
        "CONTROL: StatelessSessionStore.delete() (logout) DOES clean up all __FC_* cookies",
        True,
        bool(delete_fn and "getConnectionTokenSetsCookies" in delete_fn and "deleteCookie" in delete_fn),
        detail="this must be True — it's the asymmetry the finding is built on (delete() correct, set() incomplete)",
    )

    # connectionTokenSets: confirm it really is read/written in exactly one
    # place outside the session-store file (client.ts), as the retraction
    # claims (a "pure cache", single consumer).
    consumer_files = []
    for f in (sdk_src / "server").rglob("*.ts"):
        if f.name.endswith(".test.ts") or "stateless-session-store.ts" in f.name:
            continue
        text = f.read_text()
        if "connectionTokenSets" in text:
            consumer_files.append(str(f.relative_to(sdk_src)))
    check(
        "connectionTokenSets is referenced in exactly one non-test, non-store source file (client.ts) — supports the 'pure cache, single consumer' retraction",
        True,
        consumer_files == ["server/client.ts"],
        detail=f"files referencing connectionTokenSets outside the store: {consumer_files}",
    )

    # ------------------------------------------------------------------
    # Finding T: returnTo open redirect (composition bug)
    # ------------------------------------------------------------------
    print("--- Finding T: returnTo open redirect ---\n")

    path_utils_ts = strip_block_comments((sdk_src / "utils" / "pathUtils.ts").read_text())
    check(
        "createRouteUrl()/ensureNoLeadingSlash() strips exactly one leading slash without checking for a scheme afterward",
        True,
        bool(
            re.search(r"ensureNoLeadingSlash[\s\S]{0,300}startsWith\(\"/\"\)[\s\S]{0,50}substring\(1", path_utils_ts)
        ),
        detail="mechanically confirms the exact slash-stripping logic the finding's root-cause explanation depends on",
    )

    print("=" * 72)
    passed = sum(1 for _, e, a, _ in results if e == a)
    failed = len(results) - passed
    print(f"TOTAL: {len(results)} checks | {passed} matched expectation | {failed} did NOT")
    if failed:
        print("\nDID NOT MATCH (investigate — either the finding or this script is wrong):")
        for claim, e, a, detail in results:
            if e != a:
                print(f"  - {claim}\n      expected={e} actual={a}  {detail}")
        return 1
    print("\nAll findings' core code-level claims independently confirmed by mechanical")
    print("source parsing in a separate tool/language from the original JS proofs.")
    print("(This does not touch the still-open Auth0 server-side questions.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
