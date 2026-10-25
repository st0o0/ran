## Why

Today every non-POST path returns the same login page. Scanners that look for a specific product (WordPress, Git metadata, Spring actuator, `.env`) get no confirming answer and often leave, so rán sees only the first request. Galah and Beelzebub keep scanners engaged with generated responses; a static fixture set gives most of that benefit without an LLM.

## What Changes

- A built-in table of fixtures keyed by path pattern: status, headers and a small body that looks like the product (for example `/.git/HEAD`, `/.env`, `/actuator/health`, `/server-status`, `/phpinfo.php`, `/wp-json/`, `/robots.txt`). Content is fake and contains no real addresses or secrets.
- A fixture hit still follows the rules of `http-request-capture` for classification (exploit paths remain commands).
- Optional operator table `RAN_HTTP_FIXTURES` (path to a small JSON file, at most 64 entries and 8 KiB per body, read once at startup, validated by `check-config`).
- Applies to `http` and `https`.

## Capabilities

### Modified Capabilities

- `trap-http`: fixture responses.

## Impact

- New `httpfixtures.go`, `http.go`, config parsing, README. Depends on `http-request-capture`.

## Non-goals

- No templating, no scripting, no LLM and no dynamic content from client input.
- No reload at runtime.
- No copying of fixture text from GPL projects.
