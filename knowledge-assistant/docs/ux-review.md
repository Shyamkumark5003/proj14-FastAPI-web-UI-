# UX review: Knowledge Assistant page

Reviewed against the usability checklist: clear status, errors that say what to do,
plain words, keyboard use, contrast.

| # | Check | Result | Evidence | Fix made |
|---|---|---|---|---|
| 1 | Clear status | PASS | A "Searching..." message appears next to the Ask button while the request runs and disappears when the answer arrives. It uses role="status", so screen readers announce it. | Added hx-indicator and a status paragraph. |
| 2 | Errors say what to do | PASS | Empty question: "Your question is empty. Please type a question and press Ask." Expired session: "Your session expired. Please reload the page and try again." No match: the message suggests example words to try. | Wrote each message as an instruction. Configured HTMX to show 4xx responses, so the session message is visible. |
| 3 | Plain words | PASS | Short sentences, no technical terms shown to the user (no "CSRF" or "403"). Labels say "Your question" and "Ask". | Replaced technical error text with plain instructions. |
| 4 | Keyboard use | PASS | Tab order is skip link, question field, Ask button. Enter submits the form. A 3px blue focus outline is visible on every control. | Added :focus-visible styles and a skip link. |
| 5 | Contrast | PASS | All text pairs are at least 4.5:1 and all borders and outlines at least 3:1. See contrast-notes.md. | Chose dark text and a dark blue button, and checked each pair with a script. |

## Security checks done on the same page

- Autoescaping is on: a document containing a script tag is shown as text and never runs.
- A CSRF token is required: a POST without the token returns 403.
- A Content-Security-Policy header is sent on every response.

## Known limits

- The CSRF protection uses a cookie plus a hidden field. For production, also set the Secure cookie flag when serving over HTTPS.
- The strict Content-Security-Policy blocks the CDN scripts used by the FastAPI /docs page, so that page looks blank. This is expected.
- The search is simple word matching on three sample documents.
