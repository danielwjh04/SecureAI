# SecureAI Chrome and Edge Extension

MV3 browser protection for SecureAI Personal. The extension calls the SecureAI Worker for scan decisions, then enforces locally in the browser.

## Development install

```bash
npm install
npm run lint
npm run typecheck
npm run test:run
npm run build
```

Load `extensions/chrome/dist` as an unpacked extension in Chrome or Edge.

## Pairing

Open the extension popup and paste a SecureAI API key. The popup validates the key by making a harmless scan request through `/api/scan`, then stores the key in extension storage.

The Phase 6 installer opens the store listing and pairing flow when the user selects browser protection. It does not side-load this extension.

## Supported Hosts

- GitHub and raw GitHub content for scan buttons.
- ChatGPT, Claude, and Perplexity browser pages for paste and submit guarding.
- `https://secureai.software` for API calls.

More hosts should be added in config and manifest together so permissions stay reviewable.

## Protection Envelope

SecureAI protects what a browser extension can observe:

- Ingestion: page URLs, selected text, pasted text, and submitted text before a browser-visible AI agent reads it.
- Egress: risky destinations learned from the user's own scan results, enforced through Chrome `declarativeNetRequest` dynamic rules.

SecureAI does not claim to intercept actions that OpenAI, Anthropic, Perplexity, or another provider runs only on its own servers. No public MV3 extension can see those provider-cloud actions.

## DNR Feed Handling

The extension never downloads abuse.ch or other raw threat-feed rows. It does not receive a global feed. Dynamic DNR rules are derived only from scan results produced for this user's own browser activity.

## Manual Test Checklist

1. Load the unpacked `dist` folder.
2. Pair a valid API key in the popup.
3. Scan a benign GitHub or raw GitHub page and confirm the inline result appears.
4. Scan a known-bad gallery URL and confirm a BLOCK result.
5. Paste prompt-injection text into a supported AI page and confirm the guard fires.
6. Confirm BLOCK prevents paste or submit.
7. Confirm a learned risky destination creates a DNR dynamic rule.
8. Confirm no raw threat-feed data appears in extension storage.
