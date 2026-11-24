# Managing the published key set

`public/.well-known/ai-disclosure-jwks.json` is the public key set detectors use to check our
signed AI-disclosure markers. It is served at
<https://ai-disclosure.complexio.com/.well-known/ai-disclosure-jwks.json>. It changes only
through a reviewed pull request to this repository, approved by a code owner.

## Adding a deployment's key, before its first signed mail

1. Generate an Ed25519 key for the deployment and store the private key as that deployment's
   secret. It never enters this repository.
2. Derive the public key set entry from the private key: an OKP JWK with `crv: Ed25519`,
   `use: sig` and `alg: EdDSA`, whose key id (`kid`) is the RFC 7638 thumbprint of the public
   key. Never put a customer's name in a `kid`: this file is public, so a named kid would
   publish who our customers are.
3. Open a pull request adding that entry to the key set. Once merged and served, mail the
   deployment signs verifies for everyone.
4. Only then enable signing on the deployment. Mail signed before its key is published reads
   "marked, not verified" for every recipient.

## Rotating a key

Add the new key first and enable it. Keep the old key in the set for as long as mail it signed
may need checking; removing it makes that mail stop verifying.

## A compromised key

Remove it from the key set at once, through a reviewed pull request. Mail it signed stops
verifying, which is the intent.
