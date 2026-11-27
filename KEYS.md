# Managing the published key set

`public/.well-known/ai-disclosure-jwks.json` is the public key set detectors use to check our
signed AI-disclosure markers. It is served at
<https://ai-disclosure.complexio.com/.well-known/ai-disclosure-jwks.json>. It changes only
through a reviewed pull request to this repository, approved by a code owner. The `Checks`
workflow runs on every pull request and fails it when the file:

- is over the 1 MiB checkers accept, or is JSON the checkers refuse (a repeated member name,
  `NaN` or `Infinity`, a number too large to read, a byte-order mark, nesting over 32 deep);
- is not a JWKS document: a JSON object with a `keys` array;
- has an entry that is not a JSON object, or is not an Ed25519 OKP key;
- has a key with a private `d` member, a `use` other than `sig` or an `alg` other than `EdDSA`;
- has a key without a `kid`, with a `kid` another entry repeats, or with a `kid` that is not its
  RFC 7638 thumbprint;
- has a key whose `x` is not a canonical Ed25519 public key, or that checkers would skip, such
  as one whose `key_ops` does not include `verify`.

## What a key in the set means

Complexio vouches for every key in the set: a key here belongs to a deployment Complexio
operates. Key ids are opaque on purpose. A `kid` is the key's RFC 7638 thumbprint and names no
customer, so the public set does not reveal whom we sign for. Any key in the set can sign for
any organisation; the signed token names which (`on_behalf_of`).

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

Add the new key first and enable it. Keep the retired key in the set, so mail it signed still
checks; removing it makes that mail stop verifying. A key has no validity period: detectors do
not check a token's `iat` against when the key was in use.

## A compromised key

Remove it from the key set at once, through a reviewed pull request. Mail it signed stops
verifying, which is the intent.
