# Gluon Manifest Verifier

This script checks the cryptographic signatures of a Gluon manifest file and shows who signed the manifest.

Config Options:
* $MANIFEST_BASE: base URL that will be prepended to all requested manifest paths
* $PUBLIC_KEYS: list of public keys and their owner

URL Parameters:
* manifest: relative path to the manifest file that shall be checked
* format: either "text" (the default) to display textual output, or "json" to display JSON output

If an error is encountered (eg. manifest could not be read, or signature is invalid), the text "ERROR: " will be included in the output.
Signatures are verified against a list of known public keys.
