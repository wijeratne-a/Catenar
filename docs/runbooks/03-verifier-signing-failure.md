# Runbook: Verifier Signing Failure

## Symptom
- Verification requests return 500
- Logs: "failed to sign" or "key provider error"

## Causes
- Missing or invalid `AEGIS_SIGNING_KEY_HEX`
- KMS unreachable (if keyProvider: kms)
- Secret not mounted or wrong key name

## Checks

1. **Secret exists**:
   ```bash
   kubectl get secret aegis-signing-key -o yaml
   ```

2. **Key format**: Must be 64 hex chars (32 bytes) for Ed25519 private key.

3. **KMS** (if applicable): Verify AWS credentials, KMS key ID, region.

## Resolution

- **Recreate secret**:
  ```bash
  kubectl create secret generic aegis-signing-key \
    --from-literal=AEGIS_SIGNING_KEY_HEX=<64-char-hex> \
    --dry-run=client -o yaml | kubectl apply -f -
  ```
- **Restart verifier** after secret update.

## Note
Rotating the signing key invalidates all existing receipts. Plan key rotation during maintenance.
