# NEAR Integration Compatibility Notes

## Gateway Compatibility

The gateway handles app IDs as hex-encoded strings internally. For NEAR:
- App IDs in attestations are still bytes (as per dstack spec)
- auth-near converts hex app_id to NEAR AccountId format when calling contracts
- Gateway routing uses app_id from SNI parsing - works with any string format
- **Status**: ✅ Compatible - no changes needed

## Guest Agent Compatibility

The guest-agent uses app_id as `Vec<u8>` internally:
- App IDs come from attestation (bytes)
- Encoded/decoded as hex strings when needed
- auth-near handles the conversion to NEAR AccountId format
- **Status**: ✅ Compatible - no changes needed

## App ID Format Considerations

- **Attestation**: App IDs are always bytes (hex-encoded)
- **NEAR Contracts**: Expect AccountId (string format like "app.near")
- **Conversion**: auth-near converts hex → AccountId when calling NEAR contracts
- **Storage**: Gateway/guest-agent store app_id as hex strings internally

## Potential Future Enhancements

1. **App ID Mapping**: Consider a mapping layer if hex addresses need to map to NEAR AccountIds
2. **SNI Parsing**: Gateway SNI parsing works with any string format, but ensure AccountId format is URL-safe
3. **Validation**: Add validation to ensure AccountId format is valid NEAR account ID


