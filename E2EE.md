# Relay behavior with media E2EE

Symposium Relay is intentionally not a key endpoint. Production signaling has no
conference media-key field, the relay does not derive or store frame keys, and it
does not decrypt media. It forwards RTP packets so Android endpoints can apply
and verify `frame-aes-gcm-v1` themselves.

The room secret is distributed in an invitation URL fragment (`#e2ee=...`). A
fragment is handled locally by the browser/Android client and is never included
in the HTTP request or WebSocket join message. The relay still sees the metadata
needed to run an SFU: participant network addresses, room membership, track type,
SSRC/RTP routing data, packet sizes, and timing.

Because encoded frame bodies are opaque, server-side recording, transcoding,
mixing, moderation based on media content, and media inspection are incompatible
with E2EE unless a trusted endpoint is explicitly given the room secret. No such
endpoint exists in the relay.

The Android/relay integration test starts a standalone TLS relay and an
independent Pion participant. The host participant and Android authenticate and
decrypt each other's encoded AES-GCM frames after they traverse the relay. The
test also checks that the secret is absent from relay logs. The separate frame
wire-format test verifies that modified ciphertext is rejected.
