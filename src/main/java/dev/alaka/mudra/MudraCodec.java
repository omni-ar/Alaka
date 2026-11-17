package dev.alaka.mudra;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;

/**
 * The encoding and signature envelope shared by every Mudra token type.
 *
 * <p>Canonical payload: a domain tag followed by fields, each a 4-byte big-endian length and its
 * bytes. Length prefixes make the encoding unambiguous, and the domain tag makes a signature over
 * one token type useless as a signature over another. Token: {@code <prefix>.<base64url payload>.
 * <base64url Ed25519 signature>}, unpadded.
 */
final class MudraCodec {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_DECODER = Base64.getUrlDecoder();

    private MudraCodec() {
    }

    /** Writes a canonical payload. */
    static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Writer(String domain) {
            field(domain);
        }

        Writer field(String value) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            out.writeBytes(ByteBuffer.allocate(4).putInt(bytes.length).array());
            out.writeBytes(bytes);
            return this;
        }

        Writer field(long value) {
            return field(Long.toString(value));
        }

        byte[] bytes() {
            return out.toByteArray();
        }
    }

    /** Reads a canonical payload; every malformation is an {@link IllegalArgumentException}. */
    static final class Reader {
        private final ByteBuffer in;

        Reader(byte[] payload, String domain) {
            this.in = ByteBuffer.wrap(payload);
            if (!text().equals(domain)) {
                throw new IllegalArgumentException("not a " + domain + " encoding");
            }
        }

        String text() {
            if (in.remaining() < 4) {
                throw new IllegalArgumentException("truncated encoding");
            }
            int length = in.getInt();
            if (length < 0 || length > in.remaining()) {
                throw new IllegalArgumentException("field length " + length + " out of range");
            }
            byte[] value = new byte[length];
            in.get(value);
            return new String(value, StandardCharsets.UTF_8);
        }

        long number() {
            return Long.parseLong(text());
        }

        void end() {
            if (in.hasRemaining()) {
                throw new IllegalArgumentException("trailing bytes after the last field");
            }
        }
    }

    /** A token split into its signed payload and signature. */
    record Opened(byte[] payload, byte[] signature) {
    }

    /**
     * Rejects an encoding that decoded but is not the canonical form of what it decoded to, so a
     * token has exactly one byte form.
     */
    static void requireCanonical(byte[] reEncoded, byte[] original) {
        if (!Arrays.equals(reEncoded, original)) {
            throw new IllegalArgumentException("encoding is not canonical");
        }
    }

    static String seal(String prefix, byte[] payload, PrivateKey key) {
        try {
            Signature ed25519 = Signature.getInstance("Ed25519");
            ed25519.initSign(key);
            ed25519.update(payload);
            return prefix + "." + B64.encodeToString(payload) + "." + B64.encodeToString(ed25519.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    /**
     * Splits a token.
     *
     * @throws IllegalArgumentException if it is not {@code <prefix>.<b64>.<b64>}
     */
    static Opened open(String token, String prefix) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !prefix.equals(parts[0])) {
            throw new IllegalArgumentException("expected " + prefix + ".<claims>.<signature>");
        }
        return new Opened(B64_DECODER.decode(parts[1]), B64_DECODER.decode(parts[2]));
    }

    static boolean verify(PublicKey key, Opened opened) {
        try {
            Signature ed25519 = Signature.getInstance("Ed25519");
            ed25519.initVerify(key);
            ed25519.update(opened.payload());
            return ed25519.verify(opened.signature());
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    static void requireEd25519(PrivateKey key) {
        if (!"Ed25519".equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("not an Ed25519 key: " + key.getAlgorithm());
        }
    }
}
