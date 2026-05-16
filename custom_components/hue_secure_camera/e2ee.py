"""E2EE key decryption for Philips Hue Secure cameras.

Reverse-engineered from libapp.so (Dart AOT) and libml_kem.so (Kyber768).

Key derivation chain:
  1. PBKDF2-SHA256(passphrase, salt, 100 000 iters, 32 bytes) → master_key
  2. HKDF-SHA256(master_key, info="app_key") → ecdh_private_key (P-256)
  3. HKDF-SHA256(master_key, info="ml_kem_key") → seed → Kyber768 keypair
  4. KeyEnvelope (base64) contains ciphertext encrypted by camera with our pubkey
  5. Kyber768.dec(ciphertext, secret_key) → shared_secret (32 bytes)
  6. shared_secret == FrameCryptor AES-GCM key (keyIndex=0)

The KeyEnvelope wire format (PQC path, _KeyEnvelopeEntryMlKem768EciesP256Aes256):
  - Header: version(1B) + type(1B)
  - Entry:  kyber_ciphertext(1088B) + ecies_ciphertext(variable)
  - The ECIES path uses P-256 ECDH + HKDF + AES-256-GCM
  - Either path alone yields the 32-byte AES-GCM FrameCryptor key
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
    generate_private_key,
    SECP256R1,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_LOGGER = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

_PBKDF2_ITERS = 100_000
_KEY_LEN = 32

# HKDF info strings used in Dart code
_INFO_APP_KEY = b"app_key"
_INFO_ML_KEM = b"ml_kem_key"
_INFO_ECIES_AES = b"ecies_aes"

# Kyber768 sizes
_KYBER_PK_LEN = 1184
_KYBER_CT_LEN = 1088
_KYBER_SK_LEN = 2400
_KYBER_SS_LEN = 32

# KeyEnvelope version / type bytes (reverse-engineered)
_KE_VERSION = 0x01
_KE_TYPE_PQC = 0x02   # MlKem768EciesP256Aes256
_KE_TYPE_OLD = 0x01   # ECIES-only (legacy)


# ─── PBKDF2 + HKDF helpers ────────────────────────────────────────────────────

def _pbkdf2(passphrase: str, salt: bytes) -> bytes:
    """Derive master key from passphrase using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_PBKDF2_ITERS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _hkdf_expand(master: bytes, info: bytes, length: int = _KEY_LEN) -> bytes:
    """Expand master key with HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master)


# ─── Kyber768 (via ctypes → libml_kem.so) ────────────────────────────────────

_kyber_lib = None


def _load_kyber() -> bool:
    """Lazy-load the Kyber768 shared library."""
    global _kyber_lib
    if _kyber_lib is not None:
        return True

    import ctypes, ctypes.util

    # Try the extracted .so first (ARM64 won't run on x86 Mac; use pure-Python fallback)
    for path in [
        "/tmp/hue_libs/lib/arm64-v8a/libml_kem.so",
        "/usr/local/lib/libml_kem.so",
    ]:
        try:
            _kyber_lib = ctypes.CDLL(path)
            _kyber_lib.pqcrystals_kyber768_ref_keypair_derand.restype = ctypes.c_int
            _kyber_lib.pqcrystals_kyber768_ref_keypair_derand.argtypes = [
                ctypes.c_char_p,  # pk (out)
                ctypes.c_char_p,  # sk (out)
                ctypes.c_char_p,  # seed (in, 64 bytes)
            ]
            _kyber_lib.pqcrystals_kyber768_ref_dec.restype = ctypes.c_int
            _kyber_lib.pqcrystals_kyber768_ref_dec.argtypes = [
                ctypes.c_char_p,  # ss (out)
                ctypes.c_char_p,  # ct (in)
                ctypes.c_char_p,  # sk (in)
            ]
            return True
        except OSError:
            continue

    _LOGGER.warning(
        "libml_kem.so not loadable on this platform; will use Python Kyber768 fallback"
    )
    return False


def _kyber768_keygen_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Generate deterministic Kyber768 keypair from a 64-byte seed.

    Returns (public_key, secret_key).
    Uses libml_kem.so if available, otherwise falls back to the
    'kyber-py' pure-Python implementation.
    """
    if _load_kyber():
        import ctypes

        pk = ctypes.create_string_buffer(_KYBER_PK_LEN)
        sk = ctypes.create_string_buffer(_KYBER_SK_LEN)
        seed64 = seed[:32] + seed[32:64] if len(seed) >= 64 else (seed + b"\x00" * 64)[:64]
        ret = _kyber_lib.pqcrystals_kyber768_ref_keypair_derand(pk, sk, seed64)
        if ret != 0:
            raise RuntimeError(f"Kyber768 keygen failed: {ret}")
        return bytes(pk), bytes(sk)

    # Pure-Python fallback (requires kyber-py: pip install kyber-py)
    try:
        from kyber import Kyber768  # type: ignore[import]

        pk, sk = Kyber768.keygen_derand(seed[:64] if len(seed) >= 64 else seed.ljust(64, b"\x00"))
        return pk, sk
    except ImportError:
        raise RuntimeError(
            "Kyber768 library not available. "
            "Install 'kyber-py' (pip install kyber-py) or provide libml_kem.so."
        )


def _kyber768_dec(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Decapsulate Kyber768 to get the shared secret."""
    if _load_kyber():
        import ctypes

        ss = ctypes.create_string_buffer(_KYBER_SS_LEN)
        ret = _kyber_lib.pqcrystals_kyber768_ref_dec(ss, ciphertext, secret_key)
        if ret != 0:
            raise RuntimeError(f"Kyber768 dec failed: {ret}")
        return bytes(ss)

    try:
        from kyber import Kyber768  # type: ignore[import]

        return Kyber768.dec(secret_key, ciphertext)
    except ImportError:
        raise RuntimeError("Kyber768 library not available.")


# ─── ECIES P-256 decryption ───────────────────────────────────────────────────

def _ecies_p256_decrypt(
    private_key_bytes: bytes, ephemeral_pub_bytes: bytes, ciphertext: bytes
) -> bytes:
    """Decrypt ECIES ciphertext using our P-256 private key.

    Hue's ECIES scheme:
      - Ephemeral sender public key (65 bytes, uncompressed)
      - ECDH(our_priv, ephemeral_pub) → shared_point
      - HKDF-SHA256(shared_point, info="ecies_aes") → AES-256 key (32 B)
      - AES-256-GCM(iv=ciphertext[:12], aad=b"", ct=ciphertext[12:-16], tag=ciphertext[-16:])
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateNumbers,
        SECP256R1,
    )
    from cryptography.hazmat.primitives import serialization as ser

    priv = serialization.load_der_private_key(private_key_bytes, password=None)
    pub = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), ephemeral_pub_bytes)

    shared = priv.exchange(ECDH(), pub)
    aes_key = _hkdf_expand(shared, _INFO_ECIES_AES, 32)

    iv = ciphertext[:12]
    tag = ciphertext[-16:]
    ct = ciphertext[12:-16]
    aead = AESGCM(aes_key)
    return aead.decrypt(iv, ct + tag, None)


# ─── KeyEnvelope parser ───────────────────────────────────────────────────────

@dataclass
class KeyEnvelopeEntry:
    kyber_ciphertext: bytes | None
    ecies_ephemeral_pub: bytes | None
    ecies_ciphertext: bytes | None
    envelope_type: int = _KE_TYPE_PQC


def parse_key_envelope(b64_envelope: str) -> list[KeyEnvelopeEntry]:
    """Parse a base64-encoded KeyEnvelope binary blob.

    Wire format (best-effort reverse-engineered):
      [0]    version  (0x01)
      [1]    num_entries
      per entry:
        [0]  type  (0x01=ECIES, 0x02=MlKem768EciesP256Aes256)
        if type==0x02:
          [1..1088]   kyber ciphertext
          [1089]      ecies_pub_len (varint or fixed 65)
          [...]       ecies ephemeral public key
          [...]       ecies ciphertext (rest until next entry)
    """
    raw = base64.b64decode(b64_envelope + "==")
    entries: list[KeyEnvelopeEntry] = []

    if len(raw) < 2:
        return entries

    # version = raw[0]
    idx = 2  # skip version + reserved

    while idx < len(raw):
        if idx >= len(raw):
            break
        entry_type = raw[idx]
        idx += 1

        if entry_type == _KE_TYPE_PQC:
            # Kyber768 ciphertext (1088 bytes)
            if idx + _KYBER_CT_LEN > len(raw):
                _LOGGER.warning("KeyEnvelope: truncated kyber ciphertext")
                break
            kyber_ct = raw[idx: idx + _KYBER_CT_LEN]
            idx += _KYBER_CT_LEN

            # Ephemeral P-256 public key (65 bytes uncompressed 0x04...)
            if idx + 65 > len(raw):
                _LOGGER.warning("KeyEnvelope: no room for ecies pub")
                break
            ecies_pub = raw[idx: idx + 65]
            idx += 65

            # AES-GCM ciphertext: rest of entry = 12 (IV) + payload + 16 (tag)
            # For a 32-byte plaintext: 12 + 32 + 16 = 60 bytes
            ecies_ct_len = 12 + 32 + 16  # 60 bytes
            ecies_ct = raw[idx: idx + ecies_ct_len]
            idx += ecies_ct_len

            entries.append(KeyEnvelopeEntry(kyber_ct, ecies_pub, ecies_ct, _KE_TYPE_PQC))

        elif entry_type == _KE_TYPE_OLD:
            # Legacy ECIES-only entry
            if idx + 65 > len(raw):
                break
            ecies_pub = raw[idx: idx + 65]
            idx += 65
            ecies_ct_len = 12 + 32 + 16
            ecies_ct = raw[idx: idx + ecies_ct_len]
            idx += ecies_ct_len
            entries.append(KeyEnvelopeEntry(None, ecies_pub, ecies_ct, _KE_TYPE_OLD))

        else:
            _LOGGER.warning("KeyEnvelope: unknown entry type 0x%02x at idx %d", entry_type, idx)
            break

    return entries


# ─── Public API ───────────────────────────────────────────────────────────────

@dataclass
class E2EEKeyResult:
    """Decrypted FrameCryptor key."""
    frame_key: bytes          # 32 bytes, AES-GCM key for FrameCryptor
    key_index: int = 0        # always 0 for Hue cameras


def derive_frame_key(
    passphrase: str,
    salt: bytes,
    b64_key_envelope: str,
) -> Optional[E2EEKeyResult]:
    """Full E2EE key derivation.

    Args:
        passphrase: User's Hue E2EE passphrase
        salt:       Salt bytes from the key envelope or stored state
        b64_key_envelope: base64KeyEnvelope from the live-stream API response

    Returns:
        E2EEKeyResult with the 32-byte FrameCryptor AES-GCM key,
        or None if decryption fails.
    """
    if not passphrase or not b64_key_envelope:
        return None

    try:
        # 1. Derive master key
        master = _pbkdf2(passphrase, salt)

        # 2. Derive Kyber768 seed (64 bytes)
        ml_kem_seed = _hkdf_expand(master, _INFO_ML_KEM, 64)

        # 3. Generate deterministic Kyber768 keypair from seed
        _pk, sk = _kyber768_keygen_from_seed(ml_kem_seed)

        # 4. Parse KeyEnvelope
        entries = parse_key_envelope(b64_key_envelope)
        if not entries:
            _LOGGER.error("E2EE: empty KeyEnvelope")
            return None

        for entry in entries:
            try:
                if entry.envelope_type == _KE_TYPE_PQC and entry.kyber_ciphertext:
                    # Kyber768 decapsulation
                    shared_secret = _kyber768_dec(entry.kyber_ciphertext, sk)
                    return E2EEKeyResult(frame_key=shared_secret)

                if entry.ecies_ephemeral_pub and entry.ecies_ciphertext:
                    # ECIES fallback: derive P-256 private key from master
                    priv_bytes = _hkdf_expand(master, _INFO_APP_KEY, 32)
                    # Wrap as DER P-256 private key
                    from cryptography.hazmat.primitives.asymmetric.ec import (
                        EllipticCurvePrivateNumbers,
                    )
                    from cryptography.hazmat.primitives.asymmetric.utils import (
                        decode_dss_signature,
                    )
                    priv_int = int.from_bytes(priv_bytes, "big")
                    priv_key = EllipticCurvePrivateNumbers(
                        priv_int,
                        EllipticCurvePublicKey.from_encoded_point(
                            SECP256R1(),
                            # re-derive the expected pub
                            generate_private_key(SECP256R1())
                            .private_bytes(
                                serialization.Encoding.DER,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption(),
                            ),
                        ).public_numbers(),
                    ).private_key()
                    priv_der = priv_key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                    frame_key = _ecies_p256_decrypt(
                        priv_der, entry.ecies_ephemeral_pub, entry.ecies_ciphertext
                    )
                    return E2EEKeyResult(frame_key=frame_key)

            except Exception as exc:
                _LOGGER.debug("E2EE entry decryption failed: %s", exc)
                continue

    except Exception as exc:
        _LOGGER.error("E2EE key derivation failed: %s", exc)

    return None


def apply_frame_key_to_rtp(rtp_payload: bytes, frame_key: bytes) -> bytes:
    """Decrypt a FrameCryptor-encrypted RTP payload.

    FrameCryptor (libwebrtc) AES-GCM layout (simplified):
      - First byte: unencrypted header info
      - Bytes 1..unencrypted_size: unencrypted header
      - Remaining: IV(12B) || ciphertext || GCM-tag(16B)

    This is a best-effort implementation based on the WebRTC FrameCryptor spec.
    The exact header layout may vary per codec.
    """
    if len(rtp_payload) < 29:  # minimum: 1 header + 12 IV + 16 tag
        return rtp_payload

    try:
        unenc_size = rtp_payload[0] & 0x0F  # lower nibble
        header = rtp_payload[: 1 + unenc_size]
        body = rtp_payload[1 + unenc_size:]

        if len(body) < 28:
            return rtp_payload

        iv = body[:12]
        ct_with_tag = body[12:]

        aead = AESGCM(frame_key)
        plaintext = aead.decrypt(iv, ct_with_tag, header)
        return header + plaintext

    except Exception:
        return rtp_payload  # return as-is if decryption fails
