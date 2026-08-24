# Modifications copyright 2026 Forward Research. Apache-2.0.

from base64 import urlsafe_b64encode
from hashlib import sha512
from time import sleep

import pytest
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU

from test_ans104 import (
    CLA,
    INS_GET_SIG,
    INS_SIGN_DATA_ITEM,
    get_owner,
    initialize_if_needed,
)

INS_SIGN_HTTP = 0x04


def signature_base(owner: bytes) -> bytes:
    keyid = urlsafe_b64encode(owner).decode().rstrip("=")
    return (
        '"action": Ping\n'
        '"body": hello\n'
        '"data-protocol": ao\n'
        '"signing-format": httpsig\n'
        '"@signature-params": ("action" "body" "data-protocol" "signing-format")'
        f';alg="rsa-pss-sha512";keyid="{keyid}"'
    ).encode()


def initialize_and_add(backend: BackendInterface, payload: bytes) -> bytes:
    response = backend.exchange(CLA, INS_SIGN_HTTP, 0, 0, b"")
    assert response.status == 0x9000
    chunks = [payload[i : i + 200] for i in range(0, len(payload), 200)]
    for chunk in chunks[:-1]:
        response = backend.exchange(CLA, INS_SIGN_HTTP, 1, 0, chunk)
        assert response.status == 0x9000
    return chunks[-1]


def test_requires_fresh_command_bound_chunk_state(backend: BackendInterface):
    initialize_if_needed(backend)

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, INS_SIGN_HTTP, 1, 0, b'orphan chunk')
    assert error.value.status == 0x6987

    assert backend.exchange(CLA, INS_SIGN_DATA_ITEM, 0, 0, b'').status == 0x9000
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, INS_SIGN_HTTP, 1, 0, b'cross-command chunk')
    assert error.value.status == 0x6B00

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, INS_SIGN_DATA_ITEM, 2, 0, b'final after reset')
    assert error.value.status == 0x6987


def test_reviews_and_signs_mainnet_http_signature(backend: BackendInterface):
    initialize_if_needed(backend)
    owner = get_owner(backend)
    base = signature_base(owner)
    final_chunk = initialize_and_add(backend, base)
    reviewed_text = []

    with backend.exchange_async(CLA, INS_SIGN_HTTP, 2, 0, final_chunk):
        for _ in range(64):
            screen_text = str(backend.get_current_screen_content())
            reviewed_text.append(screen_text)
            if "APPROVE" in screen_text.upper():
                backend.both_click()
                break
            backend.right_click()
            try:
                backend.wait_for_screen_change(1)
            except TimeoutError:
                sleep(0.2)
        else:
            pytest.fail(f"Approve screen was not reached: {reviewed_text}")

    assert backend.last_async_response.status == 0x9000
    assert backend.last_async_response.data == sha512(base).digest()
    review = " ".join(reviewed_text)
    for expected in ("HTTP", "action", "Ping", "data-protocol", "signing-format"):
        assert expected in review

    first = backend.exchange(CLA, INS_GET_SIG, 0, 0, b"")
    second = backend.exchange(CLA, INS_GET_SIG, 0, 1, b"")
    signature = first.data + second.data
    key = RSA.construct((int.from_bytes(owner, "big"), 65537))
    pss.new(key, salt_bytes=64).verify(SHA512.new(base), signature)


def test_rejects_non_mainnet_http_algorithm(backend: BackendInterface):
    initialize_if_needed(backend)
    payload = signature_base(get_owner(backend)).replace(b"rsa-pss-sha512", b"rsa-pss-sha256")
    final_chunk = initialize_and_add(backend, payload)
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, INS_SIGN_HTTP, 2, 0, final_chunk)
    assert error.value.status == 0x6984


def test_rejects_keyid_for_another_owner(backend: BackendInterface):
    initialize_if_needed(backend)
    payload = signature_base(bytes([0x42]) * 512)
    final_chunk = initialize_and_add(backend, payload)
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, INS_SIGN_HTTP, 2, 0, final_chunk)
    assert error.value.status == 0x6984
