# Modifications copyright 2026 Forward Research. Apache-2.0.

from struct import pack
from hashlib import sha384
from time import sleep, time

import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU

CLA = 0x44
INS_SIGN_DATA_ITEM = 0x03
INS_GET_SIG = 0x10
INS_GET_PK = 0x20

TAGS = bytes.fromhex(
    "0c1a446174612d50726f746f636f6c04616f0e56617269616e740e616f2e544e2e31"
    "08547970650e4d6573736167650c416374696f6e105472616e73666572125265636970"
    "69656e7422726563697069656e742d61646472657373105175616e7469747908313030"
    "3000"
)


def wait_until_initialized(backend: BackendInterface) -> None:
    deadline = time() + 60
    while time() < deadline:
        try:
            response = backend.exchange(CLA, INS_GET_PK, 0, 0, b"")
            if response.status == 0x9000:
                return
        except ExceptionRAPDU as error:
            if error.status not in (0x6901, 0x6987):
                raise
        sleep(0.25)
    raise TimeoutError("Permaweb key generation did not finish")


def initialize_if_needed(backend: BackendInterface) -> None:
    try:
        response = backend.exchange(CLA, INS_GET_PK, 0, 0, b"")
        if response.status == 0x9000:
            return
    except ExceptionRAPDU as error:
        if error.status != 0x6987:
            raise

    backend.right_click()
    sleep(1)
    assert "Initialize" in str(backend.get_current_screen_content())
    backend.both_click()
    wait_until_initialized(backend)


def get_owner(backend: BackendInterface) -> bytes:
    first = backend.exchange(CLA, INS_GET_PK, 0, 0, b"")
    second = backend.exchange(CLA, INS_GET_PK, 0, 1, b"")
    assert first.status == 0x9000
    assert second.status == 0x9000
    return first.data + second.data


def data_item(owner: bytes) -> bytes:
    assert len(owner) == 512
    return b"".join(
        [
            b"\x01\x00",
            bytes(512),
            owner,
            b"\x01",
            bytes([0x22]) * 32,
            b"\x00",
            pack("<Q", 6),
            pack("<Q", len(TAGS)),
            TAGS,
            b"hello ao",
        ]
    )


def deep_hash(value):
    if isinstance(value, bytes):
        tag = sha384(f"blob{len(value)}".encode()).digest()
        return sha384(tag + sha384(value).digest()).digest()

    accumulator = sha384(f"list{len(value)}".encode()).digest()
    for child in value:
        accumulator = sha384(accumulator + deep_hash(child)).digest()
    return accumulator


def expected_digest(owner: bytes) -> bytes:
    return deep_hash(
        [
            b"dataitem",
            b"1",
            b"1",
            owner,
            bytes([0x22]) * 32,
            b"",
            TAGS,
            b"hello ao",
        ]
    )


def initialize_and_add(backend: BackendInterface, payload: bytes) -> bytes:
    response = backend.exchange(CLA, INS_SIGN_DATA_ITEM, 0, 0, b"")
    assert response.status == 0x9000
    chunks = [payload[i : i + 250] for i in range(0, len(payload), 250)]
    for chunk in chunks[:-1]:
        response = backend.exchange(CLA, INS_SIGN_DATA_ITEM, 1, 0, chunk)
        assert response.status == 0x9000
    return chunks[-1]


def test_rejects_non_arweave_signature_type(backend: BackendInterface):
    initialize_if_needed(backend)
    payload = bytearray(data_item(bytes(512)))
    payload[0] = 2
    final_chunk = initialize_and_add(backend, payload)
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, INS_SIGN_DATA_ITEM, 2, 0, final_chunk)
    assert error.value.status == 0x6984


def test_reviews_and_approves_ao_message(backend: BackendInterface):
    initialize_if_needed(backend)
    owner = get_owner(backend)
    final_chunk = initialize_and_add(backend, data_item(owner))
    reviewed_text = []
    with backend.exchange_async(CLA, INS_SIGN_DATA_ITEM, 2, 0, final_chunk):
        for _ in range(32):
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

    assert backend.last_async_response is not None
    assert backend.last_async_response.status == 0x9000
    assert len(backend.last_async_response.data) == 48
    assert backend.last_async_response.data == expected_digest(owner)

    review = " ".join(reviewed_text)
    for expected in ("ANS-104", "Target", "Data-Protocol", "Action", "Data size"):
        assert expected in review

    first = backend.exchange(CLA, INS_GET_SIG, 0, 0, b"")
    second = backend.exchange(CLA, INS_GET_SIG, 0, 1, b"")
    signature = first.data + second.data
    assert len(signature) == 512

    key = RSA.construct((int.from_bytes(owner, "big"), 65537))
    digest = SHA256.new(backend.last_async_response.data)
    pss.new(key, salt_bytes=32).verify(digest, signature)


def test_reviews_and_rejects_ao_message(backend: BackendInterface):
    initialize_if_needed(backend)
    owner = get_owner(backend)
    final_chunk = initialize_and_add(backend, data_item(owner))
    reviewed_text = []

    with pytest.raises(ExceptionRAPDU) as error:
        with backend.exchange_async(CLA, INS_SIGN_DATA_ITEM, 2, 0, final_chunk):
            for _ in range(32):
                screen_text = str(backend.get_current_screen_content())
                reviewed_text.append(screen_text)
                if "REJECT" in screen_text.upper():
                    backend.both_click()
                    break
                backend.right_click()
                try:
                    backend.wait_for_screen_change(1)
                except TimeoutError:
                    sleep(0.2)
            else:
                pytest.fail(f"Reject screen was not reached: {reviewed_text}")

    assert error.value.status == 0x6986
    assert any("REJECT" in screen.upper() for screen in reviewed_text)
