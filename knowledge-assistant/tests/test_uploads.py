import asyncio
import io

import pytest
from starlette.datastructures import Headers, UploadFile

from hardening.uploads import UploadError, save_upload

PNG = b"\x89PNG\r\n\x1a\n" + b"fake image body"
PDF = b"%PDF-1.7\nfake pdf body"


def make_upload(data: bytes, content_type: str, filename: str = "file.bin") -> UploadFile:
    return UploadFile(
        file=io.BytesIO(data),
        filename=filename,
        headers=Headers({"content-type": content_type}),
    )


def run(coro):
    return asyncio.run(coro)


def test_valid_png_is_saved_with_random_name(tmp_path):
    saved = run(save_upload(make_upload(PNG, "image/png", "cat.png"), tmp_path))
    assert saved.stored_name.endswith(".png")
    assert "cat" not in saved.stored_name
    assert (tmp_path / saved.stored_name).read_bytes() == PNG


def test_malicious_filename_never_reaches_the_path(tmp_path):
    upload = make_upload(PNG, "image/png", "../../etc/passwd.png")
    saved = run(save_upload(upload, tmp_path))
    assert "/" not in saved.stored_name
    assert ".." not in saved.stored_name
    assert [p.name for p in tmp_path.iterdir()] == [saved.stored_name]


def test_same_filename_gets_different_stored_names(tmp_path):
    a = run(save_upload(make_upload(PDF, "application/pdf", "a.pdf"), tmp_path))
    b = run(save_upload(make_upload(PDF, "application/pdf", "a.pdf"), tmp_path))
    assert a.stored_name != b.stored_name


def test_disallowed_content_type_gets_415(tmp_path):
    with pytest.raises(UploadError) as exc:
        run(save_upload(make_upload(b"#!/bin/sh\necho hi", "application/x-sh"), tmp_path))
    assert exc.value.status_code == 415


def test_svg_is_not_allowed(tmp_path):
    with pytest.raises(UploadError) as exc:
        run(save_upload(make_upload(b"<svg onload=alert(1)></svg>", "image/svg+xml"), tmp_path))
    assert exc.value.status_code == 415


def test_lying_content_type_is_caught_by_magic_bytes(tmp_path):
    with pytest.raises(UploadError) as exc:
        run(save_upload(make_upload(b"#!/bin/sh\necho hi", "image/png", "x.png"), tmp_path))
    assert exc.value.status_code == 415
    assert list(tmp_path.iterdir()) == []


def test_too_large_file_gets_413(tmp_path):
    big = PNG + b"x" * 200
    with pytest.raises(UploadError) as exc:
        run(save_upload(make_upload(big, "image/png"), tmp_path, max_bytes=100))
    assert exc.value.status_code == 413
    assert list(tmp_path.iterdir()) == []


def test_empty_file_gets_400(tmp_path):
    with pytest.raises(UploadError) as exc:
        run(save_upload(make_upload(b"", "image/png"), tmp_path))
    assert exc.value.status_code == 400


def test_text_file_with_null_byte_is_rejected(tmp_path):
    with pytest.raises(UploadError) as exc:
        run(save_upload(make_upload(b"hello\x00world", "text/plain"), tmp_path))
    assert exc.value.status_code == 415


def test_content_type_with_charset_is_accepted(tmp_path):
    saved = run(save_upload(make_upload(b"hello", "text/plain; charset=utf-8"), tmp_path))
    assert saved.stored_name.endswith(".txt")
