"""Unit tests for the forensic helpers and config modules."""

import os
import tempfile

import pytest

from velociraptor_forensic_mcp.config import Config, ForensicConfig, ServerConfig, VelociraptorConfig
from velociraptor_forensic_mcp.exceptions import SafePathError
from velociraptor_forensic_mcp.forensic_helpers import (
    get_file_metadata,
    hash_directory,
    scan_syslog,
    validate_safe_path,
)


class TestValidateSafePath:
    def test_path_inside_base(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = validate_safe_path(str(f), str(tmp_path))
        assert result == str(f.resolve())

    def test_path_outside_base_raises(self, tmp_path):
        with pytest.raises(SafePathError, match="outside"):
            validate_safe_path("/etc/passwd", str(tmp_path))

    def test_traversal_attack_raises(self, tmp_path):
        evil = str(tmp_path / ".." / ".." / "etc" / "passwd")
        with pytest.raises(SafePathError, match="outside"):
            validate_safe_path(evil, str(tmp_path))

    def test_base_itself_is_allowed(self, tmp_path):
        result = validate_safe_path(str(tmp_path), str(tmp_path))
        assert result == str(tmp_path.resolve())


class TestFileMetadata:
    def test_basic_metadata(self, tmp_path):
        f = tmp_path / "evidence.bin"
        f.write_bytes(b"\x00" * 128)
        meta = get_file_metadata(str(f), str(tmp_path))
        assert meta["size_bytes"] == 128
        assert len(meta["sha256"]) == 64
        assert "created_at" in meta
        assert "modified_at" in meta

    def test_outside_safe_base_raises(self, tmp_path):
        with pytest.raises(SafePathError):
            get_file_metadata("/etc/hostname", str(tmp_path))


class TestHashDirectory:
    def test_hashes_all_files(self, tmp_path):
        (tmp_path / "a.txt").write_text("aaa")
        (tmp_path / "b.txt").write_text("bbb")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.txt").write_text("ccc")
        result = hash_directory(str(tmp_path), str(tmp_path))
        assert len(result) == 3
        for v in result.values():
            assert len(v) == 64

    def test_not_a_directory_raises(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("x")
        with pytest.raises(SafePathError, match="Not a directory"):
            hash_directory(str(f), str(tmp_path))


class TestScanSyslog:
    def test_returns_list(self):
        result = scan_syslog("unlikely_keyword_abc123xyz")
        assert isinstance(result, list)
        assert len(result) >= 1


class TestConfig:
    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.delenv("VELOCIRAPTOR_API_KEY", raising=False)
        monkeypatch.delenv("SAFE_BASE", raising=False)
        cfg = Config.from_env()
        assert cfg.velociraptor.is_configured is False
        assert cfg.forensic.is_configured is False

    def test_disabled_tools_parsing(self, monkeypatch):
        monkeypatch.setenv("DISABLED_TOOLS", "vr_run_vql, local_scan_syslog")
        srv = ServerConfig.from_env()
        assert "vr_run_vql" in srv.disabled_tools
        assert "local_scan_syslog" in srv.disabled_tools

    def test_read_only_flag(self, monkeypatch):
        monkeypatch.setenv("READ_ONLY", "true")
        srv = ServerConfig.from_env()
        assert srv.read_only is True
