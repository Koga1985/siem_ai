"""
Unit tests for playbook safety checks
"""

import os
import sys

import pytest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../services/ai_generator")
)  # noqa: E402

from safety_checks import SafetyCheckResult, approve_playbook  # noqa: E402


@pytest.fixture
def safe_playbook():
    """A safe playbook with all required features"""
    return """---
- name: Safe remediation playbook
  hosts: linux_servers
  gather_facts: no
  pre_tasks:
    - name: Require approval
      assert:
        that: [ approve_change | default(false) ]
        fail_msg: "Approval required"
  tasks:
    - name: Update package
      package:
        name: openssl
        state: latest
      check_mode: yes
"""


@pytest.fixture
def unsafe_playbook_no_check_mode():
    """Unsafe: missing check_mode"""
    return """---
- name: Unsafe playbook
  hosts: linux_servers
  pre_tasks:
    - name: Require approval
      assert:
        that: [ approve_change | default(false) ]
  tasks:
    - name: Delete files
      file:
        path: /tmp/test
        state: absent
"""


@pytest.fixture
def unsafe_playbook_banned_module():
    """Unsafe: uses banned shell module"""
    return """---
- name: Dangerous playbook
  hosts: linux_servers
  pre_tasks:
    - name: Require approval
      assert:
        that: [ approve_change | default(false) ]
  tasks:
    - name: Run shell command
      shell: rm -rf /tmp/*
      check_mode: yes
"""


@pytest.fixture
def unsafe_playbook_all_hosts():
    """Unsafe: targets all hosts"""
    return """---
- name: Too broad playbook
  hosts: all
  pre_tasks:
    - name: Require approval
      assert:
        that: [ approve_change | default(false) ]
  tasks:
    - name: Update system
      package:
        name: '*'
        state: latest
      check_mode: yes
"""


@pytest.fixture
def unsafe_playbook_no_approval():
    """Unsafe: missing approval gate"""
    return """---
- name: No approval playbook
  hosts: linux_servers
  tasks:
    - name: Update package
      package:
        name: openssl
        state: latest
      check_mode: yes
"""


@pytest.fixture
def test_event():
    """Sample security event"""
    return {
        "event": {"id": "test-123", "category": "malware"},
        "alert": {"severity": 7, "rule": "test-rule", "risk_score": 80},
    }


class TestPlaybookSafetyChecker:
    """Test the PlaybookSafetyChecker class"""

    def test_safe_playbook_passes(self, safe_playbook, test_event):
        """Test that a safe playbook passes all checks"""
        result = approve_playbook(safe_playbook, test_event)

        assert result.approved is True
        assert len(result.reasons) == 0

    def test_missing_check_mode_fails(self, unsafe_playbook_no_check_mode, test_event):
        """Test that missing check_mode fails"""
        result = approve_playbook(unsafe_playbook_no_check_mode, test_event)

        assert result.approved is False
        assert any("check_mode" in reason for reason in result.reasons)

    def test_banned_module_fails(self, unsafe_playbook_banned_module, test_event):
        """Test that banned modules fail"""
        result = approve_playbook(unsafe_playbook_banned_module, test_event)

        assert result.approved is False
        assert any("shell" in reason.lower() for reason in result.reasons)

    def test_all_hosts_fails(self, unsafe_playbook_all_hosts, test_event):
        """Test that targeting 'all' hosts fails"""
        result = approve_playbook(unsafe_playbook_all_hosts, test_event)

        assert result.approved is False
        assert any("all" in reason.lower() for reason in result.reasons)

    def test_missing_approval_fails(self, unsafe_playbook_no_approval, test_event):
        """Test that missing approval gate fails"""
        result = approve_playbook(unsafe_playbook_no_approval, test_event)

        assert result.approved is False
        assert any("approval" in reason.lower() for reason in result.reasons)

    def test_invalid_yaml_fails(self, test_event):
        """Test that invalid YAML fails"""
        invalid_yaml = "this is not: valid: yaml: content:"
        result = approve_playbook(invalid_yaml, test_event)

        assert result.approved is False
        assert any("yaml" in reason.lower() for reason in result.reasons)

    def test_dangerous_pattern_detection(self, test_event):
        """Test detection of dangerous patterns"""
        dangerous_playbook = """---
- name: Dangerous playbook
  hosts: linux_servers
  pre_tasks:
    - name: Require approval
      assert:
        that: [ approve_change | default(false) ]
  tasks:
    - name: Dangerous command
      command: rm -rf /tmp/data
      check_mode: yes
"""
        result = approve_playbook(dangerous_playbook, test_event)

        # Should fail due to dangerous pattern or banned 'command' module
        assert result.approved is False

    def test_high_severity_warning(self, safe_playbook):
        """Test that high severity events generate warnings"""
        high_severity_event = {
            "event": {"id": "test-456", "category": "critical"},
            "alert": {"severity": 9, "rule": "critical-rule", "risk_score": 95},
        }

        result = approve_playbook(safe_playbook, high_severity_event)

        # Should still approve but with warnings
        assert result.approved is True
        assert len(result.warnings) > 0
        assert any("severity" in warning.lower() for warning in result.warnings)

    def test_empty_playbook_fails(self, test_event):
        """Test that empty playbook fails"""
        result = approve_playbook("", test_event)

        assert result.approved is False
        assert any("empty" in reason.lower() for reason in result.reasons)


class TestSafetyCheckResult:
    """Test SafetyCheckResult dataclass"""

    def test_result_with_no_warnings(self):
        """Test result creation without warnings"""
        result = SafetyCheckResult(approved=True, reasons=[])

        assert result.approved is True
        assert result.warnings == []

    def test_result_with_warnings(self):
        """Test result creation with warnings"""
        result = SafetyCheckResult(
            approved=True, reasons=[], warnings=["High severity event"]
        )

        assert result.approved is True
        assert len(result.warnings) == 1
