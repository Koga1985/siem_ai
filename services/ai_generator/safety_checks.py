"""
Comprehensive safety checks for generated Ansible playbooks
"""

import yaml
import re
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class SafetyCheckResult:
    """Result of safety check evaluation"""

    approved: bool
    reasons: List[str]
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class PlaybookSafetyChecker:
    """Comprehensive safety checks for Ansible playbooks"""

    # Dangerous modules that should never be allowed
    BANNED_MODULES = [
        "shell",  # Too risky without strict validation
        "command",  # Prefer specific modules
        "raw",  # Bypasses normal checks
        "script",  # Executes arbitrary scripts
    ]

    # High-risk modules requiring extra scrutiny
    HIGH_RISK_MODULES = [
        "file",  # Can delete files
        "lineinfile",  # Can modify system files
        "replace",  # Can modify system files
        "user",  # Creates/modifies users
        "group",  # Creates/modifies groups
        "service",  # Stops services
        "systemd",  # System control
        "reboot",  # Reboots systems
        "firewalld",  # Modifies firewall
        "iptables",  # Modifies firewall
    ]

    # Dangerous patterns in task names or content
    DANGEROUS_PATTERNS = [
        r"rm\s+-rf",  # Recursive delete
        r"dd\s+if=",  # Disk operations
        r"mkfs",  # Format filesystem
        r"fdisk",  # Partition operations
        r"\bkill\b.*-9",  # Force kill
        r"shutdown",  # System shutdown
        r"init\s+0",  # System halt
        r"init\s+6",  # System reboot
    ]

    # Required safety features
    REQUIRED_FEATURES = {
        "check_mode": ["check_mode: yes", "check_mode: true"],
        "approval_gate": ["approve_change", "assert"],
    }

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def check_check_mode(self, playbook: Dict) -> bool:
        """Verify check_mode is enabled on state-changing tasks"""
        has_check_mode = False

        for play in playbook:
            if not isinstance(play, dict):
                continue

            # Check tasks
            for task in play.get("tasks", []):
                if not isinstance(task, dict):
                    continue

                # Check for state-changing operations
                task_modules = [
                    k
                    for k in task.keys()
                    if not k.startswith("_")
                    and k not in ["name", "when", "tags", "register"]
                ]

                for module in task_modules:
                    # Verify check_mode is set
                    if task.get("check_mode") in [True, "yes", "true"]:
                        has_check_mode = True
                    elif module in self.HIGH_RISK_MODULES:
                        self.warnings.append(
                            f"High-risk module '{module}' without explicit check_mode"
                        )

        return has_check_mode

    def check_approval_gate(self, playbook: Dict) -> bool:
        """Verify playbook has approval assertion"""
        has_approval = False

        for play in playbook:
            if not isinstance(play, dict):
                continue

            # Check pre_tasks for approval assertion
            for task in play.get("pre_tasks", []):
                if not isinstance(task, dict):
                    continue

                # Look for assert with approve_change
                if "assert" in task:
                    assert_content = str(task["assert"])
                    if "approve_change" in assert_content:
                        has_approval = True

        return has_approval

    def check_dangerous_modules(self, playbook: Dict) -> bool:
        """Check for banned or dangerous modules"""
        found_dangerous = False

        for play in playbook:
            if not isinstance(play, dict):
                continue

            for task in (
                play.get("tasks", [])
                + play.get("pre_tasks", [])
                + play.get("post_tasks", [])
            ):
                if not isinstance(task, dict):
                    continue

                for module in self.BANNED_MODULES:
                    if module in task:
                        self.errors.append(
                            f"Banned module '{module}' found in task: {task.get('name', 'unnamed')}"
                        )
                        found_dangerous = True

        return not found_dangerous

    def check_dangerous_patterns(self, playbook_yaml: str) -> bool:
        """Check for dangerous command patterns"""
        found_dangerous = False

        for pattern in self.DANGEROUS_PATTERNS:
            matches = re.findall(pattern, playbook_yaml, re.IGNORECASE)
            if matches:
                self.errors.append(f"Dangerous pattern '{pattern}' found in playbook")
                found_dangerous = True

        return not found_dangerous

    def check_host_targeting(self, playbook: Dict) -> bool:
        """Verify playbook doesn't target 'all' or wildcard hosts"""
        safe_targeting = True

        for play in playbook:
            if not isinstance(play, dict):
                continue

            hosts = play.get("hosts", "")
            if hosts in ["all", "*"]:
                self.errors.append(
                    f"Playbook targets '{hosts}' - too broad, must use specific inventory groups"
                )
                safe_targeting = False
            elif not hosts or hosts == "":
                self.errors.append("Playbook has no hosts defined")
                safe_targeting = False

        return safe_targeting

    def check_yaml_structure(self, playbook_yaml: str) -> tuple[bool, Any]:
        """Validate YAML structure"""
        try:
            playbook = yaml.safe_load(playbook_yaml)
            if not playbook:
                self.errors.append("Empty playbook")
                return False, None

            if not isinstance(playbook, list):
                self.errors.append("Playbook must be a list of plays")
                return False, None

            return True, playbook

        except yaml.YAMLError as e:
            self.errors.append(f"Invalid YAML: {str(e)}")
            return False, None

    def check_event_severity(self, evt: Dict) -> bool:
        """Check if event severity requires additional controls"""
        severity = evt.get("alert", {}).get("severity", 5)

        if severity >= 8:
            self.warnings.append(
                f"High severity ({severity}) - recommend dual approval"
            )

        return True

    def evaluate(self, playbook_yaml: str, evt: Dict) -> SafetyCheckResult:
        """
        Run all safety checks

        Args:
            playbook_yaml: Playbook YAML content
            evt: Security event that triggered playbook generation

        Returns:
            SafetyCheckResult with approval decision and reasons
        """
        self.errors = []
        self.warnings = []

        # 1. Check YAML structure
        valid_yaml, playbook = self.check_yaml_structure(playbook_yaml)
        if not valid_yaml:
            return SafetyCheckResult(approved=False, reasons=self.errors)

        # 2. Check for dangerous patterns (in raw YAML)
        safe_patterns = self.check_dangerous_patterns(playbook_yaml)

        # 3. Check for dangerous modules
        safe_modules = self.check_dangerous_modules(playbook)

        # 4. Check host targeting
        safe_targeting = self.check_host_targeting(playbook)

        # 5. Check for check_mode
        has_check_mode = self.check_check_mode(playbook)
        if not has_check_mode:
            self.errors.append(
                "No check_mode found in playbook - all state-changing tasks must have check_mode enabled"
            )

        # 6. Check for approval gate
        has_approval = self.check_approval_gate(playbook)
        if not has_approval:
            self.errors.append(
                "No approval gate found - playbook must assert approve_change variable"
            )

        # 7. Check event severity
        self.check_event_severity(evt)

        # Determine approval
        approved = (
            valid_yaml
            and safe_patterns
            and safe_modules
            and safe_targeting
            and has_check_mode
            and has_approval
        )

        return SafetyCheckResult(
            approved=approved, reasons=self.errors, warnings=self.warnings
        )


# Module-level function for backward compatibility
def approve_playbook(playbook_yaml: str, evt: Dict = None) -> SafetyCheckResult:
    """
    Evaluate playbook safety

    Args:
        playbook_yaml: Playbook YAML content
        evt: Optional security event dictionary

    Returns:
        SafetyCheckResult
    """
    if evt is None:
        evt = {}

    checker = PlaybookSafetyChecker()
    return checker.evaluate(playbook_yaml, evt)
