import glob
import json
import os
import sys
import time
from datetime import datetime

from safety_checks import approve_playbook  # noqa: E402

# Add parent directory to path for common imports
sys.path.insert(0, "/repo/services")  # noqa: E402
from common.logging_config import log_audit_event, setup_logging  # noqa: E402

# Setup structured logging
logger = setup_logging("ai_generator")

# Configuration
QUEUE_DIR = os.getenv("QUEUE_DIR", "/repo/services/event_bridge/queue")
LIB_DIR = os.getenv("LIB_DIR", "/repo/playbooks/_library")
PROMPT_TMPL = "/repo/prompts/remediation_user.j2"
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))

# Create library directory
try:
    os.makedirs(LIB_DIR, exist_ok=True)
    logger.info("Library directory initialized", extra={"path": LIB_DIR})
except Exception as e:
    logger.error(
        "Failed to create library directory", extra={"path": LIB_DIR, "error": str(e)}
    )
    sys.exit(1)


def synthesize(evt: dict) -> str:
    """
    Generate remediation playbook based on event

    Args:
        evt: Security event dictionary

    Returns:
        Playbook YAML content

    Raises:
        Exception: If synthesis fails
    """
    try:
        sev = int(evt.get("alert", {}).get("severity", 5))
        cat = evt.get("event", {}).get("category", "unknown")
        event_id = evt.get("event", {}).get("id", "unknown")

        logger.info(
            "Synthesizing playbook",
            extra={"event_id": event_id, "severity": sev, "category": cat},
        )

        # Select appropriate base playbook
        if cat == "malware" or sev >= 7:
            base = "/repo/playbooks/samples/isolate_host_windows.yml"
            response_type = "isolation"
        elif cat == "intrusion_detection" or sev >= 6:
            base = "/repo/playbooks/samples/block_ip_paloalto.yml"
            response_type = "network_block"
        elif cat == "user_compromise":
            base = "/repo/playbooks/samples/disable_user_ad.yml"
            response_type = "account_disable"
        else:
            base = "/repo/playbooks/samples/patch_linux_package.yml"
            response_type = "patch"

        # Read base playbook
        try:
            with open(base, "r") as f:
                play = f.read()
        except FileNotFoundError:
            logger.error("Base playbook not found", extra={"path": base})
            raise

        logger.info(
            "Playbook synthesized",
            extra={
                "event_id": event_id,
                "response_type": response_type,
                "base_playbook": base,
            },
        )

        return play

    except Exception as e:
        logger.error(
            "Synthesis failed",
            extra={
                "event_id": evt.get("event", {}).get("id", "unknown"),
                "error": str(e),
            },
        )
        raise


def write_artifacts(evt: dict, play_yaml: str) -> str:
    """
    Write playbook and evidence artifacts

    Args:
        evt: Event dictionary
        play_yaml: Playbook YAML content

    Returns:
        Incident ID

    Raises:
        Exception: If file write fails
    """
    try:
        inc = evt["event"]["id"]
        pb_path = os.path.join(LIB_DIR, f"{inc}.yml")

        # Write playbook
        with open(pb_path, "w") as f:
            f.write(play_yaml)

        # Write evidence
        evidence_path = os.path.join(LIB_DIR, f"{inc}_EVIDENCE.json")
        with open(evidence_path, "w") as f:
            json.dump(evt, f, indent=2)

        # Write change plan
        plan_path = os.path.join(LIB_DIR, f"{inc}_CHANGE_PLAN.md")
        severity = evt.get("alert", {}).get("severity", "unknown")
        category = evt.get("event", {}).get("category", "unknown")

        change_plan = f"""# Change Plan for {inc}

## Incident Details
- **ID**: {inc}
- **Severity**: {severity}
- **Category**: {category}
- **Generated**: {datetime.utcnow().isoformat()}

## Review Checklist
- [ ] Review evidence in {inc}_EVIDENCE.json
- [ ] Verify playbook targets correct hosts
- [ ] Ensure check_mode is enabled
- [ ] Confirm approval requirements met
- [ ] Review OPA policy compliance

## Execution Steps
1. **Dry Run**: `ansible-playbook playbooks/run_generated.yml -e incident={inc} -i inventories/lab/hosts.ini --check`
2. **Review Output**: Verify no unexpected changes
3. **Approve**: Click approve in UI (http://localhost:8088)
4. **Execute**: `ansible-playbook playbooks/run_generated.yml \
   -e incident={inc} -e approve_change=true -i inventories/lab/hosts.ini`
5. **Validate**: Confirm remediation successful
6. **Rollback if needed**: Refer to playbook handlers

## Safety Gates
- OPA policy evaluation required
- Manual approval required
- Check-mode enforced for non-critical severity
- All actions logged for audit trail
"""

        with open(plan_path, "w") as f:
            f.write(change_plan)

        logger.info(
            "Artifacts written",
            extra={
                "incident_id": inc,
                "playbook": pb_path,
                "evidence": evidence_path,
                "plan": plan_path,
            },
        )

        log_audit_event(
            logger,
            "playbook_generated",
            incident_id=inc,
            playbook_path=pb_path,
            severity=severity,
            category=category,
        )

        return inc

    except Exception as e:
        logger.error(
            "Failed to write artifacts",
            extra={
                "incident_id": evt.get("event", {}).get("id", "unknown"),
                "error": str(e),
            },
        )
        raise


def process_event(path: str) -> bool:
    """
    Process a single event from queue

    Args:
        path: Path to event JSON file

    Returns:
        True if successful, False otherwise
    """
    event_id = "unknown"
    try:
        # Read event
        with open(path, "r") as f:
            evt = json.load(f)

        event_id = evt.get("event", {}).get("id", "unknown")

        logger.info(
            "Processing event", extra={"event_id": event_id, "queue_file": path}
        )

        # Synthesize playbook
        play = synthesize(evt)

        # Run safety checks
        safety_result = approve_playbook(play, evt)

        if not safety_result.approved:
            logger.warning(
                "Playbook failed safety checks",
                extra={"event_id": event_id, "reasons": safety_result.reasons},
            )

            log_audit_event(
                logger,
                "playbook_rejected",
                incident_id=event_id,
                reasons=safety_result.reasons,
            )

            # Move to failed queue
            failed_dir = os.path.join(os.path.dirname(path), "failed")
            os.makedirs(failed_dir, exist_ok=True)
            failed_path = os.path.join(failed_dir, os.path.basename(path))
            os.rename(path, failed_path)

            logger.info(
                "Event moved to failed queue",
                extra={"event_id": event_id, "path": failed_path},
            )
            return False

        # Write artifacts
        inc_id = write_artifacts(evt, play)

        # Remove from queue
        os.remove(path)

        logger.info(
            "Event processed successfully",
            extra={"event_id": event_id, "incident_id": inc_id},
        )

        return True

    except Exception as e:
        logger.error(
            "Failed to process event",
            extra={"event_id": event_id, "queue_file": path, "error": str(e)},
            exc_info=True,
        )
        return False


def loop():  # noqa: C901
    """Main processing loop"""
    logger.info(
        "AI Generator started",
        extra={
            "queue_dir": QUEUE_DIR,
            "library_dir": LIB_DIR,
            "poll_interval": POLL_INTERVAL,
        },
    )

    consecutive_errors = 0
    max_consecutive_errors = 10

    while True:
        try:
            # Find events in queue
            pattern = os.path.join(QUEUE_DIR, "*.json")
            queue_files = glob.glob(pattern)

            if queue_files:
                logger.debug(f"Found {len(queue_files)} events in queue")

                for path in queue_files:
                    try:
                        success = process_event(path)
                        if success:
                            consecutive_errors = 0  # Reset on success
                    except Exception as e:
                        logger.error(
                            "Event processing exception",
                            extra={"path": path, "error": str(e)},
                        )
                        consecutive_errors += 1

            # Check for too many consecutive errors
            if consecutive_errors >= max_consecutive_errors:
                logger.error(
                    "Too many consecutive errors, exiting",
                    extra={"consecutive_errors": consecutive_errors},
                )
                sys.exit(1)

            # Sleep before next poll
            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            logger.info("Shutting down gracefully")
            break
        except Exception as e:
            logger.error("Loop error", extra={"error": str(e)}, exc_info=True)
            consecutive_errors += 1
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    loop()
