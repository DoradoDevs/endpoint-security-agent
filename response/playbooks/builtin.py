"""
Sentinel Agent — Built-in Response Playbooks
"""

from response.playbooks.models import (
    PlaybookAction,
    PlaybookDefinition,
    PlaybookTrigger,
)


RANSOMWARE_RESPONSE = PlaybookDefinition(
    name="ransomware_response",
    description="Emergency response to ransomware detection — kill process, quarantine file, isolate endpoint",
    trigger=PlaybookTrigger(
        categories=["Ransomware"],
        min_severity="high",
        keywords=["ransom", "encrypt"],
    ),
    actions=[
        PlaybookAction(
            action_type="kill_process_tree",
            target_template="{evidence.pid}",
        ),
        PlaybookAction(
            action_type="quarantine",
            target_template="{evidence.filepath}",
        ),
        PlaybookAction(action_type="isolate"),
        PlaybookAction(
            action_type="notify",
            params={"message": "Ransomware detected and contained"},
        ),
    ],
    notifications=["desktop"],
    rollback_on_failure=False,  # Don't rollback ransomware response
)

CRYPTOMINER_RESPONSE = PlaybookDefinition(
    name="cryptominer_response",
    description="Kill cryptomining processes and quarantine binaries",
    trigger=PlaybookTrigger(
        categories=["Cryptominer"],
        min_severity="high",
        keywords=["miner", "mining"],
    ),
    actions=[
        PlaybookAction(
            action_type="kill_process_tree",
            target_template="{evidence.pid}",
        ),
        PlaybookAction(
            action_type="quarantine",
            target_template="{evidence.filepath}",
        ),
        PlaybookAction(
            action_type="notify",
            params={"message": "Cryptominer detected and removed"},
        ),
    ],
    notifications=["desktop"],
)

RAT_RESPONSE = PlaybookDefinition(
    name="rat_response",
    description="Block C2 connection, kill RAT process, quarantine payload",
    trigger=PlaybookTrigger(
        categories=["C2/RAT"],
        min_severity="high",
        keywords=["rat", "c2", "beacon", "reverse_shell"],
    ),
    actions=[
        PlaybookAction(
            action_type="block_ip",
            target_template="{evidence.remote_ip}",
        ),
        PlaybookAction(
            action_type="kill_process_tree",
            target_template="{evidence.pid}",
        ),
        PlaybookAction(
            action_type="quarantine",
            target_template="{evidence.filepath}",
        ),
        PlaybookAction(
            action_type="notify",
            params={"message": "RAT/C2 detected and blocked"},
        ),
    ],
    notifications=["desktop"],
)

DATA_EXFIL_RESPONSE = PlaybookDefinition(
    name="data_exfil_response",
    description="Block exfiltration destination and kill responsible process",
    trigger=PlaybookTrigger(
        categories=["Data Exfiltration", "Exfil"],
        min_severity="high",
        keywords=["exfiltration", "data theft"],
    ),
    actions=[
        PlaybookAction(
            action_type="block_ip",
            target_template="{evidence.remote_ip}",
        ),
        PlaybookAction(
            action_type="kill_process_tree",
            target_template="{evidence.pid}",
        ),
        PlaybookAction(
            action_type="notify",
            params={"message": "Data exfiltration attempt blocked"},
        ),
    ],
    notifications=["desktop"],
)

LATERAL_MOVEMENT_RESPONSE = PlaybookDefinition(
    name="lateral_movement_response",
    description="Isolate endpoint to prevent lateral movement, kill suspicious process",
    trigger=PlaybookTrigger(
        categories=["Lateral Movement"],
        min_severity="high",
        keywords=["lateral", "psexec", "wmi remote"],
    ),
    actions=[
        PlaybookAction(
            action_type="kill_process_tree",
            target_template="{evidence.pid}",
        ),
        PlaybookAction(action_type="isolate"),
        PlaybookAction(
            action_type="notify",
            params={"message": "Lateral movement detected — endpoint isolated"},
        ),
    ],
    notifications=["desktop"],
    rollback_on_failure=False,
)

BUILTIN_PLAYBOOKS = [
    RANSOMWARE_RESPONSE,
    CRYPTOMINER_RESPONSE,
    RAT_RESPONSE,
    DATA_EXFIL_RESPONSE,
    LATERAL_MOVEMENT_RESPONSE,
]
