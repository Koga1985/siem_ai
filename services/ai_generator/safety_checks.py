def approve(playbook_yaml:str) -> bool:
    # Extremely small guard: force check_mode presence
    return ("check_mode: yes" in playbook_yaml) or ("check_mode: true" in playbook_yaml)
