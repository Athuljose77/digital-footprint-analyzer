from app.core.findings.rules.system_rules import rule_sys_startup_001
from app.core.findings.rules.email_rules import rule_eml_breach_001
from app.core.findings.rules.username_rules import rule_usr_profile_001
from app.core.findings.rules.file_metadata_rules import rule_file_gps_001, rule_file_camera_001
from app.core.findings.rules.browser_rules import rule_brw_profile_001

ALL_RULES = [
    rule_sys_startup_001,
    rule_eml_breach_001,
    rule_usr_profile_001,
    rule_file_gps_001,
    rule_file_camera_001,
    rule_brw_profile_001,
]

MODULE_RULES = {
    "system": [rule_sys_startup_001],
    "email": [rule_eml_breach_001],
    "username": [rule_usr_profile_001],
    "file_metadata": [rule_file_gps_001, rule_file_camera_001],
    "browser": [rule_brw_profile_001],
}
