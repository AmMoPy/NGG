import os
import json
import logging
import subprocess
from typing import Dict, List
from rules.rules_mgr import RuleManager
from auditors.base_auditor import BaseAuditor
from models.base_models import Finding, AuditResult, FindingStatus, FindingType, CompiledRule


class LogicAuditor(BaseAuditor):
    def __init__(self, config_manager, rule_manager: RuleManager):
        super().__init__(config_manager, rule_manager)
        self.target_dir = config_manager.get_target_directory()
        # Initialize logger per instance
        self.logger = logging.getLogger(self.__class__.__name__)

    def run(self) -> AuditResult:
        self.logger.info(f"Starting logic audit on directory: {self.target_dir}")
        findings = []
        stats = {'pass': 0, 'fail': 0}
        metadata = {'files_scanned': 0, 'scm_checked': True}

        # --- Fetch all COMPILED rules for Logic category ---
        self.logger.info("Fetching logic controls and their linked patterns from RuleManager.")
        all_compiled_rules = self.rules.get_all_compiled_rules()
        logic_compiled_rules: Dict[str, CompiledRule] = {}

        for control_id, compiled_rule in all_compiled_rules.items():
            control_def = compiled_rule.control_definition
            pattern_def = compiled_rule.pattern_definition

            if pattern_def and control_def.category.lower() == FindingType.LOGIC.lower():
                logic_compiled_rules[control_id] = compiled_rule
                self.logger.info(f"Linked logic control {control_id} to pattern {pattern_def.id}")
        
        if not logic_compiled_rules:
            self.logger.info("No logic checks (with patterns) found for the specified framework/category.")
            return AuditResult(
                type=FindingType.LOGIC,
                findings=[],
                stats=stats,
                metadata=metadata
            )
     
        # --- Run Semgrep ONCE with the combined rules ---
        self.logger.info(f"Executing combined Semgrep run on {self.target_dir}")
        pattern_definitions_file = self.config.get_pattern_definitions_file()

        try:
            result = subprocess.run([
                "semgrep", "--config", pattern_definitions_file,
                "--json", self.target_dir
            ], capture_output=True, text=True, check=True) # check=True raises CalledProcessError on non-zero exit (usually means findings or error)

            semgrep_output = json.loads(result.stdout)
            self.logger.info(f"Semgrep run completed successfully. Received output for {len(semgrep_output.get('results', []))} matches.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Semgrep failed during combined run: {e.stderr}")
            for control_id in logic_compiled_rules:
                findings.append(Finding(
                    id=control_id,
                    type=FindingType.LOGIC,
                    status=FindingStatus.ERROR,
                    control=logic_compiled_rules[control_id].control_definition.objective,
                    evidence={"error": f"Semgrep execution failed: {e.stderr}"}
                ))
                stats['fail'] += 1

            return AuditResult(
                type=FindingType.LOGIC,
                findings=findings,
                stats=stats,
                metadata=metadata
            )

        except json.JSONDecodeError:
            self.logger.error(f"Could not parse Semgrep output during combined run")
            for control_id in logic_compiled_rules:
                findings.append(Finding(
                    id=control_id,
                    type=FindingType.LOGIC,
                    status=FindingStatus.ERROR,
                    control=logic_compiled_rules[control_id].control_definition.objective,
                    evidence={"error": "Invalid Semgrep JSON output"}
                ))
                stats['fail'] += 1

            return AuditResult(
                type=FindingType.LOGIC,
                findings=findings,
                stats=stats,
                metadata=metadata
            )


        # --- Process Semgrep Results and Map Back to Controls ---
        self.logger.info("Processing Semgrep results and mapping to controls.")
        # Extract the actual rule name (e.g., from 'patterns.auth_check_pattern' get 'auth_check_pattern')
        # This assumes the format is always 'prefix.rule_name'
        matched_rule_ids = {match.get('check_id').split('.')[-1] for match in semgrep_output.get('results', []) if match.get('check_id')}

        for control_id, compiled_rule in logic_compiled_rules.items():
            semgrep_rule_id = compiled_rule.pattern_definition.id

            if semgrep_rule_id in matched_rule_ids:
                rule_matches = [match for match in semgrep_output.get('results', []) if match.get('check_id').split('.')[-1] == semgrep_rule_id]

                self.logger.info(f"Control {control_id} (rule {semgrep_rule_id}) FAILED with {len(rule_matches)} matches.")

                findings.append(Finding(
                    id=control_id,
                    type=FindingType.LOGIC,
                    status=FindingStatus.FAIL,
                    control=compiled_rule.control_definition.objective,
                    evidence={"matches": rule_matches}
                ))
                stats['fail'] += 1
            else:
                self.logger.debug(f"Control {control_id} (rule {semgrep_rule_id}) PASSED - no matches found.")
                findings.append(Finding(
                    id=control_id,
                    type=FindingType.LOGIC,
                    status=FindingStatus.PASS,
                    control=compiled_rule.control_definition.objective,
                    evidence={} # Or a message indicating success
                ))
                stats['pass'] += 1

        # --- Get Actual File Count from Semgrep Output ---
        # Use the accurate count provided by Semgrep
        semgrep_scanned_files = semgrep_output.get("paths", {}).get("scanned", [])
        actual_file_count = len(semgrep_scanned_files)
        metadata['files_scanned'] = actual_file_count
        self.logger.info(f"Semgrep reported {actual_file_count} files scanned.")

        # Return the standardized AuditResult object
        self.logger.info(f"Logic audit completed. Total findings: {len(findings)}, Stats: {stats}")
        return AuditResult(
            type=FindingType.LOGIC,
            findings=findings,
            stats=stats,
            metadata=metadata
        )


__plugin__ = LogicAuditor