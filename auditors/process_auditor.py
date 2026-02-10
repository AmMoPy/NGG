import os
import subprocess
from typing import Dict, Callable, Optional
from rules.rules_mgr import RuleManager
from auditors.base_auditor import BaseAuditor
from models.base_models import Finding, AuditResult, FindingStatus, FindingType, ControlDefinition


# --- Decorator for registering process checks ---
# Global registry to store check functions mapped by control ID
PROCESS_CHECK_REGISTRY: Dict[str, Callable[['ProcessAuditor', ControlDefinition], Finding]] = {}

def register_process_check(control_id: str):
    """
    Decorator to register a method in the ProcessAuditor as a handler for a specific control ID.
    The decorated method must take (self, control_def: ControlDefinition) and return a Finding.
    """
    def decorator(func: Callable[['ProcessAuditor', ControlDefinition], Finding]):
        PROCESS_CHECK_REGISTRY[control_id] = func
        return func
    return decorator


class ProcessAuditor(BaseAuditor):
    def __init__(self, config_manager, rule_manager: RuleManager): # Type hint for rule_manager
        super().__init__(config_manager, rule_manager)
        self.target_dir = config_manager.get_target_directory()
        # No need to manually populate a map; the decorator handles registration
        # Verify registry is populated if needed
        self.logger.info(f"Process check registry: {list(PROCESS_CHECK_REGISTRY.keys())}")


    # --- Registered Check Functions ---
    @register_process_check("CC1.5") # Must Match control ID as presented in controls yaml
    def _check_git_gpg_signature(self, control_def: ControlDefinition) -> Finding:
        """
        Checks if the last commit in the target directory has a GPG signature.
        Maps to SOC 2 CC1.5/CC8.1 (example linkage via decorator).
        """
        try:
            original_cwd = os.getcwd() # Save current directory
            os.chdir(self.target_dir) # Change to target directory
            # Run git log command to check signature status of HEAD
            result = subprocess.run(['git', 'log', '--show-signature', '-1'], capture_output=True, text=True)
            output = result.stdout
            os.chdir(original_cwd) # Restore original directory

            if "[GNUPG:] GOODSIG" in output or "[GNUPG:] BADSIG" in output:
                sig_status_line = next((line for line in output.split('\n') if '[GNUPG:] GOODSIG' in line or '[GNUPG:] BADSIG' in line), "")
                
                if '[GNUPG:] GOODSIG' in sig_status_line:
                    return Finding(
                        id=control_def.id,
                        type=FindingType.PROCESS,
                        status=FindingStatus.PASS,
                        control=control_def.objective, # Use the objective from the control definition
                        evidence={"message": "Last commit is GPG signed.", "signature_details": sig_status_line.strip()}
                    )
                elif '[GNUPG:] BADSIG' in sig_status_line:
                    return Finding(
                        id=control_def.id,
                        type=FindingType.PROCESS,
                        status=FindingStatus.FAIL,
                        control=control_def.objective,
                        evidence={"message": "Last commit has an invalid GPG signature.", "signature_details": sig_status_line.strip()}
                    )
            else:
                return Finding(
                    id=control_def.id,
                    type=FindingType.PROCESS,
                    status=FindingStatus.FAIL,
                    control=control_def.objective,
                    evidence={"message": "Last commit is not GPG signed.", "stdout": output}
                )

            self.logger.info(f"GPG signature check for {control_def.id} completed")
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"GPG signature check for {control_def.id} failed: {e}")
            os.chdir(original_cwd) # Ensure we restore directory even on error
            return Finding(
                id=control_def.id,
                type=FindingType.PROCESS,
                status=FindingStatus.ERROR,
                control=control_def.objective,
                evidence={"message": f"Could not run git command in target directory: {e}"}
            )

        except FileNotFoundError:
            self.logger.error(f"GPG signature check for {control_def.id} failed: {e}")
            os.chdir(original_cwd)
            return Finding(
                id=control_def.id,
                type=FindingType.PROCESS,
                status=FindingStatus.ERROR,
                control=control_def.objective,
                evidence={"message": "Git command not found in environment."}
            )

        # Reset directory again in case of unexpected errors bypassing the try-except blocks
        finally:
            try:
                os.chdir(original_cwd)
            except FileNotFoundError:
                # If the original directory somehow disappeared, warn but continue
                self.logger.warning("Could not restore original working directory after Git check.")


    # @register_process_check("OTHER_CONTROL_ID") # Example for future checks
    # def _check_something_else(self, control_def: ControlDefinition) -> Finding:
    #     # Implementation for other process check
    #     pass


    # --- Main Run Method ---
    def run(self) -> AuditResult:
        findings = []
        stats = {'pass': 0, 'fail': 0}
        # metadata = {'scm_detected': 'git'} # Keep if relevant, otherwise remove

        # Query the RuleManager for all controls with category 'Process'
        all_controls = self.rules.get_all_compiled_rules() # Gets Dict[str, CompiledRule]
        process_controls = {
            control_id: compiled_rule
            for control_id, compiled_rule in all_controls.items()
            if compiled_rule.control_definition.category.lower() == FindingType.PROCESS.lower() # Compare enums or strings
        }

        # Iterate through the retrieved process controls
        for control_id, compiled_rule in process_controls.items():
            self.logger.debug(f"Processing process control: {control_id}")
            control_def = compiled_rule.control_definition # Extract ControlDefinition

            # Look up the registered check function for this control ID
            check_func = PROCESS_CHECK_REGISTRY.get(control_id)

            if check_func:
                # Call the registered function to perform the check
                finding = check_func(self, control_def) # Pass the instance (self) and the control definition
                findings.append(finding)
                # Update stats based on the finding's status
                if finding.status == FindingStatus.PASS:
                    stats['pass'] += 1
                elif finding.status == FindingStatus.FAIL:
                    stats['fail'] += 1
                # Errors might be counted separately if needed, but often treated as failures for compliance
                self.logger.info(f"Processing check finished for {control_id}")
            else:
                # Handle the case where a process control ID doesn't have a registered check function
                findings.append(Finding(
                    id=control_id,
                    type=FindingType.PROCESS,
                    status=FindingStatus.ERROR, # Mark as error or maybe FAIL?
                    control=f"Control {control_id} ({control_def.objective}): No check function registered.",
                    evidence={"message": f"No implementation found to check control {control_id}."}
                ))
                stats['fail'] += 1 # Treat missing check as a failure for compliance purposes
                self.logger.warning(f"No check function registered for process control '{control_id}'.")

        # Calculate/update metadata if necessary
        # metadata['scm_detected'] = 'git' if any(f.id.startswith("CC1.") for f in findings if f.type == FindingType.PROCESS) else None

        # Return the standardized AuditResult object
        return AuditResult(
            type=FindingType.PROCESS,
            findings=findings,
            stats=stats,
            metadata={} # Add relevant process metadata if collected
        )


__plugin__ = ProcessAuditor