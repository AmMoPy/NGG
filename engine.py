import sys
import os
import time
import hashlib
import logging
import argparse
import importlib.util
from rules.rules_mgr import RuleManager
from config.settings import ConfigManager
from models.base_models import AuditResult, AuditResultsSummary


class AuditEngine:

    def __init__(self, config_file_path: str):
        self.config = ConfigManager(config_file_path)
        self.rule_manager = RuleManager(self.config)
        # Initialize the summary object using the Pydantic model
        self.results = AuditResultsSummary(
            findings=[],
            stats={"pass": 0, "fail": 0},
            metadata={
                "framework": "",
                "target_path": "",
                "scm_checked": False, # Updated by auditors
                "integrity_hash": "",
                "scan_time": ""
            }
        )
        self.logger = logging.getLogger(self.__class__.__name__)

        self.logger.info(f"Initializing AuditEngine with config: {config_file_path}")


    def _load_module_from_file(self, module_name, file_path):
        """Helper to dynamically load a module from a file path."""
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module


    def _generate_output(self):
        """Render results as per configured output formats"""
        for output_name in self.config.get_output_modules():
            output_file_path = os.path.join('outputs', f'{output_name}.py')
            try:
                output_module = self._load_module_from_file(f"outputs.{output_name}", output_file_path)
                OutputClass = getattr(output_module, "__plugin__", None)
                if OutputClass:
                    output_instance = OutputClass(self.config)
                    class_name = OutputClass.__name__

                    self.logger.info(f"Rendering output: {class_name}")
                    
                    output_instance.render(self.results)
                    
                    self.logger.info(f"Audit completed: Output {class_name} rendered successfully.")
                else:
                    self.logger.error(f"Couldn't find the correct output class in {output_file_path}")
            except FileNotFoundError:
                self.logger.error(f"Output file {output_file_path} not found.")
            except Exception as e:
                self.logger.error(f"Error generating output {output_name}: {e}")


    def run(self, live = False):
        target_directory = self.config.get_target_directory()

        self.logger.info(
            f"Starting NGG audit for framework: {self.config.get_framework()} - "
            f"Target directory: {target_directory}"
            )

        # Ensure fresh start at each call/cycle
        self.results.clear()

        # update metadata
        self.results.metadata["scan_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.results.metadata["framework"] = self.config.get_framework()
        self.results.metadata["target_path"] = target_directory
        
        # Load and Run Auditors
        for auditor_name in self.config.get_auditor_modules():
            auditor_file_path = os.path.join('auditors', f'{auditor_name}.py')
            try:
                auditor_module = self._load_module_from_file(f"auditors.{auditor_name}", auditor_file_path)
                AuditorClass = getattr(auditor_module, "__plugin__", None)

                if AuditorClass:
                    auditor_instance = AuditorClass(self.config, self.rule_manager)
                    class_name = AuditorClass.__name__
                    
                    self.logger.info(f"Running auditor: {class_name}")
                    
                    audit_result: AuditResult = auditor_instance.run() # Type hint for clarity

                    # Extend findings list with new findings
                    self.results.findings.extend(audit_result.findings)

                    # Aggregate stats
                    self.results.stats["pass"] += audit_result.stats["pass"]
                    self.results.stats["fail"] += audit_result.stats["fail"]

                    # Update metadata - merge or take first value found
                    for key, value in audit_result.metadata.items():
                        if key not in self.results.metadata or self.results.metadata[key] is False:
                            self.results.metadata[key] = value

                    self.logger.info(f"Auditor {class_name} completed. Findings: {len(audit_result.findings)}, Stats: {audit_result.stats}")
                else:
                    self.logger.error(f"Couldn't find the correct auditor class in {auditor_file_path}")
            except FileNotFoundError:
                self.logger.error(f"Auditor file {auditor_file_path} not found.")
            except Exception as e:
                self.logger.error(f"Error running auditor {auditor_name}: {e}")

        # Generate Integrity Hash for the final results structure
        results_json = self.results.model_dump_json()
        self.results.metadata["integrity_hash"] = hashlib.sha256(results_json.encode()).hexdigest()

        # If TUI then update dashboard directly
        # Otherwise generate desired format
        if not live:
            self._generate_output()
        
        return self.results


if __name__ == "__main__":
    # Setup basic logging
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=log_format)

    logger = logging.getLogger(__name__)

    # Setup runtime options
    parser = argparse.ArgumentParser(description="NGG Governance Engine")
    parser.add_argument("--live", action='store_true', help="Run in continuous mode (e.g., for TUI)")
    parser.add_argument("--config", default="ngg_config.yaml", help="Path to the configuration file")

    # Load
    args = parser.parse_args()
    engine = AuditEngine(config_file_path=args.config)

    # Check if TUI is configured BEFORE entering the loop
    configured_outputs = engine.config.get_output_modules()
    output_name = 'tui_output' # fargile, better be moved to the centralized settings
    has_tui = output_name in configured_outputs

    if args.live and has_tui:
        # Find and run the TUI output if specified
        output_file_path = os.path.join('outputs', f'{output_name}.py')
        try:
            output_module = engine._load_module_from_file(f"outputs.{output_name}", output_file_path)
            OutputClass = getattr(output_module, "__plugin__", None)
            if OutputClass:
                output_instance = OutputClass(engine.config)
                class_name = OutputClass.__name__
                # render the live dashboard
                output_instance.render(engine)
            else:
                logger.error(f"Couldn't find the correct output class in {output_file_path}")
        except Exception as e:
            logger.error(f"Error rendering TUI output: {e}")
            raise
    else: # Default mode - generate other outputs once (e.g.: html/json reports)
        engine.run(live = has_tui) # bypass output generateion if called while enabling TUI without the --live flag