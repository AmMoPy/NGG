import sys
import os
import hashlib
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
                "framework": self.config.get_framework(),
                "target_path": self.config.get_target_directory(),
                "scm_checked": False, # Will be updated by auditors
                "integrity_hash": "", # Calculated later
                "scan_time": "" # Add timestamp
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


    def run(self):
        import time
        self.results.metadata["scan_time"] = time.strftime("%Y-%m-%d %H:%M:%S")

        self.logger.info(f"Starting NGG audit for framework: {self.config.get_framework()}")
        self.logger.info(f"Target directory: {self.config.get_target_directory()}")

        # 1. Load and Run Auditors
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
                    self.logger.error(f"Class {class_name} not found in {auditor_file_path}")
            except FileNotFoundError:
                self.logger.error(f"Auditor file {auditor_file_path} not found.")
            except Exception as e:
                self.logger.error(f"Error running auditor {auditor_name}: {e}")

        # 2. Generate Integrity Hash for the final results structure
        results_json = self.results.model_dump_json() # Serialize the Pydantic model to JSON string
        self.results.metadata["integrity_hash"] = hashlib.sha256(results_json.encode()).hexdigest()

        # 3. Load and Run Outputs
        for output_name in self.config.get_output_modules():
            output_file_path = os.path.join('outputs', f'{output_name}.py')
            try:
                output_module = self._load_module_from_file(f"outputs.{output_name}", output_file_path)
                OutputClass = getattr(output_module, "__plugin__", None)
                if OutputClass:
                    output_instance = OutputClass(self.config)
                    class_name = OutputClass.__name__

                    self.logger.info(f"Rendering output: {class_name}")
                    
                    output_instance.render(self.results) # Pass the Pydantic summary object
                    
                    self.logger.info(f"Audit completed: Output {class_name} rendered successfully.")
                else:
                    self.logger.error(f"Class {class_name} not found in {output_file_path}")
            except FileNotFoundError:
                self.logger.error(f"Output file {output_file_path} not found.")
            except Exception as e:
                self.logger.error(f"Error generating output {output_name}: {e}")


if __name__ == "__main__":
    # Setup basic logging
    import logging
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=log_format)

    # Setup runtime options
    import argparse
    parser = argparse.ArgumentParser(description="NGG Governance Engine")
    parser.add_argument("--mode", choices=["once", "tui"], default="once", help="Run mode: 'once' for single run, 'tui' for live dashboard")
    parser.add_argument("--config", default="ngg_config.yaml", help="Path to the configuration file")

    args = parser.parse_args()

    engine = AuditEngine(config_file_path=args.config)

    if args.mode == "tui":
        # Find and run the TUI output if specified
        tui_found = False
        for output_name in engine.config.get_output_modules():
            if output_name == 'tui_output':
                output_file_path = os.path.join('outputs', f'{output_name}.py')
                try:
                    output_module = engine._load_module_from_file(f"outputs.{output_name}", output_file_path)
                    OutputClass = getattr(output_module, "__plugin__", None)
                    output_instance = OutputClass(engine.config)
                    # TUI needs to run its own loop, pass the engine instance or config
                    # For TUI, it might be better for it to instantiate its own engine internally
                    # Let's adjust TUIOutput to handle this
                    output_instance.render(None) # Pass None, TUI will manage its own engine instance
                    tui_found = True
                    break
                except Exception as e:
                    print(f"Error starting TUI: {e}")
                    break
        if not tui_found:
            print("TUI output module ('tui_output') not found in configuration or failed to load.")
    else: # Default mode 'once'
        engine.run() # Run the engine once and let configured outputs process the results