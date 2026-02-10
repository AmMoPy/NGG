import yaml
import hashlib
import os
import json
import logging
from typing import Dict
from models.base_models import ControlDefinition, PatternDefinition, CompiledRule

class RulesCompiler:
    def __init__(self, control_file_path: str, pattern_file_path: str, cache_dir: str = '.ngg_cache'):
        self.control_file_path = control_file_path
        self.pattern_file_path = pattern_file_path
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.logger = logging.getLogger(self.__class__.__name__)

    def _calculate_hash(self, file_paths: list[str]):
        """Calculates a combined SHA256 hash of the content of given files."""
        combined_content = b""
        for path in file_paths:
            with open(path, 'rb') as f:
                combined_content += f.read()
        return hashlib.sha256(combined_content).hexdigest()

    def _get_cache_file_name(self):
        """Generates a unique cache file name based on input file names."""
        control_name = os.path.basename(self.control_file_path).replace('.yaml', '').replace('.yml', '')
        pattern_name = os.path.basename(self.pattern_file_path).replace('.yaml', '').replace('.yml', '')
        return os.path.join(self.cache_dir, f"compiled_{control_name}_from_{pattern_name}.json")

    def compile(self) -> Dict[str, CompiledRule]:
        """
        Compiles the control matrix and pattern definitions into a linked structure.
        Checks for a valid cache first.
        Returns a dictionary mapping control ID to CompiledRule.
        """
        cache_file = self._get_cache_file_name()
        source_files = [self.control_file_path, self.pattern_file_path]
        current_hash = self._calculate_hash(source_files)

        # Check if cache exists and is valid
        if os.path.exists(cache_file):
            self.logger.info(f"Checking for cached rules at: {cache_file}")
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                if cached_data.get("source_hash") == current_hash:
                    self.logger.info(f"Using valid cached rules from {cache_file}")
                    # Reconstruct Pydantic objects from the cached dict
                    return {k: CompiledRule.model_validate(v) for k, v in cached_data["compiled_rules"].items()}
                else:
                    self.logger.info("Cached rules are stale, recompiling...")
            except (json.JSONDecodeError, KeyError):
                 self.logger.info("No cache found, compiling rules...")

        # Load source files
        with open(self.control_file_path, 'r') as f:
            control_matrix_raw = yaml.safe_load(f)
        with open(self.pattern_file_path, 'r') as f:
            pattern_definitions_raw = yaml.safe_load(f)

        # Validate and convert raw data to Pydantic models
        control_matrix = [ControlDefinition(**c) for c in control_matrix_raw.get('controls', [])]
        pattern_definitions = [PatternDefinition(**p) for p in pattern_definitions_raw.get('rules', [])]

        # Build mapping from pattern ID to definition
        pattern_map = {p.id: p for p in pattern_definitions}

        # Link controls to patterns
        compiled_rules = {}
        for control in control_matrix:
            self.logger.info(f"Linking control {control.id} with verification_method {control.verification_method}")
            control_id = control.id
            verification_method = control.verification_method
            # category is already validated by ControlDefinition

            if verification_method:
                pattern_def = pattern_map.get(verification_method)
                if pattern_def:
                     compiled_rules[control_id] = CompiledRule(
                         control_definition=control,
                         pattern_definition=pattern_def
                     )
                else:
                     self.logger.warning(f"Pattern definition '{verification_method}' for control '{control_id}' not found.")
                     compiled_rules[control_id] = CompiledRule(
                         control_definition=control,
                         pattern_definition=None # Mark as missing
                     )
            else:
                 # Handle controls without a direct code pattern (e.g., process checks)
                 compiled_rules[control_id] = CompiledRule(
                     control_definition=control,
                     pattern_definition=None
                 )

        # Save compiled rules to cache (serialize Pydantic objects to dict)
        output_data = {
            "source_hash": current_hash,
            "compiled_rules": {k: v.model_dump() for k, v in compiled_rules.items()} # Convert to dict for JSON
        }
        with open(cache_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        self.logger.info(f"Compiled rules cached to {cache_file}")

        return compiled_rules