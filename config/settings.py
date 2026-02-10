import os
import yaml
import logging
from typing import List
from pydantic import BaseModel, ValidationError, field_validator


class OutputSettings(BaseModel):
    html_report_file: str = "audit_report.html"
    html_template_dir: str = "report_templates"
    json_output_file: str = "raw_results.json"


class NGGConfig(BaseModel):
    target_directory: str = "./"
    framework: str = "Generic"
    control_matrix_file: str = "controls/default_controls.yaml"
    pattern_definitions_file: str = "patterns/default_patterns.yaml"
    auditors: List[str] = []
    outputs: List[str] = []
    output_settings: OutputSettings = OutputSettings()

    @field_validator('target_directory')
    def validate_target_directory(cls, v):
        if not os.path.isdir(v):
            raise ValueError(f"Target directory '{v}' does not exist.")
        return v


class ConfigManager:
    def __init__(self, config_file_path: str):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config_file_path = config_file_path
        self.config_data = self._load_and_validate_config()

        
    def _load_and_validate_config(self) -> NGGConfig:
        """Loads and validates the main configuration file using Pydantic."""
        try:
            self.logger.info(f"Loading and validating config from: {self.config_file_path}")
            with open(self.config_file_path, 'r') as f:
                raw_config = yaml.safe_load(f)
            # Pydantic validation happens here
            return NGGConfig(**raw_config)
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file '{self.config_file_path}' not found.")
        except ValidationError as e:
            raise ValueError(f"Configuration validation error: {e}")


    def get(self, key: str, default=None):
        """Get a configuration value by key."""
        return getattr(self.config_data, key, default)

    # Convenience methods can still access the validated config_data
    def get_target_directory(self):
        return self.config_data.target_directory

    def get_framework(self):
        return self.config_data.framework

    def get_control_matrix_file(self):
        return self.config_data.control_matrix_file

    def get_pattern_definitions_file(self):
        return self.config_data.pattern_definitions_file

    def get_auditor_modules(self):
        return self.config_data.auditors

    def get_output_modules(self):
        return self.config_data.outputs

    def get_output_settings(self):
        return self.config_data.output_settings