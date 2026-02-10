import logging
from typing import Dict, List, Optional
from rules.rules_compiler import RulesCompiler
from models.base_models import CompiledRule, ControlDefinition, PatternDefinition

class RuleManager:
    def __init__(self, config_manager):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.control_file_path = config_manager.get_control_matrix_file()
        self.pattern_file_path = config_manager.get_pattern_definitions_file()
        self._compiled_rules: Dict[str, CompiledRule] = {}
        self._load_rules()

    def _load_rules(self):
        """Loads and compiles rules using the RulesCompiler."""
        compiler = RulesCompiler(
            control_file_path=self.control_file_path,
            pattern_file_path=self.pattern_file_path
        )
        self._compiled_rules = compiler.compile() # Now returns Dict[str, CompiledRule]

    def get_all_compiled_rules(self) -> Dict[str, CompiledRule]:
        """Returns the full compiled rules structure."""
        return self._compiled_rules

    def get_rule_for_control(self, control_id: str) -> Optional[CompiledRule]:
        """Retrieves the compiled rule (control def + pattern def) for a given control ID."""
        
        result = self._compiled_rules.get(control_id)
        
        if result:
            self.logger.info(f"Found rule for control ID: {control_id}")
        else:
            self.logger.warning(f"Rule not found for control ID: {control_id}")

        return result

    def get_all_control_ids(self) -> List[str]:
        """Returns a list of all control IDs defined in the matrix."""
        return list(self._compiled_rules.keys())