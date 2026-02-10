import logging
from abc import ABC, abstractmethod
from rules.rules_mgr import RuleManager
from config.settings import ConfigManager
from models.base_models import AuditResult

class BaseAuditor(ABC):
    def __init__(self, config_manager: ConfigManager, rule_manager: RuleManager):
        self.config = config_manager
        self.rules = rule_manager
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def run(self) -> AuditResult:
        """
        Executes the audit logic.
        Must return an AuditResult object.
        """
        pass