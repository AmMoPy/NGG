import logging
from abc import ABC, abstractmethod
from config.settings import ConfigManager
from models.base_models import AuditResultsSummary


class BaseOutput(ABC):
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def render(self, results: AuditResultsSummary):
        """
        Takes the aggregated results Summary object.
        Outputs the report in the desired format.
        """
        pass