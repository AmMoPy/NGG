import os
import json
import hashlib
from pathlib import Path
from outputs.base_output import BaseOutput
from models.base_models import AuditResultsSummary


class HTMLOutput(BaseOutput):

    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.output_file = Path(self.config.get_output_settings().html_report_file)
        # Ensure the template directory path is resolved relative to the script location or config
        self.template_dir = Path(self.config.get_output_settings().html_template_dir).resolve()


    def _load_template_fragment(self, fragment_name: str) -> str:
        """Loads an HTML fragment from the fragments subdirectory."""
        fragment_path = self.template_dir / "fragments" / fragment_name
        try:
            return fragment_path.read_text(encoding='utf-8')
        except FileNotFoundError:
            self.logger.warning(f"Fragment {fragment_path} not found.")
            return ""
        except UnicodeDecodeError:
            self.logger.warning(f"Could not decode fragment {fragment_path} as UTF-8.")
            return ""


    def render(self, results: AuditResultsSummary): # Explicitly type the input parameter
        """
        Renders the HTML report using modular templates.
        """
        # Load the main template
        main_template_path = self.template_dir / 'report_base.html'
        try:
            html_content = main_template_path.read_text(encoding='utf-8')
        except FileNotFoundError:
            self.logger.error(f"Main template {main_template_path} not found.")
            return
        except UnicodeDecodeError:
            self.logger.error(f"Could not decode main template {main_template_path} as UTF-8.")
            return

        # Load fragments
        main_html = self._load_template_fragment('_main.html')

        # Inject fragments into the main template
        html_content = html_content.replace('{{FRAGMENT_MAIN}}', main_html)
    
        # Inject the JSON results data into the template
        # Use Pydantic's model_dump_json for serialization
        json_data_str = results.model_dump_json()
        html_content = html_content.replace('{{AUDIT_DATA}}', f'JSON.parse({json.dumps(json_data_str)})')

        # Prepare the output directory
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write the final HTML file
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        # Also write the raw JSON results for debugging/CI using Pydantic
        json_output_file = Path(self.config.get_output_settings().json_output_file)
        json_output_file.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
        with open(json_output_file, 'w', encoding='utf-8') as f:
            f.write(results.model_dump_json(indent=2)) # Serialize the Pydantic model directly

        self.logger.info(f"HTML report generated: {self.output_file.resolve()}")
        self.logger.info(f"Raw JSON results saved: {json_output_file.resolve()}")


__plugin__ = HTMLOutput