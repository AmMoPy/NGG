import json, subprocess, os, sys, argparse, hashlib
from datetime import datetime


class NextGenAuditor:
    def __init__(self, target_dir=".", config_path="compliance.yaml", report_template="report_template.html"):
        self.target_dir = os.path.abspath(target_dir)
        self.config_path = config_path
        self.report_template = report_template
        self.results = {
            "metadata": {"scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "framework": "SOC2-Type1"},
            "stats": {"pass": 0, "fail": 0},
            "findings": []
        }

        # Verify the target is actually your app
        app_full_path = os.path.join(self.target_dir, "backend/app")
        # print(app_full_path)
        if not os.path.exists(app_full_path):
            print(f"❌ ERROR: Target directory '{self.target_dir}' does not look like the app root.")
            print("Usage: python audit_engine.py /path/to/your/project")
            sys.exit(1)


    def _run(self, cmd):
        return subprocess.run(cmd, capture_output=True, text=True).stdout


    def audit_git(self):
        """
        CC1.5/CC8.1: Accountability via GPG signatures.
        
        Logic: If you are coding in your dark room and haven't set up GPG signing yet, this will (rightfully) show FAIL.
        To make it PASS: You would need to generate a GPG key and configure git: 
            git config --global user.signingkey <YOUR_KEY> and git config --global commit.gpgsign true.
        For an auditor, this "FAIL" is correct—it proves you haven't yet established an "Accountable Identity" for your code changes.
        """        
        cmd = ["git", "log", "-1", '--pretty=format:%H|%ae|%G?|%ai']
        
        try:
            # We execute the command
            result = subprocess.run(cmd, cwd=self.target_dir, capture_output=True, text=True, check=True)
            data = result.stdout.strip()

            if "|" in data:
                parts = data.split('|')
                # Correctly indexing the parts list
                h = parts[0]
                email = parts[1]
                gpg = parts[2]
                date = parts[3]
                
                # SOC 2 Logic: G = Good signature. Anything else is a failure in accountability
                status = "PASS" if gpg == "G" else "FAIL"
                
                self.results["findings"].append({
                    "id": "SOC2-CC1.5",
                    "type": "Process",
                    "status": status,
                    "control": "Accountability & Change Management",
                    "evidence": {
                        "commit": h[:8],
                        "author": email,
                        "gpg_status": "Verified (Good)" if gpg == "G" else f"Unsigned/Invalid ({gpg})",
                        "date": date
                    }
                })
                self.results["stats"]["pass" if status == "PASS" else "fail"] += 1
            else:
                raise ValueError("Git output format mismatch")

        except Exception as e:
            self.results["findings"].append({
                "id": "SOC2-CC1.5",
                "type": "Process",
                "status": "FAIL",
                "evidence": f"Git Scan Error: {str(e)}"
            })
            self.results["stats"]["fail"] += 1


    def audit_logic(self):
        """CC6.1/CC7.2: Logic checks via Semgrep pattern matching"""
        if not os.path.exists(self.config_path):
            return
        
        raw = self._run(["semgrep", "--config", self.config_path, "--json", self.target_dir])
        
        try:
            data = json.loads(raw)
            findings = data.get("results", [])
            target_ids = ["SOC2-CC6.1-Auth-Check", "SOC2-CC6.3-Admin-Privilege"]

            # Capture coverage data for TUI
            self.results["metadata"]["files_scanned"] = len(data.get("paths", {}).get("scanned", []))
            self.results["metadata"]["target_path"] = self.target_dir

            # Map every rule in YAML; if not in findings, it's a PASS
            for cid in target_ids:
                issues = [i for i in findings if i["check_id"] == cid]
                status = "FAIL" if issues else "PASS"

                # Logic: If 10 functions fail one control, that is 10 "fail" points
                # for the developer to fix, but 1 "FAIL" for the SOC2 Matrix.
                if issues:
                    self.results["stats"]["fail"] += len(issues)
                else:
                    self.results["stats"]["pass"] += 1 

                self.results["findings"].append({
                    "id": cid.split('-')[1], 
                    "type": "Logic", 
                    "status": status,
                    "control": cid.replace("SOC2-", "").replace("-", " "),
                    "evidence": [{"file": i["path"], "line": i["start"]["line"], "msg": i["extra"]["message"]} for i in issues] if issues else "Verified compliant code patterns."
                })
        
        except Exception as e:
            print(f"❌ Failed to parse Semgrep output: {e}")


    def save(self):
        # Generate Tamper-Proof Hash of the results
        results_str = json.dumps(self.results, sort_keys=True)
        self.results["metadata"]["integrity_hash"] = hashlib.sha256(results_str.encode()).hexdigest()

        with open(self.report_template, "r") as f:
            html = f.read().replace("{{AUDIT_DATA}}", json.dumps(self.results))
        with open("audit_report.html", "w") as f: f.write(html)
        print(f"✅ Audit complete. Score: {self.results['stats']['pass']}/{self.results['stats']['pass']+self.results['stats']['fail']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NGG Governance Engine")
    parser.add_argument("target", help="Path to the project root (contains backend/app)")
    args = parser.parse_args()

    engine = NextGenAuditor(target_dir=args.target)
    engine.audit_git()
    engine.audit_logic()
    engine.save()
