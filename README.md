<div align="center">
  
<img width="50%" src="https://raw.githubusercontent.com/AmMoPy/NGG/refs/heads/main/ngg.svg"> 

# Next-Gen GRC (NGG): Automated Governance for the Paranoid Developer

</div>

## TF Is This ?

A language-agnostic, local-first engine that translates abstract compliance frameworks into concrete code contracts. Built as a prototype for the elite, refined through a consulting partnership for the secure.

If you’re here, it’s because you realized that other tools are just glorified HR checklists that don't actually look at your trash code. NGG actually opens your files and judges you.

### Architecture Decisions
> *How to avoid talking to real auditors*

- **Logic-Process Fusion:** Combines Semgrep with Git Metadata. If the code is good but you didn't GPG-sign it, you fail. If you signed it but forgot Auth, you fail.

- **Language Agnostic:** AST-based patterns, because you don't have time to write a specific parser for every framework you'll abandon next month.

- **Local-First:** No cloud. No SaaS. No "Subscription." It runs on your machine because you don't want anyone else seeing your TODO: fix this security hole comments.

## System Components

1. **The "Contract"** A list of ways to tell the scanner how your "special" code handles framework requirements (e.g., SOC 2 Criteria - CC6.1).
2. **The "Orchestrator"** A Python script that tries to run Semgrep without crashing your terminal.
3. **The "Shiny Lights"** A TUI dashboard using Rich so you can feel like a hacker while fixing line 42 for the fifth time.
4. **The "Lie-Detector"** A single-file HTML report you can email to an auditor to prove you're "compliant."

## Why SOC 2 For Demo?

**Flexibility:** Unlike ISO 27001, which is a rigid Management System, SOC 2 is "criteria-based." You define the controls that fit your app.

**Logic-Friendly:** SOC 2 "Trust Services Criteria" map very cleanly to the technical features I already built in my testing app [DOX](https://github.com/AmMoPy/DOX)!


## Getting Started

###  Prerequisites

- Python 3.10+
- Semgrep Binary (pip install semgrep)
- Rich (pip install rich pyyaml)

### Running The Audit

```bash
python engine.py # use --live for continuous monitoring
```
 
## The Value Proposition

Most GRC tools are "Administrative"; they check if a human did a task. **NGG** is "Technical"; it proves the software itself is compliant.

- **For the Auditor:** It moves from "Sampling" (checking 5 endpoints) to "Full Population Testing" (verifying 100% of the code).

- **For the Developer:** It turns compliance from a "Yearly Tax" into a "Unit Test."

---