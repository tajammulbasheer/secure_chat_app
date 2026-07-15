# 11. Continuous Integration using GitHub Actions

* Status: **Accepted**
* Date: 2026-07-06
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
Currently, validating code style formatting, dependencies updates, and test suite execution is done manually by the developer on their local host. As the project matures, or if multiple developers collaborate, there is no automatic check to prevent broken changes or formatting violations from being committed and pushed.

We need a Continuous Integration (CI) pipeline to automatically verify code health on every commit or pull request.

## Decision Drivers
- Automatically verify all cryptographic assertions and code unit tests.
- Verify compatibility with clean environments.
- Provide visible status badges for recruitment portfolio presentation.

## Considered Options
1. **Option A (Manual pre-commit hooks)**: Configure a git pre-commit hook that runs pytest locally. (Prone to local developer bypass, does not guarantee compatibility on other machines).
2. **Option B (GitHub Actions)**: Standard cloud-based automation pipeline integrated natively with GitHub repositories.

## Decision Outcome
Chosen Option: **Option B (GitHub Actions)**

### Implementation Details
We will create a GitHub Actions workflow configuration at `.github/workflows/ci.yml`.
The workflow will:
1. Trigger on every `push` or `pull_request` to target branches (`main` and `dev`).
2. Run on an isolated, fresh runner instance (`ubuntu-latest`).
3. Set up Python 3.10.
4. Cache and install dependencies defined in `requirements.txt` and `requirements-dev.txt` (which contains `pytest`).
5. Execute the test runner:
   ```bash
   python -m pytest tests/
   ```

### Positive Consequences
- **Automated Validation**: Restructures are validated in a clean Linux environment automatically, catching platform incompatibilities.
- **Portfolio Appeal**: GitHub displays a green checkmark next to verified commits, showing clean coding standards.

### Negative Consequences
- Minor execution delay on github actions.
