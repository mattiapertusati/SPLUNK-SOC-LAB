# Positive Tests

Positive tests represent controlled attack behaviors that are expected to trigger a detection.

Each test should document:

- Detection ID
- MITRE ATT&CK technique
- Test objective
- Attack simulation or command
- Expected telemetry
- Expected detection
- Observed result
- Validation date

## Test Result

A positive test is considered successful when the expected telemetry is generated and the corresponding detection triggers as expected.

Example structure:

```text
Detection ID: DET-001
Technique: T1059.001
Scenario: Encoded PowerShell execution

Expected:
Detection triggers on encoded PowerShell command execution.

Observed:
Detection triggered successfully.

Result:
PASS
