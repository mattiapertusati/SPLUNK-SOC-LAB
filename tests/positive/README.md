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
```


---

## `tests/negative/README.md`

```markdown
# Negative Tests

Negative tests represent legitimate or benign activity that should not trigger a detection.

Each test should document:

- Detection ID
- Benign scenario
- Test command or activity
- Expected result
- Observed result
- False-positive assessment

## Test Result

A negative test is considered successful when the benign activity does not trigger the detection.
```

Example structure:

```text
Detection ID: DET-001
Scenario: Legitimate PowerShell administrative activity

Expected:
No detection.

Observed:
No detection generated.

Result:
PASS
```

---

## `tests/bypass/README.md`

```markdown
# Bypass Tests

Bypass tests evaluate whether a detection can be avoided by modifying the syntax or execution method of the monitored behavior.

Possible variations include:

- Case changes
- Command-line syntax changes
- Alternative executable paths
- Parent-process changes
- Equivalent administrative commands
- Obfuscation
- Alternative tooling

Each test should document:

- Detection ID
- Evasion variation
- Test input
- Expected result
- Observed result
- Detection gap, if any
```
## Test Result

A bypass test is used to identify detection weaknesses.

A test does not need to "pass" in the traditional sense. If a variation bypasses the detection, the result should be documented as a detection gap requiring tuning.
