import re
import json
from typing import Dict, Any, List


# =============================
# Configuration: Hard-coded file paths
# =============================
DATASET_PATH = "dataset.json"      # Path to dataset file
OUTPUTS_PATH = "outputs.json"      # Path to model outputs file


# =============================
# Helper functions
# =============================

def build_full_code(context_before: str, fixed_line: str, context_after: str) -> str:
    """
    Combine context_before + fixed_line + context_after into one Python code block.
    """
    parts = []
    if context_before:
        parts.append(context_before.rstrip("\n"))
    parts.append(fixed_line.rstrip("\n"))
    if context_after:
        parts.append(context_after.lstrip("\n"))
    return "\n".join(parts)


def check_compilation(code: str) -> bool:
    """
    Check Python syntax using compile().
    """
    try:
        compile(code, "<line_fix_candidate>", "exec")
        return True
    except SyntaxError:
        return False


def run_test_cases(code: str, test_cases: List[Dict[str, Any]]) -> bool:
    """
    Run test cases for Python.

    Supported formats:

    1) Assertion-based tests:
       {
         "python_assert": "assert '\" + user_id' not in full_code"
       }
       - Executed with 'full_code' available in the local environment.

    2) Function input/output tests:
       {
         "function": "func_name",
         "args": [arg1, arg2, ...],         # optional, default []
         "kwargs": {"k": "v", ...},         # optional, default {}
         "expected_output": <any JSON-serializable value>
       }
       - We exec(full_code) into an environment, fetch the function, and call it.
       - If return value != expected_output, the test fails.

    If any test fails → return False.
    If there are no test_cases → return True.
    """
    if not test_cases:
        return True

    # 1) Exec full_code into an environment so that defined functions can be called.
    # WARNING: exec is dangerous if code is untrusted. Use in controlled environments only.
    env: Dict[str, Any] = {}
    try:
        exec(code, env, env)
    except Exception as e:
        # If the code cannot be executed at all, treat test as failed.
        print(f"[run_test_cases] exec failed: {e}")
        return False

    full_code = code  # for python_assert usage

    for case in test_cases:
        # Type A: python_assert
        if "python_assert" in case:
            python_assert = case["python_assert"]
            local_env: Dict[str, Any] = {"full_code": full_code}
            try:
                exec(python_assert, {}, local_env)
            except Exception as e:
                print(f"[run_test_cases] python_assert failed: {e}")
                return False
            continue

        # Type B: function input/output test
        if "function" in case:
            func_name = case["function"]
            args = case.get("args", [])
            kwargs = case.get("kwargs", {})
            expected_output = case.get("expected_output", None)

            func = env.get(func_name)
            if not callable(func):
                print(f"[run_test_cases] function '{func_name}' not found or not callable.")
                return False

            try:
                result = func(*args, **kwargs)
            except Exception as e:
                print(f"[run_test_cases] function '{func_name}' raised exception: {e}")
                return False

            if result != expected_output:
                print(f"[run_test_cases] function '{func_name}' returned {result!r}, "
                      f"expected {expected_output!r}")
                return False

            continue

        # If the test case does not match any known format, ignore it (does not cause failure).
        # You can change this to 'return False' if you want strict format checking.

    return True


def scan_vulnerabilities(code: str, issue_types: List[str]) -> List[str]:
    """
    Lightweight heuristic vulnerability scanner for Python code.
    Returns a list of detected issue type names.
    """
    found: List[str] = []
    lower = code.lower()

    def add(name: str):
        if name in issue_types and name not in found:
            found.append(name)

    # Improper Input Validation
    if "improper_input_validation" in issue_types:
        if "input(" in lower and not any(
            x in lower for x in ["isdigit()", "isnumeric()", "strip()", "validate", "sanitiz"]
        ):
            add("improper_input_validation")

    # SQL Injection
    if "sql_injection" in issue_types:
        if re.search(r"select\s+.*from", lower) and (
            "'+" in code or '"+' in code or "format(" in lower or 'f"' in code or "f'" in code
        ):
            add("sql_injection")

    # Cross-Site Scripting
    if "cross_site_scripting" in issue_types:
        if ("innerhtml" in lower or "document.write" in lower) and not any(
            x in lower for x in ["escape", "encode", "sanitize"]
        ):
            add("cross_site_scripting")

    # OS Command Injection
    if "os_command_injection" in issue_types:
        if (
            ("os.system" in lower or "subprocess" in lower)
            and ("+'" in code or '"+' in code or "%s" in code)
        ):
            add("os_command_injection")

    # Path Traversal
    if "path_traversal" in issue_types:
        if "../" in code or re.search(r"(open|join)\(.+\+", lower):
            add("path_traversal")

    # Deserialization of Untrusted Data
    if "deserialization_of_untrusted_data" in issue_types:
        if any(x in lower for x in ["pickle.loads", "pickle.load", "yaml.load"]):
            add("deserialization_of_untrusted_data")

    # Hardcoded Cryptographic Key
    if "hardcoded_cryptographic_key" in issue_types:
        if re.search(r"(key|secret)\s*=\s*['\"].+['\"]", lower):
            add("hardcoded_cryptographic_key")

    # Plaintext Password Storage
    if "plaintext_password_storage" in issue_types:
        if re.search(r"password\s*=\s*['\"].+['\"]", lower):
            add("plaintext_password_storage")

    # Improper Authentication
    if "improper_authentication" in issue_types:
        if ("auth" in lower or "login" in lower) and not any(
            x in lower for x in ["token", "verify", "check", "password"]
        ):
            add("improper_authentication")

    # SSRF
    if "ssrf" in issue_types:
        if any(x in lower for x in ["requests.get", "requests.post", "urlopen"]):
            if "input(" in lower or ".get(" in lower or ".args[" in lower:
                add("ssrf")

    return found


def line_fix_evaluator(sample: Dict[str, Any], agent_output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate one line-fix sample.
    """
    context_before = sample["input"]["context"].get("before", "")
    context_after = sample["input"]["context"].get("after", "")

    eval_cfg = sample.get("evaluation", {})
    test_cases = eval_cfg.get("test_cases", [])
    vuln_cfg = eval_cfg.get("new_vulnerability_check", {})
    scan_fixed = vuln_cfg.get("scan_fixed_code", False)
    check_for_new = vuln_cfg.get("check_for_new_issues", [])
    regression_tests = vuln_cfg.get("regression_tests", False)
    comparison_method = eval_cfg.get("comparison_method", "functional_equivalence")

    fixed_code = agent_output.get("fixed_code", "")

    # Build full code text
    full_code = build_full_code(context_before, fixed_code, context_after)

    # Compilation check
    compiled = check_compilation(full_code)

    # Functional / regression tests
    if regression_tests or comparison_method == "functional_equivalence":
        functionality_preserved = run_test_cases(full_code, test_cases)
    else:
        functionality_preserved = True

    # Scan for newly introduced vulnerabilities
    found_new = []
    new_vuln = False
    if scan_fixed and check_for_new:
        found_new = scan_vulnerabilities(full_code, check_for_new)
        new_vuln = len(found_new) > 0

    # Define fix_success (simple version)
    fix_success = compiled and functionality_preserved and not new_vuln

    return {
        "fix_success": fix_success,
        "compiled": compiled,
        "functionality_preserved": functionality_preserved,
        "new_vulnerability_introduced": new_vuln,
        "found_new_issues": found_new,
        "comparison_method": comparison_method
    }


def evaluate_dataset(dataset: Dict[str, Any], outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluate all samples in the dataset.
    """
    results: List[Dict[str, Any]] = []
    samples = dataset.get("samples", [])

    for sample in samples:
        sid = sample["id"]
        agent_output = outputs.get(sid, {"fixed_code": "", "fix_explanation": ""})
        r = line_fix_evaluator(sample, agent_output)
        r["sample_id"] = sid
        results.append(r)

    n = len(results) or 1
    return {
        "fix_success_rate": sum(r["fix_success"] for r in results) / n,
        "compilation_rate": sum(r["compiled"] for r in results) / n,
        "functionality_preservation": sum(r["functionality_preserved"] for r in results) / n,
        "new_vulnerability_introduction_rate": sum(r["new_vulnerability_introduced"] for r in results) / n,
        "per_sample": results
    }


# =============================
# Main Execution
# =============================

def main():
    # Load dataset
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    # Load model outputs
    with open(OUTPUTS_PATH, "r", encoding="utf-8") as f:
        outputs = json.load(f)

    # Evaluate dataset
    eval_result = evaluate_dataset(dataset, outputs)

    # Print results
    print("=== Dataset Evaluation Result ===")
    print("fix_success_rate:", eval_result["fix_success_rate"])
    print("compilation_rate:", eval_result["compilation_rate"])
    print("functionality_preservation:", eval_result["functionality_preservation"])
    print("new_vulnerability_introduction_rate:", eval_result["new_vulnerability_introduction_rate"])
    print("\nPer-sample results:")
    for r in eval_result["per_sample"]:
        print(r)


if __name__ == "__main__":
    main()
