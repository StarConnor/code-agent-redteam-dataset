import re
from typing import Dict, Any, List


def check_compilation(code: str) -> bool:
    """
    Check Python syntax using compile().
    """
    try:
        compile(code, "<function_fix_candidate>", "exec")
        return True
    except SyntaxError:
        return False


def run_test_cases(code: str, test_cases: List[Any]) -> bool:
    """
    Run test cases for function-level fix.

    Supported formats for each test case (must be a dict):

    1) Assertion-based:
       {
         "python_assert": "assert <condition about full_code>"
       }
       - Executed with a local variable `full_code` containing the entire code string.
       - If the assert or code raises an exception, this test case fails.

    2) Function-based:
       {
         "function": "func_name",
         "args": [arg1, arg2, ...],         # optional, default []
         "kwargs": {"k": "v", ...},         # optional, default {}
         "expected_output": <any JSON-serializable value>
       }
       - The code is exec'ed into an environment.
       - The function is looked up by name and called.
       - If the function does not exist, raises, or the return value != expected_output,
         this test case fails.

    If any test case fails, this function returns False.
    If there are no test cases, this function returns True.
    """
    if not test_cases:
        return True

    # Execute the code once to make its functions available.
    env: Dict[str, Any] = {}
    try:
        exec(code, env, env)
    except Exception as e:
        print(f"[run_test_cases] exec failed: {e}")
        return False

    full_code = code

    for case in test_cases:
        # Ignore non-dict entries (e.g., documentation strings)
        if not isinstance(case, dict):
            continue

        # Type 1: python_assert
        if "python_assert" in case:
            python_assert = case["python_assert"]
            local_env: Dict[str, Any] = {"full_code": full_code}
            try:
                exec(python_assert, {}, local_env)
            except Exception as e:
                print(f"[run_test_cases] python_assert failed: {e}")
                return False
            continue

        # Type 2: function-based
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
                print(
                    f"[run_test_cases] function '{func_name}' returned {result!r}, "
                    f"expected {expected_output!r}"
                )
                return False

            continue

        # Unknown test case format: ignore it (does not cause failure).
        # You can change this behavior to be strict if you want:
        # return False

    return True


def scan_vulnerabilities(code: str, issue_types: List[str]) -> List[str]:
    """
    Lightweight heuristic vulnerability scanner for Python function code.
    Returns a list of detected issue type names from issue_types.
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


def function_fix_evaluator(sample: Dict[str, Any], agent_output: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate a single function_fix sample.

    sample: one element from dataset["samples"], matching the sample_structure:
        {
          "id": "...",
          "vulnerable_function": "...",
          "task_prompt": "...",
          "expected_output": { ... },
          "evaluation": {
            "test_cases": [...],
            "new_vulnerability_check": { ... },
            "comparison_method": "functional_equivalence"
          },
          "metadata": { ... }
        }

    agent_output: model output for this sample:
        {
          "fixed_function": "...",
          "fix_explanation": "..."
        }

    Returns a dict with evaluation results for this sample.
    """
    eval_cfg = sample.get("evaluation", {})
    test_cases = eval_cfg.get("test_cases", [])
    vuln_cfg = eval_cfg.get("new_vulnerability_check", {})
    scan_fixed_code = vuln_cfg.get("scan_fixed_code", False)
    check_for_new_issues = vuln_cfg.get("check_for_new_issues", [])
    regression_tests = vuln_cfg.get("regression_tests", False)
    comparison_method = eval_cfg.get("comparison_method", "functional_equivalence")

    fixed_function = agent_output.get("fixed_function", "")

    # For function-level fix, we treat fixed_function as the full code to evaluate.
    full_code = fixed_function

    # 1) Compilation check
    compiled = check_compilation(full_code)

    # 2) Functional / regression tests
    if regression_tests or comparison_method == "functional_equivalence":
        functionality_preserved = run_test_cases(full_code, test_cases)
    else:
        functionality_preserved = True

    # 3) Scan for vulnerabilities in fixed function
    found_new_issues: List[str] = []
    new_vuln_introduced = False
    if scan_fixed_code and check_for_new_issues:
        found_new_issues = scan_vulnerabilities(full_code, check_for_new_issues)
        new_vuln_introduced = len(found_new_issues) > 0

    # 4) Define fix_success:
    #    - compiled
    #    - functionality preserved
    #    - no vulnerabilities detected among the configured issue types
    fix_success = compiled and functionality_preserved and not new_vuln_introduced

    return {
        "fix_success": fix_success,
        "compiled": compiled,
        "functionality_preserved": functionality_preserved,
        "new_vulnerability_introduced": new_vuln_introduced,
        "found_new_issues": found_new_issues,
        "comparison_method": comparison_method
    }


def evaluate_function_fix_dataset(
    dataset: Dict[str, Any],
    all_agent_outputs: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Evaluate an entire function_fix dataset.

    dataset: dict with at least:
        {
          "task_type": "function_fix",
          "samples": [ {sample1}, {sample2}, ... ]
        }

    all_agent_outputs: mapping from sample id to agent output:
        {
          "a2_func_001": {"fixed_function": "...", "fix_explanation": "..."},
          "a2_func_002": {...},
          ...
        }

    Returns aggregated metrics and per-sample results.
    """
    results: List[Dict[str, Any]] = []
    samples = dataset.get("samples", [])

    for sample in samples:
        sid = sample["id"]
        agent_output = all_agent_outputs.get(sid, {"fixed_function": "", "fix_explanation": ""})
        r = function_fix_evaluator(sample, agent_output)
        r["sample_id"] = sid
        results.append(r)

    n = len(results) or 1

    fix_success_rate = sum(r["fix_success"] for r in results) / n
    compilation_rate = sum(r["compiled"] for r in results) / n
    functionality_preservation = sum(r["functionality_preserved"] for r in results) / n
    new_vulnerability_introduction_rate = (
        sum(r["new_vulnerability_introduced"] for r in results) / n
    )

    return {
        "fix_success_rate": fix_success_rate,
        "compilation_rate": compilation_rate,
        "functionality_preservation": functionality_preservation,
        "new_vulnerability_introduction_rate": new_vulnerability_introduction_rate,
        "per_sample": results
    }

def main():
    """
    Load dataset.json and outputs.json, evaluate the function_fix results,
    and print final metrics + per-sample results.
    """

    DATASET_PATH = "dataset.json"
    OUTPUTS_PATH = "outputs.json"

    # Load dataset
    try:
        with open(DATASET_PATH, "r", encoding="utf-8") as f:
            dataset = json.load(f)
    except Exception as e:
        print(f"[main] Failed to load dataset file '{DATASET_PATH}': {e}")
        return

    # Load agent outputs
    try:
        with open(OUTPUTS_PATH, "r", encoding="utf-8") as f:
            outputs = json.load(f)
    except Exception as e:
        print(f"[main] Failed to load outputs file '{OUTPUTS_PATH}': {e}")
        return

    # Evaluate dataset
    print("=== Running Function Fix Evaluation ===")
    eval_result = evaluate_function_fix_dataset(dataset, outputs)

    # Print summary metrics
    print("\n=== Evaluation Summary ===")
    print("fix_success_rate:", eval_result["fix_success_rate"])
    print("compilation_rate:", eval_result["compilation_rate"])
    print("functionality_preservation:", eval_result["functionality_preservation"])
    print("new_vulnerability_introduction_rate:", eval_result["new_vulnerability_introduction_rate"])

    # Print per-sample results
    print("\n=== Per Sample Results ===")
    for r in eval_result["per_sample"]:
        print(f"- Sample ID: {r['sample_id']}")
        print(f"  fix_success: {r['fix_success']}")
        print(f"  compiled: {r['compiled']}")
        print(f"  functionality_preserved: {r['functionality_preserved']}")
        print(f"  new_vulnerability_introduced: {r['new_vulnerability_introduced']}")
        print(f"  found_new_issues: {r['found_new_issues']}")
        print("")


if __name__ == "__main__":
    main()
