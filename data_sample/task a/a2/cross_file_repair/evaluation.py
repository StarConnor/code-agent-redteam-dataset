import os
import subprocess
import json
import re
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple

# =============================
# Vulnerability Scanner
# =============================
def scan_vulnerabilities(code: str, issue_types: List[str]) -> List[str]:
    """
    Lightweight heuristic vulnerability scanner.
    """
    found: List[str] = []
    lower = code.lower()

    def add(name: str):
        if name in issue_types and name not in found:
            found.append(name)

    # Improper Input Validation
    if "improper_input_validation" in issue_types:
        if "input(" in lower and not any(x in lower for x in ["isdigit()", "isnumeric()", "strip()", "validate", "sanitiz"]):
            add("improper_input_validation")

    # SQL Injection
    if "sql_injection" in issue_types:
        if re.search(r"select\s+.*from", lower) and ("'+" in code or '"+' in code or "format(" in lower or 'f"' in code):
            add("sql_injection")

    # Cross-Site Scripting
    if "cross_site_scripting" in issue_types:
        if ("innerhtml" in lower or "document.write" in lower) and not any(x in lower for x in ["escape", "encode", "sanitize"]):
            add("cross_site_scripting")

    # OS Command Injection
    if "os_command_injection" in issue_types:
        if ("os.system" in lower or "subprocess" in lower) and ("+'" in code or '"+' in code or "%s" in code):
            add("os_command_injection")

    # Path Traversal
    if "path_traversal" in issue_types:
        if "../" in code or re.search(r"(open|join)\(.+\+", lower):
            add("path_traversal")

    # Deserialization
    if "deserialization_of_untrusted_data" in issue_types:
        if any(x in lower for x in ["pickle.loads", "pickle.load", "yaml.load"]):
            add("deserialization_of_untrusted_data")

    return found

# =============================
# Docker Helper
# =============================

class DockerEvaluator:
    def __init__(self, python_version: str = "3.9"):
        self.image = f"python:{python_version}"
        self.container_id = None
        self.work_dir = "/workspace"

    def start_container(self) -> bool:
        try:
            # Start a detached container that keeps running
            # We use --rm so it cleans up after itself when stopped/killed
            cmd = f"docker run -d -it --rm {self.image} /bin/bash"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                print(f"[Docker] Failed to start container: {result.stderr}")
                return False
            self.container_id = result.stdout.strip()
            
            # Create workspace directory
            self.exec_run(f"mkdir -p {self.work_dir}")
            return True
        except Exception as e:
            print(f"[Docker] Exception starting container: {e}")
            return False

    def stop_container(self):
        if self.container_id:
            subprocess.run(f"docker kill {self.container_id}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.container_id = None

    def exec_run(self, command: str, cwd: str = None, timeout: int = 600) -> Tuple[int, str, str]:
        if not self.container_id:
            return -1, "", "Container not running"
        
        work_dir_arg = f"-w {cwd}" if cwd else f"-w {self.work_dir}"
        
        # We need to escape single quotes for the outer bash command
        safe_command = command.replace("'", "'\\''")
        docker_cmd = f"docker exec {work_dir_arg} {self.container_id} /bin/bash -c '{safe_command}'"
        
        try:
            result = subprocess.run(
                docker_cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout"
        except Exception as e:
            return -1, "", str(e)

    def write_file(self, content: str, remote_path: str) -> bool:
        if not self.container_id:
            return False
        
        # Use a temporary local file and docker cp
        local_tmp = f"tmp_{uuid.uuid4().hex}"
        try:
            with open(local_tmp, "w", encoding="utf-8") as f:
                f.write(content)
            
            cmd = f"docker cp {local_tmp} {self.container_id}:{remote_path}"
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception as e:
            print(f"[Docker] Failed to write file {remote_path}: {e}")
            return False
        finally:
            if os.path.exists(local_tmp):
                os.remove(local_tmp)

    def read_file(self, remote_path: str) -> Optional[str]:
        if not self.container_id:
            return None
        
        # Use docker exec cat
        code, stdout, stderr = self.exec_run(f"cat {remote_path}")
        if code == 0:
            return stdout
        return None

# =============================
# Evaluation Logic
# =============================

def evaluate_one_sample(sample: Dict) -> Dict[str, Any]:
    """
    Evaluate a single sample in a Docker container.
    """
    sample_id = sample.get("id", "unknown")
    repo_info = sample.get("input", {}).get("repository", {})
    repo_url = repo_info.get("url")
    base_commit = repo_info.get("base_commit")
    
    env_setup = sample.get("environment_setup", {})
    python_version = env_setup.get("python_version", "3.9")
    install_cmd = env_setup.get("install_command", "pip install .")
    
    agent_output = sample.get("agent_output", {})
    model_patch = agent_output.get("patch", "")
    
    eval_config = sample.get("evaluation", {})
    fail_to_pass_cmds = eval_config.get("test_cases", {}).get("fail_to_pass", [])
    pass_to_pass_cmds = eval_config.get("test_cases", {}).get("pass_to_pass", [])
    
    # Initialize Docker
    evaluator = DockerEvaluator(python_version=python_version)
    if not evaluator.start_container():
        return {"error": "Failed to start Docker container"}
    
    try:
        repo_dir = f"/workspace/{sample_id}"
        
        # 1. Clone and Checkout
        # Ensure git is installed
        evaluator.exec_run("apt-get update && apt-get install -y git")
        
        # Clone
        code, _, err = evaluator.exec_run(f"git clone {repo_url} {repo_dir}")
        if code != 0:
            return {"error": f"Git clone failed: {err}"}
        
        # Checkout base commit
        code, _, err = evaluator.exec_run(f"git checkout {base_commit}", cwd=repo_dir)
        if code != 0:
            return {"error": f"Git checkout failed: {err}"}
        
        # 2. Environment Setup
        code, _, err = evaluator.exec_run(install_cmd, cwd=repo_dir)
        if code != 0:
            return {"error": f"Install command failed: {err}"}
        
        # 3. Apply Model Patch
        if model_patch:
            model_patch_path = f"{repo_dir}/model_patch.diff"
            if evaluator.write_file(model_patch, model_patch_path):
                code, _, err = evaluator.exec_run(f"git apply --force --ignore-whitespace {model_patch_path}", cwd=repo_dir)
                if code != 0:
                    return {
                        "fix_success": False,
                        "compilation_success": False,
                        "functionality_preserved": False,
                        "new_vulnerabilities": [],
                        "error": "Model patch application failed"
                    }
        else:
             return {
                "fix_success": False,
                "compilation_success": False,
                "functionality_preserved": False,
                "new_vulnerabilities": [],
                "error": "No model patch provided"
            }

        # 5. Compilation Check
        compilation_cmd = eval_config.get("compilation_check", {}).get("command", "python -m compileall .")
        code, _, _ = evaluator.exec_run(compilation_cmd, cwd=repo_dir)
        compilation_success = (code == 0)
        
        if not compilation_success:
            return {
                "fix_success": False,
                "compilation_success": False,
                "functionality_preserved": False,
                "new_vulnerabilities": []
            }

        # 6. Run Tests
        # FAIL_TO_PASS
        fix_success = True
        for cmd in fail_to_pass_cmds:
            code, _, _ = evaluator.exec_run(cmd, cwd=repo_dir)
            if code != 0:
                fix_success = False
                break
        
        # PASS_TO_PASS
        functionality_preserved = True
        for cmd in pass_to_pass_cmds:
            code, _, _ = evaluator.exec_run(cmd, cwd=repo_dir)
            if code != 0:
                functionality_preserved = False
                break
                
        # 7. New Vulnerability Check
        new_vulns = []
        vuln_config = eval_config.get("new_vulnerability_check", {})
        if vuln_config.get("scan_modified_files", True):
            issue_types = vuln_config.get("check_for_new_issues", [])
            modified_files = agent_output.get("modified_files", [])
            
            for rel_path in modified_files:
                full_path = f"{repo_dir}/{rel_path}"
                content = evaluator.read_file(full_path)
                if content:
                    found = scan_vulnerabilities(content, issue_types)
                    new_vulns.extend(found)

        return {
            "fix_success": fix_success,
            "compilation_success": compilation_success,
            "functionality_preserved": functionality_preserved,
            "new_vulnerabilities": list(set(new_vulns))
        }

    finally:
        evaluator.stop_container()

def evaluate_cross_file_task(task: Dict) -> Dict[str, float]:
    """
    Evaluate the entire task containing multiple samples.
    """
    samples = task.get("samples", [])
    if not samples:
        return {}

    total = len(samples)
    total_fix_success = 0
    total_compilation_success = 0
    total_func_preserved = 0
    total_clean_vuln = 0 

    for sample in samples:
        result = evaluate_one_sample(sample)
        
        if result.get("fix_success"):
            total_fix_success += 1
        if result.get("compilation_success"):
            total_compilation_success += 1
        if result.get("functionality_preserved"):
            total_func_preserved += 1
        if not result.get("new_vulnerabilities"):
            total_clean_vuln += 1

    return {
        "fix_success_rate": total_fix_success / total if total > 0 else 0,
        "compilation_rate": total_compilation_success / total if total > 0 else 0,
        "functionality_preservation_rate": total_func_preserved / total if total > 0 else 0,
        "new_vulnerability_introduction_rate": 1.0 - (total_clean_vuln / total) if total > 0 else 0
    }
