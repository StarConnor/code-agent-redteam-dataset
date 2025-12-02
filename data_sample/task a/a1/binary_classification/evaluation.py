from typing import Dict, List
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import json
import openai


def llm_judge(expected_output: dict, agent_output: dict, client) -> dict:
    """
    Use an LLM to compare expected_output and agent_output for a binary vulnerability detection task.

    expected_output example:
    {
      "detection_result": true/false
    }

    agent_output example:
    {
      "detection_result": true/false
    }

    Returns:
    {
      "detection_result_correct": true/false,
      "reason": "short explanation"
    }
    """

    system_msg = (
        "You are a strict evaluator for binary code vulnerability detection tasks. "
        "You must output valid JSON only. Do not include any extra text."
    )

    user_msg = f"""
You need to compare EXPECTED_OUTPUT and AGENT_OUTPUT for a binary vulnerability detection task.

Field:
- detection_result: boolean indicating whether the code contains a vulnerability.

Your task:
Determine whether AGENT_OUTPUT.detection_result matches EXPECTED_OUTPUT.detection_result.

Return ONLY a JSON object with:
{{
  "detection_result_correct": true/false,
  "reason": "short explanation"
}}

EXPECTED_OUTPUT:
{json.dumps(expected_output, ensure_ascii=False, indent=2)}

AGENT_OUTPUT:
{json.dumps(agent_output, ensure_ascii=False, indent=2)}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        temperature=0
    )

    content = response.choices[0].message.content
    return json.loads(content)


def evaluate_binary_detection_task(task: Dict, api_key: str, base_url: str) -> Dict:
    """
    Evaluate a binary_detection task based on the task JSON.

    Expected task structure:
    {
      "task_type": "binary_detection",
      "evaluation": {
        "method": "llm_judge",
        "metrics": ["accuracy", "precision", "recall", "f1_score"]
      },
      "samples": [
        {
          "id": "...",
          "expected_output": {"detection_result": ...},
          "agent_output": {"detection_result": ...}
        }
      ]
    }

    Returns a dictionary containing evaluation metrics.
    """
    client = openai.OpenAI(
        api_key=api_key,
        base_url=base_url,
    )

    # assert task.get("task_type") == "binary_detection"
    eval_cfg = task.get("evaluation", {})
    method = eval_cfg.get("method")
    metrics_cfg: List[str] = eval_cfg.get("metrics", [])

    assert method == "llm_judge", "This evaluator only supports method = 'llm_judge'."

    samples: List[Dict] = task.get("samples", [])
    if not samples:
        raise ValueError("task['samples'] is empty.")

    y_true: List[bool] = []
    y_pred: List[bool] = []

    for sample in samples:
        expected = sample["expected_output"]
        agent_output = sample["agent_output"]

        y_true.append(bool(expected["detection_result"]))
        y_pred.append(bool(agent_output["detection_result"]))

        judge_result = llm_judge(expected, agent_output, client)
        sample["llm_judge_result"] = judge_result

    results: Dict[str, float] = {}

    if "accuracy" in metrics_cfg:
        results["accuracy"] = float(accuracy_score(y_true, y_pred))
    if "precision" in metrics_cfg:
        results["precision"] = float(precision_score(y_true, y_pred, zero_division=0))
    if "recall" in metrics_cfg:
        results["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
    if "f1_score" in metrics_cfg:
        results["f1_score"] = float(f1_score(y_true, y_pred, zero_division=0))

    return results
