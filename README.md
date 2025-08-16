# TypeNarrowingAgent

A CLI tool to analyze Python and TypeScript codebases for vulnerable predicate functions, prioritizing TypeGuard and type predicates (x is T).

## Installation

Clone the repository:
```bash
git clone https://github.com/sivasathyaseeelan/TypeNarrowingAgent.git
cd TypeNarrowingAgent
```

Install Poetry:
```bash
pip install poetry
```

Install dependencies:
```bash
poetry install
```

Create a .env file in the project root:
```bash
GROQ_API_KEY=your_groq_api_key
```
Obtain your API key from https://console.groq.com.


## Usage
Run the CLI tool using the agent command:

Analyze an entire repository:
```bash
poetry run agent --repo-url https://github.com/openai/openai-python.git
```

Analyze a specific file in a repository:
```bash
poetry run agent --repo-url https://github.com/openai/openai-python.git --file-path src/openai/_streaming.py
```

Analyze a local file:
```bash
poetry run agent --file-path /path/to/local/file.py
```


## Output
The tool outputs a JSON report, prioritizing vulnerabilities in Python TypeGuard and TypeScript x is T functions, followed by other predicate functions. Example:
```json
{
  "vulnerabilities": [
    {
      "file": "types.py",
      "function": "is_string_int_dict",
      "line": 15,
      "vulnerable_code": "from typing import TypeGuard\ndef is_string_int_dict(x: any) -> TypeGuard[dict[str, int]]:\n    return isinstance(x, dict)",
      "issue": "The TypeGuard function only checks if x is a dictionary but does not verify that keys are strings and values are integers.",
      "corrected_code": "from typing import TypeGuard\ndef is_string_int_dict(x: any) -> TypeGuard[dict[str, int]]:\n    if not isinstance(x, dict):\n        return False\n    return all(isinstance(k, str) and isinstance(v, int) for k, v in x.items())",
      "recommendations": ["Use mypy with --strict", "Use pydantic for runtime validation", "Add unit tests"]
    }
  ]
}
```

## Development
Run tests (once implemented):
```bash
poetry run pytest
```