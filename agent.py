import os
import git
import tempfile
from groq import Groq
from pathlib import Path
import json
from dotenv import load_dotenv
import time

# Load environment variables from .env file
load_dotenv()

# Initialize Groq client
api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    raise ValueError("GROQ_API_KEY not found in .env file or environment variables. Set it in .env or as an environment variable.")
client = Groq(api_key=api_key)

# System prompt for analyzing predicate functions
SYSTEM_PROMPT = """
Analyze Python and TypeScript codebases to identify predicate functions with incomplete type or structure validation, which may allow invalid data to pass through and cause issues downstream. A predicate function either returns a boolean or a type-annotated data structure (e.g., Python: dict[str, int], TypeScript: Record<string, number>).

### Detection Criteria
1. **Scope**: Search for functions that:
   - Return a boolean or a type-annotated data structure.
   - Use superficial type checks (e.g., Python: `isinstance(x, dict)`, TypeScript: `typeof x === "object"`) without validating nested elements.
   - Have type annotations indicating specific constraints (e.g., key/value types) that are not enforced.
2. **Issues to Identify**:
   - Functions with superficial checks (e.g., Python: `isinstance(x, dict)` without checking keys/values; TypeScript: `typeof x === "object"` without checking properties).
   - Mismatches between type annotations and validation logic.
   - Missing validation of nested elements or required fields.

### Output Format
For each vulnerable function:
- **File**: File path relative to the repository.
- **Function**: Function name.
- **Line**: Starting line number.
- **Vulnerable Code**: Code snippet of the function.
- **Issue**: Explanation of why the function is vulnerable.
- **Corrected Code**: Suggested fix with proper validation.
- **Recommendations**: Best practices (e.g., use `mypy` for Python, `zod` for TypeScript, or add unit tests).

Return the analysis in JSON format:
{
  "vulnerabilities": [
    {
      "file": "string",
      "function": "string",
      "line": integer,
      "vulnerable_code": "string",
      "issue": "string",
      "corrected_code": "string",
      "recommendations": ["string"]
    }
  ]
}
If no vulnerabilities are found, return an empty vulnerabilities list.
"""

def clone_repository(repo_url: str, temp_dir: str) -> str:
    """Clone a GitHub repository to a temporary directory."""
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    clone_path = os.path.join(temp_dir, repo_name)
    try:
        git.Repo.clone_from(repo_url, clone_path)
        return clone_path
    except git.GitCommandError as e:
        raise ValueError(f"Failed to clone repository {repo_url}: {str(e)}")

def read_code_files(repo_path: str) -> dict:
    """Read Python and TypeScript files from the repository."""
    code_files = {}
    max_file_size = 1_000_000  # 1MB limit
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith((".py", ".ts")):
                file_path = os.path.join(root, file)
                # Skip files that are too large
                if os.path.getsize(file_path) > max_file_size:
                    print(f"Skipping {file_path}: File size exceeds {max_file_size} bytes")
                    continue
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        # Skip empty files
                        if content.strip():
                            code_files[file_path] = content
                        else:
                            print(f"Skipping {file_path}: File is empty")
                except UnicodeDecodeError:
                    print(f"Skipping {file_path}: Unable to decode file as UTF-8")
    return code_files

def analyze_code_with_groq(code: str, file_path: str) -> dict:
    """Send code to Groq API for vulnerability analysis with retry logic."""
    max_retries = 3
    retry_delay = 5  # seconds
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze the following code from {file_path}:\n\n```python\n{code}\n```"}
                ],
                max_tokens=4000,
                temperature=0.5,
                top_p=0.95,
                stream=False
            )
            raw_content = response.choices[0].message.content
            try:
                return json.loads(raw_content)
            except json.JSONDecodeError as e:
                print(f"JSON decode error for {file_path}: {str(e)}")
                print(f"Raw response: {raw_content}")
                return {"vulnerabilities": [], "error": f"Invalid JSON response from Groq API: {str(e)}"}
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"Retrying {file_path} ({attempt + 1}/{max_retries}) after error: {str(e)}")
                time.sleep(retry_delay)
                continue
            return {"vulnerabilities": [], "error": f"Failed to analyze {file_path}: {str(e)}"}
    return {"vulnerabilities": [], "error": f"Failed to analyze {file_path} after {max_retries} attempts"}

def analyze_repository(repo_url: str) -> dict:
    """Analyze a GitHub repository for vulnerable predicate functions."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Clone the repository
        repo_path = clone_repository(repo_url, temp_dir)
        
        # Read code files
        code_files = read_code_files(repo_path)
        
        # Analyze each file
        all_vulnerabilities = []
        for file_path, code in code_files.items():
            relative_path = os.path.relpath(file_path, repo_path)
            print(f"\n\nAnalyzing {relative_path}...")
            analysis = analyze_code_with_groq(code, relative_path)
            if "vulnerabilities" in analysis:
                all_vulnerabilities.extend(analysis["vulnerabilities"])
            if "error" in analysis:
                all_vulnerabilities.append({"file": relative_path, "error": analysis["error"]})
        
        return {"vulnerabilities": all_vulnerabilities}

def main():
    # Example usage
    repo_url = input("Enter the GitHub repository URL: ")
    try:
        result = analyze_repository(repo_url)
    except ValueError as ve:
        print(f"Error: {str(ve)}")
    except Exception as e:
        print(f"Error analyzing repository: {str(e)}")

if __name__ == "__main__":
    main()