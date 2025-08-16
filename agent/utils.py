import os
import git
import tempfile
from groq import Groq
from pathlib import Path
import json
from dotenv import load_dotenv
import time
import re
from .prompt import SYSTEM_PROMPT

# Load environment variables from .env file
load_dotenv()

# Initialize Groq client
api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    raise ValueError("GROQ_API_KEY not found in .env file or environment variables. Set it in .env or as an environment variable.")
client = Groq(api_key=api_key)

def clone_repository(repo_url: str, temp_dir: str) -> str:
    """Clone a GitHub repository to a temporary directory."""
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    clone_path = os.path.join(temp_dir, repo_name)
    try:
        git.Repo.clone_from(repo_url, clone_path)
        return clone_path
    except git.GitCommandError as e:
        raise ValueError(f"Failed to clone repository {repo_url}: {str(e)}")

def read_code_files(repo_path: str, specific_file: str = None) -> dict:
    """Read Python and TypeScript files from the repository or a specific file."""
    code_files = {}
    max_file_size = 1_000_000  # 1MB limit
    if specific_file:
        file_path = os.path.join(repo_path, specific_file)
        if not os.path.exists(file_path):
            raise ValueError(f"File {specific_file} not found in repository")
        if not file_path.endswith((".py", ".ts")):
            raise ValueError(f"File {specific_file} must be a .py or .ts file")
        if os.path.getsize(file_path) > max_file_size:
            raise ValueError(f"File {file_path} exceeds size limit of {max_file_size} bytes")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                if not content.strip():
                    raise ValueError(f"File {file_path} is empty")
                code_files[file_path] = content
        except UnicodeDecodeError:
            raise ValueError(f"Unable to decode {file_path} as UTF-8")
    else:
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith((".py", ".ts")):
                    file_path = os.path.join(root, file)
                    if os.path.getsize(file_path) > max_file_size:
                        print(f"Skipping {file_path}: File size exceeds {max_file_size} bytes")
                        continue
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                            if content.strip():
                                code_files[file_path] = content
                            else:
                                print(f"Skipping {file_path}: File is empty")
                    except UnicodeDecodeError:
                        print(f"Skipping {file_path}: Unable to decode file as UTF-8")
    return code_files

def read_local_file(file_path: str) -> dict:
    """Read a local Python or TypeScript file."""
    if not os.path.exists(file_path):
        raise ValueError(f"Local file {file_path} not found")
    if not file_path.endswith((".py", ".ts")):
        raise ValueError(f"File {file_path} must be a .py or .ts file")
    max_file_size = 1_000_000  # 1MB limit
    if os.path.getsize(file_path) > max_file_size:
        raise ValueError(f"File {file_path} exceeds size limit of {max_file_size} bytes")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            if not content.strip():
                raise ValueError(f"File {file_path} is empty")
            return {file_path: content}
    except UnicodeDecodeError:
        raise ValueError(f"Unable to decode {file_path} as UTF-8")

def extract_json_from_response(raw_response: str) -> str:
    """Extract the JSON portion from a mixed text and JSON response."""
    # Find the JSON block using regex (matches `{ ... }` at the end)
    json_match = re.search(r'(\{.*\})', raw_response, re.DOTALL)
    if json_match:
        return json_match.group(1)
    return ""

def analyze_code_with_groq(code: str, file_path: str) -> dict:
    """Send code to Groq API for vulnerability analysis with retry logic and JSON extraction."""
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
            if not raw_content.strip():
                print(f"Empty response from Groq API for {file_path}")
                return {"vulnerabilities": [], "error": f"Empty response from Groq API for {file_path}"}

            # Extract JSON from the response
            json_content = extract_json_from_response(raw_content)
            if not json_content:
                print(f"No valid JSON found in response for {file_path}")
                print(f"Raw response: {raw_content}")
                return {"vulnerabilities": [], "error": f"No valid JSON found in response for {file_path}"}

            try:
                parsed_json = json.loads(json_content)
                return parsed_json
            except json.JSONDecodeError as e:
                print(f"JSON decode error for {file_path}: {str(e)}")
                print(f"Extracted JSON content: {json_content}")
                print(f"Raw response: {raw_content}")
                return {"vulnerabilities": [], "error": f"Invalid JSON response from Groq API: {str(e)}"}
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"Retrying {file_path} ({attempt + 1}/{max_retries}) after error: {str(e)}")
                time.sleep(retry_delay)
                continue
            print(f"Failed to analyze {file_path}: {str(e)}")
            print(f"Raw response: {raw_content if 'raw_content' in locals() else 'No response received'}")
            return {"vulnerabilities": [], "error": f"Failed to analyze {file_path}: {str(e)}"}
    return {"vulnerabilities": [], "error": f"Failed to analyze {file_path} after {max_retries} attempts"}

def analyze_repository(repo_url: str, specific_file: str = None) -> dict:
    """Analyze a GitHub repository or a specific file in it for vulnerable predicate functions."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Clone the repository
        repo_path = clone_repository(repo_url, temp_dir)
        
        # Read code files
        code_files = read_code_files(repo_path, specific_file)
        
        # Analyze each file
        all_vulnerabilities = []
        for file_path, code in code_files.items():
            relative_path = os.path.relpath(file_path, repo_path)
            print(f"\nAnalyzing {relative_path}...")
            analysis = analyze_code_with_groq(code, relative_path)
            if "vulnerabilities" in analysis:
                all_vulnerabilities.extend(analysis["vulnerabilities"])
            if "error" in analysis:
                all_vulnerabilities.append({"file": relative_path, "error": analysis["error"]})
        
        return {"vulnerabilities": all_vulnerabilities}

def analyze_local_file(file_path: str) -> dict:
    """Analyze a local file for vulnerable predicate functions."""
    code_files = read_local_file(file_path)
    all_vulnerabilities = []
    for file_path, code in code_files.items():
        print(f"\nAnalyzing {file_path}...")
        analysis = analyze_code_with_groq(code, file_path)
        if "vulnerabilities" in analysis:
            all_vulnerabilities.extend(analysis["vulnerabilities"])
        if "error" in analysis:
            all_vulnerabilities.append({"file": file_path, "error": analysis["error"]})
    return {"vulnerabilities": all_vulnerabilities}