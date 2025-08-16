import argparse
import json
from .utils import analyze_repository, analyze_local_file

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool to analyze Python and TypeScript code for vulnerable predicate functions, prioritizing TypeGuard and type predicates."
    )
    parser.add_argument(
        "--repo-url",
        type=str,
        help="URL of the GitHub repository to analyze (e.g., https://github.com/user/repo.git)"
    )
    parser.add_argument(
        "--file-path",
        type=str,
        help="Path to a specific file to analyze (relative to repo root if --repo-url is provided, otherwise a local file)"
    )
    args = parser.parse_args()

    if not args.repo_url and not args.file_path:
        parser.error("At least one of --repo-url or --file-path must be provided")

    try:
        if args.file_path and not args.repo_url:
            # Analyze a local file
            result = analyze_local_file(args.file_path)
        else:
            # Analyze a repository or a specific file in it
            result = analyze_repository(args.repo_url, args.file_path)
        print(json.dumps(result, indent=2))
    except ValueError as ve:
        print(f"Error: {str(ve)}")
        exit(1)
    except Exception as e:
        print(f"Error analyzing code: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()