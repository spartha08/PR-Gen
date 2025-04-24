#!/usr/bin/python3
import logging
import traceback
from issue_iterator import SonarQubeConfig, SonarQubeIssueIterator
from fix_generator import FixGenerator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("sonarqube_iterator_example")

# Configuration for SonarQube
sonarqube_url = "http://localhost:9000"  # Replace with your SonarQube server URL
project_key = "pet-shop-api"         # Replace with your project key
auth_token = "squ_9863d7942f02cda30b7e202686520790a4aef3a5"           # Replace with your SonarQube token

# Create a SonarQubeConfig object
config = SonarQubeConfig(
    url=sonarqube_url,
    token=auth_token,
    project_key=project_key
)

try:
    # Create an instance of the SonarQubeIssueIterator
    iterator = SonarQubeIssueIterator(config, batch_size=50, logger=logger)
    fg = FixGenerator(config, "aws_access_key", "aws_secret_key", "us-west-2", "model_id", logger=logger)
    # Iterate over all issues
    for issue in iterator:
        if issue:
            print(f"Issue {issue}")
            print(f"Issue Key: {issue.get('key')}")
            print(f"Severity: {issue.get('severity')}")
            print(f"Message: {issue.get('message')}")
            print(f"Component: {issue.get('component')}")
            print(f"Line: {issue.get('line')}")
            print(f"Source Code: \n {iterator.get_file_line_context(issue.get('component'), issue.get('line'), 5)}")
            print("-" * 40)
            print(f"Prompt: {fg.create_prompt(issue)}")
            print("-" * 40)
        else:  # Handle the case where the issue is None
            logger.warning("Received None issue from iterator. Skipping...")
            continue
except Exception as e:
    logger.error(f"An error occurred: {str(e)}")
    logger.error(f"Stack trace: {traceback.format_exc()}")
