#!/usr/bin/python3
import logging
from issue_iterator import SonarQubeConfig, SonarQubeIssueIterator

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

    # Iterate over all issues
    for issue in iterator:
        print(f"Issue {issue}")
        print(f"Issue Key: {issue.get('key')}")
        print(f"Severity: {issue.get('severity')}")
        print(f"Message: {issue.get('message')}")
        print(f"Component: {issue.get('component')}")
        print(f"Line: {issue.get('line')}")
        print(f"Source Code: \n {iterator.get_source_code(issue.get('component'))}")
        print("-" * 40)

except Exception as e:
    logger.error(f"An error occurred: {str(e)}")
