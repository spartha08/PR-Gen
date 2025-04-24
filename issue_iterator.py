#!/usr/bin/env python3
"""
SonarQubeIssueIterator: A Python class for iterating through SonarQube issues

This module provides a simple way to connect to SonarQube and iterate
through issues from a project with improved authentication and error handling.

Author: spartha08
Date: 2025-04-23
"""

import requests
import logging
import base64
import time
from datetime import datetime  # Added datetime import here
from urllib.parse import quote
from typing import Dict, List, Any, Iterator, Optional, Union, Tuple
from dataclasses import dataclass


@dataclass
class SonarQubeConfig:
    """Configuration for SonarQube connection"""
    url: str
    token: str = None
    username: str = None
    password: str = None
    project_key: str = None
    verify_ssl: bool = True
    retry_count: int = 3
    retry_delay: int = 2


class SonarQubeAuthError(Exception):
    """Authentication error for SonarQube"""
    pass


class SonarQubePermissionError(Exception):
    """Permission error for SonarQube"""
    pass


class SonarQubeIssueIterator:
    """
    Iterator class for SonarQube issues with improved error handling.
    
    This class connects to a SonarQube instance and provides methods to
    iterate through issues from a specific project.
    """
    
    def __init__(
        self, 
        config: SonarQubeConfig,
        batch_size: int = 100,
        filters: Dict[str, str] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the SonarQube Issue Iterator.
        
        Args:
            config: SonarQubeConfig object with connection details
            batch_size: Number of issues to fetch in each API call
            filters: Additional filters to apply to the issue search
            logger: Optional logger instance
        """
        self.url = config.url.rstrip('/')
        self.project_key = config.project_key
        self.batch_size = batch_size
        self.filters = filters or {}
        self.verify_ssl = config.verify_ssl
        self.retry_count = config.retry_count
        self.retry_delay = config.retry_delay
        
        # Set up logging
        self.logger = logger or logging.getLogger(__name__)
        
        # Set up authentication (token takes precedence over username/password)
        if config.token:
            self.auth = (config.token, '')
            self.headers = {'Authorization': f'Bearer {config.token}'}
            self.auth_method = 'token'
        elif config.username and config.password:
            auth_str = f"{config.username}:{config.password}"
            encoded_auth = base64.b64encode(auth_str.encode()).decode()
            self.headers = {'Authorization': f'Basic {encoded_auth}'}
            self.auth = (config.username, config.password)
            self.auth_method = 'basic'
        else:
            raise SonarQubeAuthError("Either token or username/password must be provided")
        
        # Check connection
        self._check_connection()
        
        # Internal state
        self._current_page = 1
        self._total_issues = None
        self._fetched_issues = []
        self._current_index = 0
        self._exhausted = False
    
    def _check_connection(self) -> None:
        """Verify SonarQube connection and permissions"""
        try:
            url = f"{self.url}/api/system/status"
            response = requests.get(
                url, 
                headers=self.headers, 
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            # Check if we can access the project
            if self.project_key:
                url = f"{self.url}/api/components/show"
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    params={'component': self.project_key},
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                
            self.logger.info(f"Successfully connected to SonarQube at {self.url}")
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise SonarQubeAuthError(f"Authentication failed for {self.url}")
            elif e.response.status_code == 403:
                raise SonarQubePermissionError(f"Permission denied for {self.project_key}")
            else:
                raise Exception(f"SonarQube connection error: {str(e)}")
    
    def __iter__(self) -> 'SonarQubeIssueIterator':
        """Return self as iterator"""
        self.reset()
        return self
    
    def __next__(self) -> Dict[str, Any]:
        """Get the next issue"""
        if self._current_index >= len(self._fetched_issues):
            if self._exhausted:
                raise StopIteration
            self._fetch_next_batch()
            if not self._fetched_issues or self._current_index >= len(self._fetched_issues):
                raise StopIteration
        
        issue = self._fetched_issues[self._current_index]
        self._current_index += 1
        return issue
    
    def reset(self) -> None:
        """Reset the iterator to start from the beginning"""
        self._current_page = 1
        self._current_index = 0
        self._fetched_issues = []
        self._exhausted = False
    
    def _make_request(self, method: str, endpoint: str, params: Dict = None, 
                     data: Dict = None, retries_left: int = None) -> requests.Response:
        """
        Make a request to the SonarQube API with retry logic
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (without base URL)
            params: URL parameters
            data: POST data
            retries_left: Number of retries left
            
        Returns:
            Response object
        """
        if retries_left is None:
            retries_left = self.retry_count
            
        url = f"{self.url}{endpoint}"
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                params=params,
                json=data,
                verify=self.verify_ssl
            )
            
            # Handle rate limiting
            if response.status_code == 429:
                if retries_left > 0:
                    wait_time = int(response.headers.get('Retry-After', self.retry_delay))
                    self.logger.warning(f"Rate limited. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    return self._make_request(method, endpoint, params, data, retries_left - 1)
                    
            # Handle server errors
            elif response.status_code >= 500 and retries_left > 0:
                self.logger.warning(f"Server error ({response.status_code}). Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
                return self._make_request(method, endpoint, params, data, retries_left - 1)
            
            # Handle authentication errors
            elif response.status_code == 401:
                raise SonarQubeAuthError("Authentication failed. Check your credentials.")
                
            # Handle permission errors
            elif response.status_code == 403:
                msg = f"Permission denied for {endpoint}"
                if params and 'key' in params:
                    msg += f" with key {params['key']}"
                raise SonarQubePermissionError(msg)
                
            # Raise for other errors
            response.raise_for_status()
            
            return response
            
        except requests.exceptions.ConnectionError as e:
            if retries_left > 0:
                self.logger.warning(f"Connection error. Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
                return self._make_request(method, endpoint, params, data, retries_left - 1)
            raise
    
    def _fetch_next_batch(self) -> None:
        """Fetch the next batch of issues from SonarQube"""
        if self._exhausted:
            return
        
        # Base parameters
        params = {
            "componentKeys": self.project_key,
            "p": self._current_page,  # Page number
            "ps": self.batch_size,    # Page size
        }
        
        # Add any additional filters
        params.update(self.filters)
        
        try:
            self.logger.debug(f"Fetching issues page {self._current_page} (batch size: {self.batch_size})")
            response = self._make_request("GET", "/api/issues/search", params=params)
            
            data = response.json()
            issues = data.get("issues", [])
            
            # Update total if not set yet
            if self._total_issues is None:
                self._total_issues = data.get("total", 0)
                self.logger.info(f"Total issues found: {self._total_issues}")
            
            # Check if we've reached the end
            if not issues:
                self._exhausted = True
                self.logger.debug("No more issues available")
            else:
                self._fetched_issues = issues
                self._current_index = 0
                self._current_page += 1
                self.logger.debug(f"Fetched {len(issues)} issues")
        
        except (SonarQubeAuthError, SonarQubePermissionError) as e:
            self.logger.error(str(e))
            self._exhausted = True
            self._fetched_issues = []
            raise
        
        except Exception as e:
            self.logger.error(f"Error fetching issues: {str(e)}")
            self._exhausted = True
            self._fetched_issues = []
    
    def filter(self, **kwargs) -> 'SonarQubeIssueIterator':
        """
        Apply additional filters to the issue search.
        
        Args:
            **kwargs: Key-value pairs for SonarQube API filters
                    (e.g., languages="java", severities="CRITICAL,BLOCKER")
        
        Returns:
            Self for chaining
        """
        self.filters.update(kwargs)
        self.reset()
        return self
    
    def get_total_count(self) -> int:
        """
        Get the total number of issues matching the filter criteria.
        
        Returns:
            Total issue count
        """
        if self._total_issues is None:
            # Trigger a fetch to get the total
            self._fetch_next_batch()
            # Reset to start fresh with iteration
            self.reset()
        
        return self._total_issues or 0
    
    def get_issue_by_key(self, issue_key: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific issue by its key.
        
        Args:
            issue_key: The SonarQube issue key
            
        Returns:
            Issue data or None if not found
        """
        try:
            response = self._make_request("GET", "/api/issues/search", params={"issues": issue_key})
            issues = response.json().get("issues", [])
            return issues[0] if issues else None
            
        except (SonarQubeAuthError, SonarQubePermissionError) as e:
            self.logger.error(f"Error fetching issue {issue_key}: {str(e)}")
            raise
        
        except Exception as e:
            self.logger.error(f"Error fetching issue {issue_key}: {str(e)}")
            return None
    
    def get_rule_details(self, rule_key: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a rule.
        
        Args:
            rule_key: The SonarQube rule key
            
        Returns:
            Rule data or None if not found
        """
        try:
            response = self._make_request("GET", "/api/rules/show", params={"key": rule_key})
            return response.json().get("rule")
            
        except (SonarQubeAuthError, SonarQubePermissionError) as e:
            self.logger.error(f"Error fetching rule {rule_key}: {str(e)}")
            raise
        
        except Exception as e:
            self.logger.error(f"Error fetching rule {rule_key}: {str(e)}")
            return None
    
    def get_source_code(self, component_key: str) -> Optional[str]:
        """
        Get source code for a component.
        
        Args:
            component_key: The component key
            
        Returns:
            Source code string or None if not found
        """
        try:
            response = self._make_request(
                "GET", 
                "/api/sources/raw", 
                params={"key": component_key}
            )
            return response.text
            
        except SonarQubePermissionError as e:
            self.logger.error(f"Error fetching source code for {component_key}: {str(e)}")
            self.logger.info("You may need 'Browse' permission on the project to access source code.")
            return None
            
        except Exception as e:
            self.logger.error(f"Error fetching source code for {component_key}: {str(e)}")
            return None
    
    def get_project_permissions(self) -> Optional[Dict[str, List[str]]]:
        """
        Get current user's permissions for the project
        
        Returns:
            Dictionary of permission groups or None if error
        """
        if not self.project_key:
            return None
            
        try:
            response = self._make_request(
                "GET", 
                "/api/permissions/users", 
                params={"projectKey": self.project_key}
            )
            data = response.json()
            users = data.get("users", [])
            
            # Extract current user's permissions
            current_user = None
            for user in users:
                if user.get("login") == "Current User":  # Placeholder, actual value depends on SonarQube version
                    current_user = user
                    break
                    
            return {"permissions": current_user.get("permissions", [])} if current_user else None
            
        except Exception as e:
            self.logger.error(f"Error fetching project permissions: {str(e)}")
            return None
    
    def get_file_line_context(self, component_key: str, line: int, context_lines: int = 10) -> Optional[Dict[str, Any]]:
        """
        Get line context around an issue
        
        Args:
            component_key: The component key
            line: The line number
            context_lines: Number of lines of context to include
            
        Returns:
            Dictionary with lines data or None if error
        """
        try:
            from_line = max(1, line - context_lines)
            to_line = line + context_lines
            
            response = self._make_request(
                "GET", 
                "/api/sources/lines", 
                params={
                    "key": component_key,
                    "from": from_line,
                    "to": to_line
                }
            )
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Error fetching line context for {component_key}: {str(e)}")
            return None
    
    def fetch_all(self) -> List[Dict[str, Any]]:
        """
        Fetch all matching issues at once.
        
        Warning: This could be memory-intensive for large projects.
        
        Returns:
            List of all matching issues
        """
        self.reset()
        return list(self)


# Example usage showing how to handle the 403 error you encountered
# if __name__ == "__main__":
#     import sys
#     import getpass
    
#     # Set up logging
#     logging.basicConfig(
#         level=logging.INFO,
#         format="%(asctime)s [%(levelname)s] %(message)s",
#         handlers=[logging.StreamHandler(sys.stdout)]
#     )
#     logger = logging.getLogger("sonarqube_example")
    
#     # Get credentials interactively (safer than hardcoding)
#     print("SonarQube Authentication")
#     url = input("SonarQube URL (default: http://localhost:9000): ") or "http://localhost:9000"
    
#     auth_type = input("Authentication type (token/user) [token]: ") or "token"
    
#     if auth_type.lower() == "token":
#         token = getpass.getpass("Enter your SonarQube token: ")
#         config = SonarQubeConfig(url=url, token=token)
#     else:
#         username = input("Username: ")
#         password = getpass.getpass("Password: ")
#         config = SonarQubeConfig(url=url, username=username, password=password)
    
#     # Set project key
#     project_key = input("Project key (default: pet-shop-api): ") or "pet-shop-api"
#     config.project_key = project_key
    
#     try:
#         # Create iterator
#         iterator = SonarQubeIssueIterator(config, logger=logger)
        
#         # Print current user info
#         current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         print(f"Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): {current_time}")
        
#         for idx, first_issue in enumerate(iterator, 1):
#             # Try to get source code
#             try:
#                 if first_issue:
#                     print(f"Iter {first_issue}")
#                     component_key = first_issue.get('component')
#                     print(f"Fetching source code for {component_key}...")
            
#                     source_code = iterator.get_source_code(component_key)
#                     if source_code:
#                         print(f"Successfully retrieved {len(source_code)} characters of source code")
#                         # Show first 100 characters as preview
#                         preview = source_code[:100].replace('\n', ' ') + ('...' if len(source_code) > 100 else '')
#                         print(f"Preview: {source_code}")
#                     else:
#                         print("Failed to retrieve source code. Check your permissions.")
#                         print("You need 'Browse' permission on the project to access source code.")
                
#                         # Suggest solutions
#                         print("\nPossible solutions:")
#                         print("1. Use a token with more permissions")
#                         print("2. Ask your SonarQube administrator to grant you 'Browse' permission")
#                         print("3. If you're an admin, you can grant yourself permission in the project settings")
            
#             except SonarQubeAuthError as e:
#                 print(f"Authentication error: {str(e)}")
#             except SonarQubePermissionError as e:
#                 print(f"Permission error: {str(e)}")
#     except Exception as e:
#         print(f"Error: {str(e)}")
