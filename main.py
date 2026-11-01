import argparse
import logging
import re
import sys
import urllib.parse

import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Payloads are stored in raw form; the single encoding step in
# send_request encodes them once, so the newline and carriage return
# payloads reach the target as %0A and %0D, not double encoded.
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
    "\nwhoami",  # newline + whoami
    "\rwhoami"   # carriage return + whoami
]

# Output shaped indicators only. A bare substring such as "root" is not
# an indicator: it matches ordinary page text such as a CSS :root rule.
COMMAND_EXECUTION_INDICATORS = [
    "uid=",  # Common in 'id' command output
    "gid=",  # Common in 'id' command output
    "www-data",  # Common user for web servers
    "NT AUTHORITY\\SYSTEM"  # Common Windows user
]

CREDENTIAL_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|session|cookie)(\s*[:=]\s*)\S+")


def setup_argparse():
    parser = argparse.ArgumentParser(description="Detect potential OS Command Injection vulnerabilities.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("--data", help="Data to send in a POST request (e.g., 'param1=value1&param2=value2').  If not provided, a GET request will be used.", default=None)
    parser.add_argument("--param", help="The parameter to inject the payload into.  Required if --data is used.", default=None)
    parser.add_argument("--method", help="The HTTP method to use (GET or POST).  Defaults to GET, use POST if --data is provided.", choices=['GET', 'POST'], default='GET')
    parser.add_argument("--headers", help="Custom headers to send (e.g., 'Header1: Value1, Header2: Value2').", default=None)
    parser.add_argument("--timeout", help="Request timeout in seconds", type=int, default=10)

    return parser.parse_args()


def find_indicator(response_text, baseline_text=None):
    """Return the first output shaped indicator that appears in the
    response but not in the baseline response, or None."""
    if not response_text:
        return None
    baseline = (baseline_text or "").lower()
    for indicator in COMMAND_EXECUTION_INDICATORS:
        if indicator.lower() in response_text.lower() and indicator.lower() not in baseline:
            return indicator
    return None


def is_vulnerable(response_text, baseline_text=None):
    return find_indicator(response_text, baseline_text) is not None


def redacted_excerpt(response_text, indicator, radius_before=40, radius_after=80):
    """Short excerpt around the match, with credential shaped values redacted."""
    idx = response_text.lower().find(indicator.lower())
    if idx < 0:
        idx = 0
    excerpt = response_text[max(0, idx - radius_before): idx + len(indicator) + radius_after]
    excerpt = CREDENTIAL_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", excerpt)
    excerpt = re.sub(r"(?i)Bearer\s+\S+", "Bearer [redacted]", excerpt)
    return " ".join(excerpt.split())


def send_request(url, method="GET", data=None, headers=None, payload=None, param=None, timeout=10):
    """Send one request. Returns the response for any status (error
    statuses are recorded data, not silent skips), or None when no
    response was received."""
    try:
        header_dict = {}
        if headers:
            for header_pair in headers.split(','):
                if ':' not in header_pair:
                    logging.error(f"Invalid header format: {header_pair}.  Skipping.")
                    return None
                key, value = header_pair.split(':', 1)
                header_dict[key.strip()] = value.strip()

        if method == "GET":
            sep = "&" if "?" in url else "?"
            full_url = url + sep + urllib.parse.quote_plus(param) + "=" + urllib.parse.quote_plus(payload)
            return requests.get(full_url, headers=header_dict, timeout=timeout)

        if method == "POST":
            post_data = {}
            if data:
                for data_pair in data.split('&'):
                    if '=' not in data_pair:
                        logging.error(f"Invalid data format: {data_pair}. Skipping.")
                        return None
                    key, value = data_pair.split('=', 1)
                    post_data[key.strip()] = value.strip()
                if param in post_data:
                    post_data[param] = payload
                else:
                    logging.error(f"Parameter '{param}' not found in POST data.")
                    return None
            return requests.post(url, data=post_data, headers=header_dict, timeout=timeout)

        logging.error(f"Invalid HTTP method: {method}")
        return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def main():
    args = setup_argparse()

    url = args.url
    data = args.data
    param = args.param
    method = args.method
    headers = args.headers
    timeout = args.timeout

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

    # Baseline response with a benign value, used so an indicator that
    # the page always contains is not reported as a hit.
    baseline = send_request(url, method, data, headers, "baselineprobe", param, timeout)
    baseline_text = baseline.text if baseline is not None else None
    if baseline is not None:
        logging.info(f"Baseline response recorded (status {baseline.status_code}).")

    completed = 0
    error_statuses = 0

    for payload in COMMAND_INJECTION_PAYLOADS:
        logging.info(f"Testing payload: {payload!r}")

        response = send_request(url, method, data, headers, payload, param, timeout)

        if response is None:
            logging.error(f"Failed to get a valid response for payload: {payload!r}")
            continue

        completed += 1
        if response.status_code >= 400:
            error_statuses += 1
        logging.info(f"Payload {payload!r} received a response (status {response.status_code}).")

        indicator = find_indicator(response.text, baseline_text)
        if indicator:
            logging.warning(f"Potential OS Command Injection vulnerability detected with payload: {payload!r}")
            print(f"VULNERABLE: {url} is potentially vulnerable to OS Command Injection.")
            print(f"Payload used: {payload!r}")
            print(f"Matched indicator: {indicator}")
            print(f"Excerpt: {redacted_excerpt(response.text, indicator)}")
            return
        logging.info(f"Payload {payload!r} did not trigger a vulnerability.")

    if completed == 0:
        print(f"SCAN FAILED: {url} could not be tested: no payload received a response, so no safety verdict can be given.")
        logging.error("Scan failed: no payload received a response.")
        sys.exit(1)

    print(f"SCAN COMPLETE: {url} appears to be safe from OS Command Injection using the tested payloads. ({completed} responses received, {error_statuses} with error status.)")


if __name__ == "__main__":
    main()
