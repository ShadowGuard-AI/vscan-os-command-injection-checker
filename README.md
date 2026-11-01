# vscan-os-command-injection-checker
Detects potential OS Command Injection vulnerabilities by injecting a set of predefined payloads into user-supplied input fields and analyzing the responses for command execution indicators (e.g., output of 'whoami' or 'id' commands). - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-os-command-injection-checker`

## Usage
`./vscan-os-command-injection-checker [params]`

## Parameters
- `--data`: Data to send in a POST request (e.g., 
- `--param`: The parameter to inject the payload into.  Required if --data is used.
- `--method`: No description provided
- `--headers`: Custom headers to send (e.g., 
- `--timeout`: Request timeout in seconds

## License
Copyright (c) ShadowGuardAI

## Behaviour notes
A safe verdict is printed only when at least one payload received a response; when no payload receives a response the scan reports failure and exits non-zero. Responses are compared against a baseline response fetched with a benign value, and only output shaped indicators (such as uid= and gid=) count as evidence. On a hit the tool prints a short excerpt around the match with credential shaped values redacted, never the full response body. Header values may contain colons and POST values may contain equals signs; both are split on the first separator only.
