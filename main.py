#!/usr/bin/env python3

import argparse
import requests
import logging
import sys
import json
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed HTTP methods to test
HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH']

def setup_argparse():
    """
    Sets up the command-line argument parser.
    """
    parser = argparse.ArgumentParser(description="Audits a website's allowed HTTP methods for each endpoint, highlighting potential vulnerabilities.",
                                     epilog="Example: python vuln_http_method_auditor.py -u https://example.com")
    parser.add_argument("-u", "--url", required=True, help="The target URL to audit.")
    parser.add_argument("-e", "--endpoints", nargs='+', help="Specific endpoints to test. If not provided, attempts to test all discovered endpoints.")
    parser.add_argument("-m", "--methods", nargs='+', default=HTTP_METHODS, help="HTTP methods to test (default: all).  Example: GET POST PUT DELETE")
    parser.add_argument("-o", "--output", help="Output file to save results (JSON format).")
    parser.add_argument("--discover", action="store_true", help="Attempt to discover endpoints by crawling.") # Placeholder for future crawling functionality
    parser.add_argument("--user-agent", default="VulnHTTPMethodAuditor/1.0", help="Custom User-Agent string.")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds.")
    parser.add_argument("--ignore-ssl", action="store_true", help="Ignore SSL certificate validation errors.")
    
    return parser.parse_args()


def test_http_methods(url, endpoint, methods, user_agent="VulnHTTPMethodAuditor/1.0", timeout=10, ignore_ssl=False):
    """
    Tests the allowed HTTP methods for a given endpoint.

    Args:
        url (str): The base URL of the website.
        endpoint (str): The specific endpoint to test.
        methods (list): A list of HTTP methods to test.
        user_agent (str): The User-Agent string to use.
        timeout (int): Request timeout in seconds.
        ignore_ssl (bool): Whether to ignore SSL certificate validation errors.

    Returns:
        dict: A dictionary containing the results of the HTTP method tests.
              Keys are HTTP methods, values are boolean indicating if the method is allowed (status code not in 400-599).
              Returns None on failure.
    """
    results = {}
    full_url = urljoin(url, endpoint)  # Ensure proper URL joining

    try:
        for method in methods:
            try:
                logging.debug(f"Testing {method} on {full_url}")
                response = requests.request(method, full_url, headers={'User-Agent': user_agent}, timeout=timeout, verify=not ignore_ssl)

                if 400 <= response.status_code < 600:
                    results[method] = False
                else:
                    results[method] = True

                logging.debug(f"{method} - Status Code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error testing {method} on {full_url}: {e}")
                results[method] = None # Mark as error
            except Exception as e:
                logging.error(f"Unexpected error testing {method} on {full_url}: {e}")
                results[method] = None
    except Exception as e:
         logging.error(f"An unexpected error occurred: {e}")
         return None
    return results


def save_results_to_file(results, filename):
    """
    Saves the results to a JSON file.

    Args:
        results (dict): The results to save.
        filename (str): The filename to save the results to.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving results to {filename}: {e}")

def main():
    """
    Main function to drive the HTTP method auditor.
    """
    args = setup_argparse()

    # Input validation
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    if args.endpoints is None:
        logging.warning("No endpoints specified.  Consider using --discover (not implemented) or providing specific endpoints with -e.")
        print("Error: No endpoints specified, this tool requires you to explicitly list the endpoints. Example: -e /admin /api/v1")
        sys.exit(1) #exit if no endpoints are provided


    all_results = {}

    for endpoint in args.endpoints:
        logging.info(f"Auditing endpoint: {endpoint}")
        results = test_http_methods(args.url, endpoint, args.methods, args.user_agent, args.timeout, args.ignore_ssl)
        if results:
            all_results[endpoint] = results
        else:
            logging.error(f"Failed to test HTTP methods for endpoint: {endpoint}")

    if args.output:
        save_results_to_file(all_results, args.output)
    else:
        print(json.dumps(all_results, indent=4))  # Print to console if no output file specified.

    logging.info("Audit completed.")


if __name__ == "__main__":
    main()