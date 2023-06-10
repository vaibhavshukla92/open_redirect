import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import concurrent.futures
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
import signal
import sys
import atexit


# Open the file in write mode and truncate the content
with open('vulnerable.txt', 'w') as file:
    file.truncate(0)


def remove_similar_urls(urls):
    parsed_urls = []
    similar_urls = defaultdict(list)

    # Parse and group URLs by path and query parameters
    for url in urls:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Sort and format query parameters
        sorted_params = sorted((key, value[0]) for key, value in query_params.items())
        query_params_str = '&'.join(f'{key}={value}' for key, value in sorted_params)

        key = (parsed_url.path, query_params_str)
        parsed_urls.append((url, key))
        similar_urls[key].append(url)

    # Keep only one URL from each group
    unique_urls = [urls[0] for urls in similar_urls.values()]

    return unique_urls


# Create a flag to track if the program is interrupted
interrupted = False

def signal_handler(sig, frame):
    global interrupted
    interrupted = True

# Set the signal handler
signal.signal(signal.SIGINT, signal_handler)


# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# List of parameter names
parameter_names = [
    'url', 'target', 'rurl', 'dest', 'destination', 'redir', 'redirect_uri',
    'redirect_url', 'redirect', '/redirect/', '/cgi-bin/redirect.cgi', '/out/',
    '/out', 'view', '/loginto', 'image_url', 'go', 'return', 'returnTo',
    'return_to', 'checkout_url', 'continue', 'return_path', 'success', 'data',
    'qurl', 'login', 'logout', 'ext', 'clickurl', 'goto', 'rit_url',
    'forward_url', 'forward', 'pic', 'callback_url', 'jump', 'jump_url',
    'clicku', 'originUrl', 'origin', 'Url', 'desturl', 'u', 'page', 'u1',
    'action', 'action_url', 'Redirect', 'sp_url', 'service', 'recurl',
    'j?url', 'url=//', 'uri', 'u', 'allinurl:', 'q', 'link', 'src', 'tc?src',
    'linkAddress', 'location', 'burl', 'request', 'backurl', 'RedirectUrl',
    'Redirect', 'ReturnUrl', 'redirecturl', 'checkout_url', 'return_url', 'authorize_callback'
]

# Read URLs from file
with open('urls.txt', 'r') as file:
    urls = file.read().splitlines()
    urls = remove_similar_urls(urls)
# Initialize a list to store vulnerable URLs
vulnerable_urls = []

print('Check URLs for keywords and test for open redirection')

def check_url(url):
    found_keyword = False

    variations = [
        '///www.google.com/',
        '//www.google.com',
        '////www.google.com',
        'https://www.google.com',
        'https%3A%2F%2Fwww.google.com%2F',
        'https://www%2Egoogle%2Ecom',
        'https%3A%2F%2Fwww%252Egoogle%252Ecom',
        'http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D'
    ]

    is_vulnerable = False  # Flag variable to track vulnerability

    for variation in variations:
        # Check if URL contains any keyword
        for keyword in parameter_names:
            pattern = r'([?&])(' + re.escape(keyword) + r'=)'
            match = re.search(pattern, url)

            if match:
                found_keyword = True
                url_new = re.sub(r'(\?|&)' + re.escape(keyword) + '=([^&]*)', r'\1' + keyword + '=' + variation, url)
                break

        if found_keyword:
            # Test for open redirection by redirecting to www.google.com
            try:
                response = requests.get(url_new, allow_redirects=False, verify=False)
            except requests.exceptions.RequestException as e:
                print('\033[91m[Error]\033[0m', url_new, '--', str(e))
                continue  # Continue to the next variation

            # Analyze the response to determine vulnerability
            location = response.headers.get('Location', '')

            if 300 <= response.status_code <= 309 and (location.startswith('https://www.google.com') or location.startswith(variation)):
                print('\033[91m[Vulnerable]\033[0m', url_new)  # Print in red for vulnerable ones
                is_vulnerable = True
                vulnerable_urls.append(url_new)
                if url_new in urls:
                    urls.remove(url_new)
                try:
                    with open('vulnerable.txt', 'a') as file:
                        file.write(url_new + '\n')
                    break
                except:
                    print('Error occurred while writing vulnerable URLs to the file.')



            else:
                print('\033[92m[Non-Vulnerable]\033[0m', url_new)  # Print in green for non-vulnerable ones

    if not found_keyword:
        print('\033[97m[Ignored]\033[0m', url)  # Print in white for ignored ones

    return url, is_vulnerable

# Use ThreadPoolExecutor to run the loops in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    results = executor.map(check_url, urls)

