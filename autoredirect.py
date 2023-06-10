import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import concurrent.futures

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
                print(location)
                vulnerable_urls.append(url_new)
                break
            else:
                print('\033[92m[Non-Vulnerable]\033[0m', url_new)  # Print in green for non-vulnerable ones
                print(location)
                break

    if not found_keyword:
        print('\033[97m[Ignored]\033[0m', url)  # Print in white for ignored ones

    return url, is_vulnerable

# Use ThreadPoolExecutor to run the loops in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    results = executor.map(check_url, urls)

# Collect the results
processed_urls = set()
for result in results:
    url, is_vulnerable = result
    processed_urls.add(url)

# Remove processed URLs from the original list
urls = list(set(urls) - processed_urls)

print('Write vulnerable URLs to a file')
with open('vulnerable.txt', 'w') as file:
    for url in vulnerable_urls:
        file.write(url + '\n')
