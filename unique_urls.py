from urllib.parse import urlparse, parse_qs

def extract_url_pattern(url):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.split("/")
    pattern = "/".join(path_parts[:-2]) + "/"
    return pattern

def has_duplicate_url_pattern(url, seen_patterns):
    pattern = extract_url_pattern(url)
    if pattern in seen_patterns:
        return True
    seen_patterns.add(pattern)
    return False

def has_duplicate_query_params(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    unique_params = set(tuple(sorted(values)) for values in query_params.values())
    return len(query_params) != len(unique_params)

def filter_urls(urls):
    unique_urls = []
    seen_patterns = set()
    for url in urls:
        if not has_duplicate_url_pattern(url, seen_patterns) and not has_duplicate_query_params(url):
            unique_urls.append(url)
    return unique_urls

# Read URLs from file
file_path = "urls.txt"

with open(file_path, "r") as file:
    urls = file.read().splitlines()

# Filter unique URLs
unique_urls = filter_urls(urls)

# Write unique URLs back to file
with open(file_path, "w") as file:
    file.write("\n".join(unique_urls))

print("Unique URLs have been written to urls.txt.")
