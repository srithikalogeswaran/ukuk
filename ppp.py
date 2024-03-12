import requests
import argparse
import os

# ANSI escape codes for colored text
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[33m"
END = "\033[0m"

def check_clickjacking_vulnerability(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    try:
        response = requests.get(url, headers=headers)
    except requests.exceptions.RequestException:
        return f"Error: Failed to connect to '{url}'. Please enter a valid domain name."

    if response.ok:
        if "frame" in response.headers.get("content-security-policy", "").lower():
            return f"{GREEN}✓ Not vulnerable{END}"
        if "frame-ancestors" in response.headers.get("content-security-policy", "").lower():
            return f"{GREEN}✓ Not vulnerable{END}"
        if "x-frame-options" in response.headers:
            return f"{GREEN}✓ Not vulnerable{END}"
        if "window.self !== window.top" in response.text:
            return f"{GREEN}✓ Not vulnerable{END}"

    return f"{RED}✗ Vulnerable{END}"

def check_clickjacking_vulnerability_file(filename, save_file=None):
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' does not exist.")
        return

    with open(filename, "r") as file:
        websites = file.readlines()

    vulnerable_sites = []

    for index, website in enumerate(websites, start=1):
        website = website.strip()
        if not website.startswith("http://") and not website.startswith("https://"):
            Website1 = "http://" + website

        result = check_clickjacking_vulnerability(website)
        bullet_mark = f"{YELLOW}{index}.{END}"
        print(f"\n{bullet_mark} {website}: {result}")
        if result.startswith(RED) and save_file:
            vulnerable_sites.append(website)

    if save_file and vulnerable_sites:
        with open(save_file, "w") as file:
            for site in vulnerable_sites:
                file.write(site + "\n")

    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clickjacking vulnerability checker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--single", help="Single website URL to check for vulnerabilities")
    group.add_argument("-m", "--multiple", nargs="+", help="Multiple website URLs to check for vulnerabilities")
    group.add_argument("-f", "--file", help="Text file containing a list of websites")
    parser.add_argument("-v", "--save", help="Save vulnerable sites to a text file")
    args = parser.parse_args()

    if args.single:
        website = args.single
        if not website.startswith("http://") and not website.startswith("https://"):
            website = "http://" + website

        result = check_clickjacking_vulnerability(website)
        if website.startswith("http://") or website.startswith("https://"):
            print(f"\n{result}")
        else:
            print(f"\n{website}: {result}")

        if result.startswith(RED) and args.save:
            with open(args.save, "a") as file:
                file.write(website + "\n")

    elif args.multiple:
        for index, website in enumerate(args.multiple, start=1):
            if not website.startswith("http://") and not website.startswith("https://"):
                websites = "http://" + website

            result = check_clickjacking_vulnerability(website)
            bullet_mark = f"{YELLOW}{index}.{END}"
            print(f"\n{bullet_mark} {website}: {result}")

            if result.startswith(RED) and args.save:
                with open(args.save, "a") as file:
                    file.write(website + "\n")

    elif args.file:
        check_clickjacking_vulnerability_file(args.file, args.save)
