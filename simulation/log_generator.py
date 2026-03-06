"""
Generates realistic syslog lines mixed with malicious IOCs.
80% benign traffic, 20% malicious (matching IOCs from ioc_seeds.json).

Outputs to stdout or a file. Pipe to a file or directly into Wazuh agent container.

Usage:
    python simulation/log_generator.py --count 10000 --output logs/test.log
    python simulation/log_generator.py --stream --rate 2    # 2 logs/sec to stdout

Log types generated:
- SSH failed login (with IP)
- Web access log (with IP and URL)
- DNS query log (with domain)
- Firewall block log (with IP)
"""

import random
import argparse
import time
import datetime
import json
import sys
import os

# Load IOC seeds
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SEEDS_PATH = os.path.join(SCRIPT_DIR, "ioc_seeds.json")

with open(SEEDS_PATH, "r") as f:
    seeds = json.load(f)

# Log templates
TEMPLATES = {
    "ssh": "{date} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
    "web": '{date} {host} apache2[{pid}]: {ip} - - [{date}] "GET {url} HTTP/1.1" {status} {bytes}',
    "dns": "{date} {host} named[{pid}]: query: {domain} IN A + ({ip})",
    "firewall": "{date} {host} kernel: [UFW BLOCK] IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=443",
}

BENIGN_DOMAINS = [
    "google.com", "cloudflare.com", "github.com", "stackoverflow.com",
    "microsoft.com", "amazon.com", "wikipedia.org", "reddit.com",
]


def generate_log(malicious: bool = False) -> str:
    """Generate a single log line. If malicious, uses known-bad IOCs."""
    template_key = random.choice(list(TEMPLATES.keys()))
    template = TEMPLATES[template_key]

    ip = random.choice(seeds["malicious_ips"] if malicious else seeds["benign_ips"])
    domain = random.choice(
        seeds["malicious_domains"] if malicious else BENIGN_DOMAINS
    )

    return template.format(
        date=datetime.datetime.utcnow().strftime("%b %d %H:%M:%S"),
        host=f"webserver-{random.randint(1, 3)}",
        pid=random.randint(1000, 65535),
        user=random.choice(["root", "admin", "ubuntu", "ec2-user"]),
        ip=ip,
        port=random.randint(1024, 65535),
        url=random.choice(["/", "/login", "/admin", "/wp-admin", "/.env", "/api/v1/users"]),
        domain=domain,
        status=random.choice([200, 200, 200, 404, 403, 500]),
        bytes=random.randint(100, 50000),
    )


def main():
    parser = argparse.ArgumentParser(
        description="Generate realistic syslog lines mixed with malicious IOCs"
    )
    parser.add_argument(
        "--count", type=int, default=1000, help="Number of logs to generate"
    )
    parser.add_argument(
        "--output", type=str, default=None, help="Output file path"
    )
    parser.add_argument(
        "--stream", action="store_true", help="Continuous streaming mode"
    )
    parser.add_argument(
        "--rate", type=float, default=1.0, help="Logs per second in stream mode"
    )
    parser.add_argument(
        "--malicious-ratio",
        type=float,
        default=0.2,
        help="Ratio of malicious logs (0-1)",
    )
    args = parser.parse_args()

    output = None
    if args.output:
        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        output = open(args.output, "w")

    try:
        count = 0
        while args.stream or count < args.count:
            is_malicious = random.random() < args.malicious_ratio
            line = generate_log(malicious=is_malicious)

            print(line, file=output or sys.stdout, flush=True)
            count += 1

            if args.stream:
                time.sleep(1.0 / args.rate)

        if not args.stream:
            dest = args.output or "stdout"
            malicious_count = int(args.count * args.malicious_ratio)
            print(
                f"\n[+] Generated {args.count} log lines "
                f"(~{malicious_count} malicious) → {dest}",
                file=sys.stderr,
            )
    finally:
        if output:
            output.close()


if __name__ == "__main__":
    main()
