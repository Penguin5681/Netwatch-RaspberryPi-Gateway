import argparse
import time

from agent.capture import capture
from agent.flow_engine import aggregate


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch continuous monitoring runner"
    )

    parser.add_argument("--interface", default="wlan0")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--window", type=int, default=15)
    parser.add_argument("--bucket", type=int, default=60)
    parser.add_argument("--filter", default="ip or ip6")

    args = parser.parse_args()

    if min(args.duration, args.interval, args.window, args.bucket) < 1:
        parser.error("All time values must be positive.")

    print("====================================")
    print(" NETWATCH CONTINUOUS MONITOR")
    print("====================================")
    print(f"Interface        : {args.interface}")
    print(f"Capture duration : {args.duration}s")
    print(f"Cycle interval   : {args.interval}s")
    print(f"Analysis window  : {args.window} minutes")
    print("Press Ctrl+C to stop.")

    cycle = 0

    try:
        while True:
            cycle += 1
            started = time.monotonic()

            print(f"\n===== MONITOR CYCLE {cycle} =====")

            capture(
                interface=args.interface,
                duration=args.duration,
                bpf_filter=args.filter,
            )

            aggregate(
                window_minutes=args.window,
                bucket_seconds=args.bucket,
                interface=args.interface,
            )

            elapsed = time.monotonic() - started
            sleep_time = max(0, args.interval - elapsed)

            print(f"Cycle completed in {elapsed:.1f}s")

            if sleep_time:
                print(f"Next cycle in {sleep_time:.1f}s")
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\n[NETWATCH] Monitoring stopped.")


if __name__ == "__main__":
    main()
