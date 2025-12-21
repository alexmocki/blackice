import argparse
from datetime import datetime, timezone, timedelta

from blackice.simulator.profiles import AttackProfile
from blackice.simulator.generator import AttackSimulator, write_jsonl


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="data/samples/simulated.jsonl")
    p.add_argument("--seed", type=int, default=1337)
    args = p.parse_args()

    sim = AttackSimulator(seed=args.seed)

    # smaller, more realistic mix
    profiles = [
        # baseline (mostly benign): single country, no special flags
        AttackProfile(
            name="baseline",
            description="Mostly normal traffic",
            total_events=200,
            users=80,
            window_minutes=60,
            success_rate=0.92,
            reuse_token=False,
            multi_country=False,
            impossible_travel=False,
            burst_single_ip=False,
        ),
        # stuffing
        AttackProfile(
            name="credential_stuffing_burst_ip",
            description="One IP sprays many usernames",
            total_events=180,
            users=120,
            window_minutes=10,
            success_rate=0.03,
            burst_single_ip=True,
        ),
        # token reuse
        AttackProfile(
            name="token_reuse_multi_country",
            description="Same token reused across countries",
            total_events=90,
            users=20,
            window_minutes=20,
            success_rate=0.9,
            reuse_token=True,
            multi_country=True,
        ),
        # impossible travel (keep it small!)
        AttackProfile(
            name="impossible_travel",
            description="A few impossible travel events",
            total_events=30,
            users=15,
            window_minutes=15,
            success_rate=0.85,
            impossible_travel=True,
            multi_country=True,
        ),
    ]

    events = []
    for prof in profiles:
        events.extend(sim.generate(prof))

    events.sort(key=lambda e: e["ts"])
    write_jsonl(args.out, events)
    print(f"wrote {len(events)} events -> {args.out}")


if __name__ == "__main__":
    main()




def run_replay(input_path: str, output_path: str):
    """Programmatic entrypoint: input events JSONL -> output alerts JSONL."""
    # Preferred: call a real function if the module defines it.
    if "replay" in globals() and callable(globals()["replay"]):
        return globals()["replay"](input_path, output_path)

    # Fallback: drive the simulator CLI main() by setting sys.argv.
    if "main" in globals() and callable(globals()["main"]):
        import sys
        old_argv = sys.argv[:]
        try:
            # Try common flag forms. Adjust if your CLI uses different names.
            sys.argv = [old_argv[0], "--input", input_path, "--output", output_path]
            try:
                rc = globals()["main"]()
            except TypeError:
                # Some CLIs define main(argv=None)
                rc = globals()["main"](None)
            except SystemExit as e:
                rc = int(getattr(e, "code", 0) or 0)

            # Return a minimal summary compatible with the pipeline.
            return {"input_events": input_path, "output_alerts": output_path, "exit_code": rc}
        finally:
            sys.argv = old_argv

    raise ImportError(
        "simulator/cli.py has neither replay(input_path, output_path) nor main(). "
        "Add replay(...) or adjust run_replay wrapper to call your real function."
    )

    raise ImportError(
        "run_replay wrapper added, but simulator/cli.py has no replay/main/run function. "
        "Open blackice/simulator/cli.py and rename your real function to replay(input_path, output_path) "
        "or update this wrapper to call the correct function."
    )
