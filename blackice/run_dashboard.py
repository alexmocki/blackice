import argparse
from blackice.viz.dashboard import render_dashboard


def main():
    p = argparse.ArgumentParser(description="Render HTML dashboard report.")
    p.add_argument("--out", default=None, help="Optional output path (if supported by renderer).")
    args = p.parse_args()

    # Your current render_dashboard() works with defaults, so we keep it safe.
    out = render_dashboard() if args.out is None else render_dashboard(args.out)
    print(f"Open: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
