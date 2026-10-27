"""``ai-perimeter-chat``: send one prompt to a provider, to check the setup.

Examples::

    ai-perimeter-chat --provider local --model muse-glimmer "Hello"
    ai-perimeter-chat --provider baseten --allow-cloud "Hello"
    ai-perimeter-chat --provider meta --allow-cloud "Hello"

A cloud provider needs ``--allow-cloud`` every time (security-lessons G11),
and its key is read from ``~/.config/fr_os/<provider>_api_key`` (mode 0600).
"""

from __future__ import annotations

import argparse
import sys
import time

from .client import ChatClient, ConfigError, PRESETS, ProviderError, ProviderSettings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai-perimeter-chat", description=__doc__.split("\n")[0])
    parser.add_argument("--provider", default="local",
                        help=f"one of {', '.join(PRESETS)} or a custom name with --base-url")
    parser.add_argument("--base-url")
    parser.add_argument("--model")
    parser.add_argument("--api-key-file")
    parser.add_argument("--allow-cloud", action="store_true",
                        help="allow a non-local provider (off by default)")
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--show-reasoning", action="store_true")
    parser.add_argument("prompt")
    args = parser.parse_args(argv)

    try:
        settings = ProviderSettings.build(
            args.provider, base_url=args.base_url, model=args.model,
            api_key_file=args.api_key_file, allow_cloud=args.allow_cloud,
            timeout=args.timeout)
        client = ChatClient(settings)
        started = time.monotonic()
        result = client.chat([{"role": "user", "content": args.prompt}],
                             max_tokens=args.max_tokens)
    except (ConfigError, ProviderError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    if args.show_reasoning and result.reasoning:
        print(f"--- reasoning ---\n{result.reasoning}\n--- answer ---")
    print(result.text)
    tokens = result.usage.get("completion_tokens")
    print(f"[{settings.name} {result.model or settings.model}, {elapsed:.1f} s"
          + (f", {tokens} tokens" if tokens else "") + "]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
