"""Developer entry point: ``python main.py ...`` == ``jarvis ...`` (``python main.py --daemon`` == ``jarvisd``)."""

import sys

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "src"))

if __name__ == "__main__":
    if "--daemon" in sys.argv:
        sys.argv.remove("--daemon")
        from jarvis.daemon.main import main as daemon_main

        raise SystemExit(daemon_main())
    from jarvis.cli.main import main

    raise SystemExit(main())
