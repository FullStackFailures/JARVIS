# JARVIS (Milestone 1: kernel vertical slice)

Cross-platform (Linux/Windows) agent foundation. Linux verified (241 tests: 223 pass, 18 Windows-only skipped); **Windows written but NOT VERIFIED; CI written but never executed** (see `docs/WINDOWS_VERIFICATION.md`).

    pip install -e .                      # Python 3.11+
    jarvisd                               # daemon, foreground  (or: python -m jarvis.daemon / python main.py --daemon)
    jarvis ask "what is my hostname"      # thin client over local IPC (unix socket / named pipe)
    jarvis daemon status | stop
    jarvis audit verify
    jarvis --doctor | --self-test | --status | --tools | --tasks | --logs
    jarvis local "get my IP"              # in-process, no daemon
    python -m tests.run                   # test suite (stdlib unittest, tagged report)
    python -m tests.compat_matrix         # regenerate docs/compat-matrix.md

State of the project: `PROJECT_STATE.md`. Plan: `IMPLEMENTATION_PLAN.md`. Decisions: `DECISIONS.md`. Audit: `docs/M1_GAP_AUDIT.md`.
Not in M1: GUI, voice, browser automation, vision, memory, privileged execution, native packaging (.exe / launcher is M3).
