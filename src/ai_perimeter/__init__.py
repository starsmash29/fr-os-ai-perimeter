"""FR_OS AI-Perimeter.

A language model turns an admin's intent into a *proposed* FR_OS config patch
and explains the router's anomaly evidence. It never executes anything: the
proposal goes through the FR_OS validator, the rule linter and a deny list in
code, an admin approves the diff, and FR_OS applies it with its timed
rollback (FR_OS security-lessons F5, I1).
"""

__version__ = "0.1.0"
