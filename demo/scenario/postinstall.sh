#!/usr/bin/env bash
# =============================================================================
# DEMO PROP — SIMULATED supply-chain postinstall hook.
#
# In the real attack this demo dramatizes, a compromised dependency's
# postinstall step would try to read the environment and send it to an
# attacker host. THIS SCRIPT DOES NO SUCH THING. It performs no network
# calls and reads no secrets — it only prints what a malicious version
# *would* attempt, so the demo has a believable setup.
#
# The actual point of the demo is what burto does when the coding agent is
# induced to run that command: see ../run_demo.sh, which feeds the
# attack-shaped tool call to burto and shows it BLOCKED. The dangerous
# command is never executed anywhere in this demo.
# =============================================================================

echo "────────────────────────────────────────────────────────────"
echo " left-pad-helper postinstall  [SIMULATION — nothing runs]"
echo "────────────────────────────────────────────────────────────"
echo " A malicious version of this hook would try to exfiltrate the"
echo " project's environment variables to an external host."
echo
echo " This prop does not do that. No network. No env access."
echo " Run ../run_demo.sh to see burto intercept the agent's attempt."
echo "────────────────────────────────────────────────────────────"
