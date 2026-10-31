"""mitmproxy entry point. See README ("Egress proxy") for the full command.

    GOV_POLICY=policy/policy.yaml mitmdump -s scripts/mitm_gov.py
"""
from gov.collectors.egress_proxy import build_from_env

addons = [build_from_env()]
