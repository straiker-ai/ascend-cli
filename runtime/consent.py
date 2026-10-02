"""Consent and cookie gates: the buttons a page puts between a visitor and its chat widget.

One list, used by BOTH halves of browser-drive so they cannot drift: discovery's capture clicks
through the gate before it looks for the launcher, and the per-probe browser adapter replays the
same step at the start of every session. Order matters — vendor buttons with stable ids first
(they never match anything else), generic text last.

MEASURED (2026-09-30): a widget behind an "Accept & continue" banner that only mounts its chat
iframe after acceptance. The capture found no launcher and no input, recorded no chat traffic,
and reported "the launcher never got past the consent gate to reach the inner frame".
"""
from __future__ import annotations

CONSENT_SELECTORS = [
    "[id*='accept-btn' i]",                         # a common consent-manager button id
    "#CybotCookiebotDialogBodyButtonAccept",         # Cookiebot
    "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
    "button[aria-label*='accept' i]",
    "[id*='consent' i] button", "[class*='consent' i] button",
    "[id*='cookie' i] button", "[class*='cookie' i] button",
    "button:has-text('Accept & continue')", "button:has-text('Accept and continue')",
    "button:has-text('Accept all')", "button:has-text('Accept')",
    "button:has-text('I agree')", "button:has-text('Agree')",
    "button:has-text('Got it')", "button:has-text('Allow all')",
]


def selectors(first: str | None = None) -> list[str]:
    """The shared list, with the selector a capture actually clicked tried first."""
    return ([first] if first else []) + [s for s in CONSENT_SELECTORS if s != first]
