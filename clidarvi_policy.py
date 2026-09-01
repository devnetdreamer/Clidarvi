# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
# Additional warranty, liability, and operational terms: see DISCLAIMER.md and TERMS.md.

"""Conservative command and confirmation policy for Clidarvi.

The module has no GUI or network dependencies.  It deliberately classifies only
commands whose intent can be inferred from the first CLI tokens.  Anything else
is ``UNKNOWN`` and should be shown to a user instead of being auto-approved.

Typical use in an automation loop::

    command_class = classify_command(command, device_type)
    decision = decide_follow_up(
        response,
        command,
        device_type,
        allow_destructive=user_explicitly_opted_in,
        follow_up_count=follow_ups_sent,
    )
    if decision.should_reply:
        connection.send_command_timing(decision.reply)

Prompt detection intentionally examines only the final non-empty output line
and uses full-line matches.  Words in banners or ordinary command output can
therefore never trigger an automatic reply.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Final, Pattern


class CommandClass(str, Enum):
    """Persistent-impact classification for a device command."""

    READ_ONLY = "read_only"
    CHANGE = "change"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class PromptAction(str, Enum):
    """Outcome of evaluating the final line of command output."""

    NO_PROMPT = "no_prompt"
    REPLY = "reply"
    BLOCKED = "blocked"
    LIMIT_REACHED = "limit_reached"


@dataclass(frozen=True)
class FollowUpPrompt:
    """A recognized, exact final-line prompt and its normal CLI response."""

    text: str
    reply: str
    requires_destructive_approval: bool
    kind: str


@dataclass(frozen=True)
class PromptDecision:
    """Decision returned by :func:`decide_follow_up`.

    ``reply`` is populated only when ``action`` is :attr:`PromptAction.REPLY`.
    Callers should log ``reason`` when a prompt is blocked or the cap is hit.
    """

    action: PromptAction
    command_class: CommandClass
    prompt: FollowUpPrompt | None = None
    reply: str | None = None
    reason: str = ""

    @property
    def should_reply(self) -> bool:
        """Return whether the caller may send ``reply`` automatically."""

        return self.action is PromptAction.REPLY


# A fixed cap is intentional: a device repeating a prompt must not create an
# unbounded response loop.  Three replies cover normal copy/save interactions.
MAX_FOLLOW_UPS: Final = 3
MAX_PROMPT_LINE_CHARS: Final = 512

_ANSI_ESCAPE_RE: Final[Pattern[str]] = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")
_OSC_ESCAPE_RE: Final[Pattern[str]] = re.compile(r"(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|$)", re.DOTALL)
_STRING_ESCAPE_RE: Final[Pattern[str]] = re.compile(
    r"(?:\x1b[P\^_X]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c|$)", re.DOTALL
)
_SINGLE_ESCAPE_RE: Final[Pattern[str]] = re.compile(r"\x1b(?:[ -/]*[@-~])?")
_MULTISPACE_RE: Final[Pattern[str]] = re.compile(r"\s+")
_CHAINING_RE: Final[Pattern[str]] = re.compile(r"(?:;|&&?|\|\|?|[<>`()!]|\$\{)")
_OUTPUT_REDIRECTION_RE: Final[Pattern[str]] = re.compile(
    r"\|\s*(?:redirect|append|tee)\b", re.IGNORECASE
)
_PROMPT_CHOICE_END_RE: Final[Pattern[str]] = re.compile(
    r"(?:\[[^\]\r\n]+(?:/|,)\s*[^\]\r\n]+\]|"
    r"\([^\)\r\n]+(?:/|\bor\b)\s*[^\)\r\n]+\))\s*:?$",
    re.IGNORECASE,
)
_PROMPT_INSTRUCTION_RE: Final[Pattern[str]] = re.compile(
    r"\b(?:press|hit)\s+(?:enter|return|any\s+key)\b.*$|"
    r"\b(?:password|passphrase|username|confirmation)\s*:\s*$|"
    r"^\s*(?:enter|select|choose|specify|provide|type|how\s+many|file\s*name|"
    r"filename|destination|remote\s+host)\b[^\r\n]*(?:\?|:)?\s*$|"
    r"^\s*(?:continue|confirm|proceed|are\s+you\s+sure)\b"
    r"[^\r\n]*(?:\?|:)?\s*$|"
    r"\[[^\]\r\n]+\]\s*:?\s*$",
    re.IGNORECASE,
)
_URI_USERINFO_PASSWORD_RE: Final[Pattern[str]] = re.compile(
    r"(?P<prefix>[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]*:)[^\s/@]+(?=@)"
)
_CONTROL_DECORATED_RESPONSE_LABEL: Final = "<terminal-control response>"
_OVERSIZED_RESPONSE_LABEL: Final = "<oversized terminal response>"
_SENSITIVE_ARGUMENT_RE: Final[Pattern[str]] = re.compile(
    r"\b(?:password|passwd|secret|psksecret|community|token|key|key-string|"
    r"auth-key|shared-secret|client-secret|pre[- ]shared[- ]key|private[- ]key|"
    r"passphrase|wpa-psk|phash|"
    # Fortinet/Aruba SNMPv3 secret fields, including hyphenated forms.
    r"auth[- ](?:pwd|pass|password)|priv[- ](?:pwd|pass|password)|"
    # SNMPv3 auth/priv passphrases follow these positional markers.
    r"auth\s+(?:sha|sha-?(?:224|256|384|512)|md5)|priv\s+(?:aes|des|3des)|"
    # Cisco WLC and Aruba commands carry positional secrets after these.
    r"mgmt-?user(?:\s+add)?|netuser\s+add|v3user\s+create|"
    r"(?:radius|tacacs)\s+(?:auth|acct)\s+add|ascii|hex)\b",
    re.IGNORECASE,
)
_KEY_BLOCK_RE: Final[Pattern[str]] = re.compile(
    r"-{3,}\s*BEGIN[^\n]{0,80}?-{3,}.*?(?:-{3,}\s*END[^\n]{0,80}?-{3,}|\Z)",
    re.DOTALL | re.IGNORECASE,
)
# Cisco IOS "snmp-server host" carries the community string (or SNMPv3 user) as
# a POSITIONAL argument that no keyword precedes, so the keyword rule above
# cannot see it.  Match the fixed prefix and its optional qualifiers, then
# redact everything that follows (the secret plus any trailing options).
_SNMP_HOST_SECRET_RE: Final[Pattern[str]] = re.compile(
    r"^(\s*(?:no\s+)?snmp-server\s+host\s+\S+"
    r"(?:\s+vrf\s+\S+)?"
    r"(?:\s+(?:traps|informs))?"
    r"(?:\s+version\s+(?:1|2c|3(?:\s+(?:auth|noauth|priv))?))?"
    r")\s+\S.*$",
    re.IGNORECASE,
)


def _prefix_pattern(*prefixes: str) -> Pattern[str]:
    alternatives = "|".join(re.escape(prefix).replace(r"\ ", r"\s+") for prefix in prefixes)
    return re.compile(rf"(?:{alternatives})(?:\s|$)", re.IGNORECASE)


_READ_ONLY_BY_VENDOR: Final[dict[str, tuple[Pattern[str], ...]]] = {
    "cisco": (
        _prefix_pattern(
            "show",
            "sh",
            "do show",
            "do sh",
            "dir",
            "more",
        ),
    ),
    "fortinet": (
        _prefix_pattern("get", "show"),
        _prefix_pattern(
            "diagnose hardware deviceinfo",
            "diagnose ip address list",
            "diagnose netlink interface list",
            "diagnose sys session list",
            "diagnose sys top",
            "diagnose vpn tunnel list",
        ),
    ),
    "aruba": (
        _prefix_pattern(
            "show",
            "display",
        ),
    ),
    "paloalto": (
        _prefix_pattern(
            "show",
        ),
    ),
}

_DESTRUCTIVE_COMMON: Final[tuple[Pattern[str], ...]] = (
    _prefix_pattern(
        "delete",
        "erase",
        "format",
        "reload",
        "reboot",
        "halt",
        "poweroff",
        "shutdown",
        "factory reset",
        "factory-reset",
        "factoryreset",
        "wipe",
        "zeroize",
    ),
    re.compile(r"write\s+erase(?:\s|$)", re.IGNORECASE),
    re.compile(
        r"clear\s+(?:startup-config|startup-configuration|configuration)(?:\s|$)",
        re.IGNORECASE,
    ),
    # Full running-configuration replacement has no benign meaning on any
    # supported platform, so it is destructive even for the generic vendor
    # family.  The trailing boundary keeps Fortinet "config replacemsg ..."
    # out of this rule.
    re.compile(r"config(?:ure)?\s+replace(?:\s|$)", re.IGNORECASE),
)

_DESTRUCTIVE_BY_VENDOR: Final[dict[str, tuple[Pattern[str], ...]]] = {
    "cisco": (
        re.compile(r"request\s+platform\s+software\s+system\s+shell", re.I),
        # Cisco WLC full restart and configuration wipe.
        re.compile(r"reset\s+system(?:\s|$)", re.IGNORECASE),
        re.compile(r"clear\s+config(?:\s|$)", re.IGNORECASE),
    ),
    "fortinet": (
        re.compile(
            r"execute\s+(?:reboot|shutdown|factoryreset2?|formatlogdisk|disk\s+format|restore)"
            r"(?:\s|$)",
            re.IGNORECASE,
        ),
        _prefix_pattern("purge"),
    ),
    "aruba": (
        re.compile(r"erase\s+(?:all|startup-config)(?:\s|$)", re.IGNORECASE),
        _prefix_pattern("boot system"),
    ),
    "paloalto": (
        re.compile(r"request\s+(?:restart|shutdown)\s+system(?:\s|$)", re.IGNORECASE),
        re.compile(
            r"request\s+system\s+(?:private-data-reset|factory-reset)(?:\s|$)",
            re.IGNORECASE,
        ),
    ),
}

_CHANGE_COMMON: Final[tuple[Pattern[str], ...]] = (
    _prefix_pattern(
        "configure",
        "configure terminal",
        "conf t",
        "config",
        "set",
        "unset",
        "edit",
        "rename",
        "move",
        "clone",
        "commit",
        "revert",
        "save",
        "copy",
        "write memory",
        "wr mem",
        "interface",
        "router",
        "vlan",
        "hostname",
        "switchport",
        "description",
        "username",
        "snmp-server",
        "access-list",
        "banner",
        "logging",
        "line",
        "no",
    ),
)

_CHANGE_BY_VENDOR: Final[dict[str, tuple[Pattern[str], ...]]] = {
    "cisco": (_prefix_pattern("ip", "ipv6", "aaa", "spanning-tree"),),
    "fortinet": (_prefix_pattern("next", "end"),),
    "aruba": (_prefix_pattern("aaa", "spanning-tree"),),
    "paloalto": (_prefix_pattern("load"),),
}


def _vendor_family(vendor: str | None) -> str:
    """Map UI labels and Netmiko device types to one policy family."""

    normalized = re.sub(r"[^a-z0-9]+", "", (vendor or "").lower())
    if "forti" in normalized:
        return "fortinet"
    if any(token in normalized for token in ("aruba", "procurve", "aoscx")):
        return "aruba"
    if any(token in normalized for token in ("paloalto", "panos")):
        return "paloalto"
    if "cisco" in normalized or normalized in {
        "asa",
        "ios",
        "iosxe",
        "iosxr",
        "nxos",
    }:
        return "cisco"
    return "generic"


def _matches_any(command: str, patterns: tuple[Pattern[str], ...]) -> bool:
    return any(pattern.match(command) is not None for pattern in patterns)


def _is_unsafe_unicode_control(char: str, *, allow_line_controls: bool = False) -> bool:
    """Return whether *char* can alter parsing or the visual meaning of text.

    Unicode categories are intentionally used instead of an enumerated list so
    newly encountered bidi, format, surrogate, C0, and C1 code points fail
    closed. CR/LF are permitted only while processing a multi-line text block.
    """

    if allow_line_controls and char in "\r\n":
        return False
    return unicodedata.category(char) in {"Cc", "Cf", "Cs"}


def classify_command(command: str, vendor: str | None = None) -> CommandClass:
    """Classify one device command using conservative, vendor-aware rules.

    Leading/trailing whitespace and letter case are ignored.  Multi-line input,
    control characters, and shell-like command chaining are never considered
    read-only.  A destructive command always takes precedence over other rules.

    Args:
        command: A single command exactly as it would be sent to the device.
        vendor: A Clidarvi vendor label or Netmiko device type. Unknown vendors
            never receive a read-only allowlist. Active probes such as ping and
            traceroute are also left ``UNKNOWN`` and therefore require review.
    """

    if not isinstance(command, str):
        return CommandClass.UNKNOWN
    if any(_is_unsafe_unicode_control(char) for char in command):
        return CommandClass.UNKNOWN
    stripped = command.strip()
    if not stripped:
        return CommandClass.UNKNOWN

    normalized = _MULTISPACE_RE.sub(" ", stripped).lower()
    family = _vendor_family(vendor)
    effective = (
        normalized[3:].lstrip()
        if family == "cisco" and normalized.startswith("do ")
        else normalized
    )

    # Chained input is deliberately not allowlisted.  Preserve the strongest
    # useful warning if a destructive command appears in one of its segments.
    if _CHAINING_RE.search(effective):
        segments = [part.strip() for part in _CHAINING_RE.split(effective)]
        for segment in segments:
            if _matches_any(segment, _DESTRUCTIVE_COMMON) or _matches_any(
                segment, _DESTRUCTIVE_BY_VENDOR.get(family, ())
            ):
                return CommandClass.DESTRUCTIVE
        # Network-CLI redirection is a known state change, but only after all
        # chained segments have been checked for a destructive command.
        if _OUTPUT_REDIRECTION_RE.search(effective):
            return CommandClass.CHANGE
        return CommandClass.UNKNOWN

    if _matches_any(effective, _DESTRUCTIVE_COMMON) or _matches_any(
        effective, _DESTRUCTIVE_BY_VENDOR.get(family, ())
    ):
        return CommandClass.DESTRUCTIVE

    if _matches_any(effective, _CHANGE_COMMON) or _matches_any(
        effective, _CHANGE_BY_VENDOR.get(family, ())
    ):
        return CommandClass.CHANGE

    vendor_read_only = _READ_ONLY_BY_VENDOR.get(family, ())
    if _matches_any(effective, vendor_read_only):
        return CommandClass.READ_ONLY
    return CommandClass.UNKNOWN


def _normalize_terminal_text(text: str, *, allow_line_controls: bool = False) -> tuple[str, bool]:
    """Remove terminal controls without attempting to emulate a terminal.

    The boolean reports whether anything except CR/LF normalization was
    removed. Prompt policy uses it to fail closed: a control-decorated final
    prompt is never eligible for an automatic response. Redaction uses the
    normalized text so ANSI/OSC/C0 or bidi controls cannot split a secret
    keyword or visually rewrite a log line.
    """

    normalized = text
    suspicious = False
    for pattern in (
        _OSC_ESCAPE_RE,
        _STRING_ESCAPE_RE,
        _ANSI_ESCAPE_RE,
        _SINGLE_ESCAPE_RE,
    ):
        normalized, count = pattern.subn("", normalized)
        suspicious = suspicious or bool(count)
    safe_chars: list[str] = []
    for char in normalized:
        if _is_unsafe_unicode_control(char, allow_line_controls=allow_line_controls):
            suspicious = True
            continue
        safe_chars.append(char)
    normalized = "".join(safe_chars)
    if allow_line_controls:
        normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    return normalized, suspicious


def _redact_uri_userinfo_passwords(text: str) -> str:
    """Redact passwords embedded in supported URI userinfo fields."""

    return _URI_USERINFO_PASSWORD_RE.sub(r"\g<prefix><redacted>", text)


def redact_command(command: str) -> str:
    """Remove likely credential material before logging a command.

    Network CLIs vary widely, so the conservative rule redacts everything after
    the first credential-bearing keyword instead of trying to parse a secret's
    exact length or optional flags.
    """

    if not isinstance(command, str):
        return "<invalid command>"
    normalized, suspicious = _normalize_terminal_text(command)
    normalized = _redact_uri_userinfo_passwords(normalized)
    snmp_host = _SNMP_HOST_SECRET_RE.match(normalized)
    if snmp_host is not None:
        return f"{snmp_host.group(1)} <redacted>"
    match = _SENSITIVE_ARGUMENT_RE.search(normalized)
    if match is None:
        if suspicious:
            return "<redacted> (control-decorated line)"
        return normalized
    return f"{normalized[: match.end()]} <redacted>"


def redact_text_block(text: str) -> str:
    """Redact multi-line device text before logging or transcription.

    Removes PEM-style key blocks that span lines, which per-line keyword
    redaction cannot see, then applies :func:`redact_command` per line.
    """

    if not isinstance(text, str):
        return "<invalid text>"
    normalized, suspicious = _normalize_terminal_text(text, allow_line_controls=True)
    if suspicious:
        return "<redacted> (terminal-control output)"
    without_key_blocks = _KEY_BLOCK_RE.sub("<redacted block>", normalized)
    return "\n".join(redact_command(line) for line in without_key_blocks.splitlines())


@dataclass(frozen=True)
class _PromptRule:
    pattern: Pattern[str]
    reply: str
    requires_destructive_approval: bool
    kind: str


_SHORT_YES_NO = r"(?:\[y/n\]|\((?:y/n|y or n)\))"
_LONG_YES_NO = r"(?:\[yes/no\]|\((?:yes/no|yes or no)\))"

_PROMPT_RULES: Final[tuple[_PromptRule, ...]] = (
    _PromptRule(
        re.compile(
            r"(?:are you sure you want to |do you want to |proceed with (?:the )?)"
            r"(?:reload|reboot|restart|shutdown|erase|delete|format|factory[- ]?reset)"
            r"(?:\s+(?:the\s+)?(?:system|device|configuration|file))?\??"
            r"\s*\[confirm\]:?",
            re.IGNORECASE,
        ),
        "\n",
        True,
        "destructive_confirmation",
    ),
    _PromptRule(
        re.compile(
            rf"(?:are you sure you want to |do you want to |proceed with (?:the )?)"
            rf"(?:reload|reboot|restart|shutdown|erase|delete|format|factory[- ]?reset)"
            rf"(?:\s+(?:the\s+)?(?:system|device|configuration|file))?\??"
            rf"\s*{_SHORT_YES_NO}:?",
            re.IGNORECASE,
        ),
        "y",
        True,
        "destructive_confirmation",
    ),
    _PromptRule(
        re.compile(
            rf"(?:are you sure you want to |do you want to |proceed with (?:the )?)"
            rf"(?:reload|reboot|restart|shutdown|erase|delete|format|factory[- ]?reset)"
            rf"(?:\s+(?:the\s+)?(?:system|device|configuration|file))?\??"
            rf"\s*{_LONG_YES_NO}:?",
            re.IGNORECASE,
        ),
        "yes",
        True,
        "destructive_confirmation",
    ),
    _PromptRule(
        re.compile(
            r"(?:are you sure you want to |do you want to |proceed with (?:the )?)"
            r"(?:reload|reboot|restart|shutdown|erase|delete|format|factory[- ]?reset)"
            r"(?:\s+(?:the\s+)?(?:system|device|configuration|file))?\??:?",
            re.IGNORECASE,
        ),
        "yes",
        True,
        "destructive_confirmation",
    ),
    _PromptRule(
        re.compile(
            rf"(?:are you sure(?: you want to (?:continue|proceed))?|"
            rf"do you want to continue|continue)\??\s*{_SHORT_YES_NO}:?",
            re.IGNORECASE,
        ),
        "y",
        True,
        "ambiguous_confirmation",
    ),
    _PromptRule(
        re.compile(
            rf"(?:are you sure(?: you want to (?:continue|proceed))?|"
            rf"do you want to continue|continue)\??\s*{_LONG_YES_NO}:?",
            re.IGNORECASE,
        ),
        "yes",
        True,
        "ambiguous_confirmation",
    ),
    _PromptRule(
        re.compile(
            r"overwrite(?:\s+(?:the\s+)?(?:existing|current|previous))?"
            r"(?:\s+(?:file|configuration))?(?:\s+\[[^\]\r\n]*\])?\??"
            r"\s*\[confirm\]:?",
            re.IGNORECASE,
        ),
        "\n",
        True,
        "overwrite_confirmation",
    ),
    _PromptRule(
        re.compile(
            rf"overwrite(?:\s+(?:the\s+)?(?:existing|current|previous))?"
            rf"(?:\s+(?:file|configuration))?(?:\s+\[[^\]\r\n]*\])?\??"
            rf"\s*{_SHORT_YES_NO}:?",
            re.IGNORECASE,
        ),
        "y",
        True,
        "overwrite_confirmation",
    ),
    _PromptRule(
        re.compile(
            rf"overwrite(?:\s+(?:the\s+)?(?:existing|current|previous))?"
            rf"(?:\s+(?:file|configuration))?(?:\s+\[[^\]\r\n]*\])?\??"
            rf"\s*{_LONG_YES_NO}:?",
            re.IGNORECASE,
        ),
        "yes",
        True,
        "overwrite_confirmation",
    ),
    _PromptRule(
        re.compile(
            r"destination filename(?:\s+\[[^\]\r\n]*\])?\s*\?:?",
            re.IGNORECASE,
        ),
        "\n",
        False,
        "destination_filename",
    ),
    _PromptRule(
        re.compile(r"(?:proceed|continue)\??\s*\[confirm\]:?", re.IGNORECASE),
        "\n",
        False,
        "confirmation",
    ),
    _PromptRule(
        re.compile(r"\[confirm\]:?", re.IGNORECASE),
        "\n",
        False,
        "confirmation",
    ),
)


def _last_nonempty_line_details(output: str) -> tuple[str, bool]:
    if not isinstance(output, str) or not output:
        return "", False
    normalized, suspicious = _normalize_terminal_text(output, allow_line_controls=True)
    for line in reversed(normalized.split("\n")):
        cleaned = line.strip()
        if cleaned:
            return cleaned, suspicious
    return "", suspicious


def detect_follow_up_prompt(output: str) -> FollowUpPrompt | None:
    """Return a recognized prompt only when the final non-empty line matches.

    Matching uses :meth:`re.Pattern.fullmatch`; prompt-like words elsewhere in
    ``output`` are ordinary device output and are ignored.
    """

    final_line, suspicious = _last_nonempty_line_details(output)
    if not final_line or suspicious or len(final_line) > MAX_PROMPT_LINE_CHARS:
        return None
    for rule in _PROMPT_RULES:
        if rule.pattern.fullmatch(final_line):
            return FollowUpPrompt(
                text=final_line,
                reply=rule.reply,
                requires_destructive_approval=rule.requires_destructive_approval,
                kind=rule.kind,
            )
    return None


def _detect_unrecognized_prompt_line(output: str) -> str:
    """Return a suspicious final input prompt that has no approved reply rule."""

    final_line, suspicious = _last_nonempty_line_details(output)
    # Any terminal/control-decorated response makes remote state ambiguous.
    # Return a constant label rather than attacker-controlled normalized text;
    # callers can safely report it and must abort instead of sending a later
    # command into a prompt that an OSC/DCS string concealed.
    if suspicious:
        return _CONTROL_DECORATED_RESPONSE_LABEL
    if not final_line:
        return ""
    if len(final_line) > MAX_PROMPT_LINE_CHARS:
        return _OVERSIZED_RESPONSE_LABEL
    if detect_follow_up_prompt(final_line) is not None:
        return ""
    if (
        final_line.rstrip(":").endswith("?")
        or _PROMPT_CHOICE_END_RE.search(final_line)
        or _PROMPT_INSTRUCTION_RE.search(final_line)
    ):
        return final_line
    return ""


def decide_follow_up(
    output: str,
    command: str,
    vendor: str | None = None,
    *,
    allow_destructive: bool = False,
    follow_up_count: int = 0,
) -> PromptDecision:
    """Decide whether Clidarvi may automatically answer a device prompt.

    Only recognized prompts following a ``CHANGE`` command are answered by
    default.  A destructive command or destructive/ambiguous prompt additionally
    requires ``allow_destructive=True``.  ``READ_ONLY`` and ``UNKNOWN`` commands
    are blocked when they unexpectedly ask for confirmation.

    ``follow_up_count`` is the number of replies already sent for the command.
    Once :data:`MAX_FOLLOW_UPS` is reached, further replies are refused.
    """

    if not isinstance(allow_destructive, bool):
        raise TypeError("allow_destructive must be a bool")
    if isinstance(follow_up_count, bool) or not isinstance(follow_up_count, int):
        raise TypeError("follow_up_count must be an int")
    if follow_up_count < 0:
        raise ValueError("follow_up_count cannot be negative")

    command_class = classify_command(command, vendor)
    prompt = detect_follow_up_prompt(output)
    if prompt is None:
        unrecognized_line = _detect_unrecognized_prompt_line(output)
        if unrecognized_line:
            return PromptDecision(
                action=PromptAction.BLOCKED,
                command_class=command_class,
                prompt=FollowUpPrompt(
                    text=unrecognized_line,
                    reply="",
                    requires_destructive_approval=True,
                    kind="unrecognized_prompt",
                ),
                reason="An unrecognized interactive prompt is never answered automatically.",
            )
        return PromptDecision(
            action=PromptAction.NO_PROMPT,
            command_class=command_class,
            reason="The final output line is not a recognized prompt.",
        )

    if follow_up_count >= MAX_FOLLOW_UPS:
        return PromptDecision(
            action=PromptAction.LIMIT_REACHED,
            command_class=command_class,
            prompt=prompt,
            reason=f"The maximum of {MAX_FOLLOW_UPS} automatic replies was reached.",
        )

    if command_class is CommandClass.UNKNOWN:
        return PromptDecision(
            action=PromptAction.BLOCKED,
            command_class=command_class,
            prompt=prompt,
            reason="Unknown commands are never auto-confirmed.",
        )

    if command_class is CommandClass.READ_ONLY:
        return PromptDecision(
            action=PromptAction.BLOCKED,
            command_class=command_class,
            prompt=prompt,
            reason="A confirmation after a read-only command is unexpected.",
        )

    requires_opt_in = (
        command_class is CommandClass.DESTRUCTIVE or prompt.requires_destructive_approval
    )
    if requires_opt_in and not allow_destructive:
        return PromptDecision(
            action=PromptAction.BLOCKED,
            command_class=command_class,
            prompt=prompt,
            reason="Destructive confirmation requires explicit opt-in.",
        )

    return PromptDecision(
        action=PromptAction.REPLY,
        command_class=command_class,
        prompt=prompt,
        reply=prompt.reply,
        reason="The prompt is recognized and permitted by policy.",
    )


__all__ = [
    "CommandClass",
    "FollowUpPrompt",
    "MAX_FOLLOW_UPS",
    "PromptAction",
    "PromptDecision",
    "classify_command",
    "decide_follow_up",
    "detect_follow_up_prompt",
    "redact_command",
    "redact_text_block",
]
