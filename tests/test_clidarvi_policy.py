# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

import unittest

from clidarvi_policy import (
    MAX_FOLLOW_UPS,
    CommandClass,
    PromptAction,
    classify_command,
    decide_follow_up,
    detect_follow_up_prompt,
    redact_command,
    redact_text_block,
)


class CommandClassificationTests(unittest.TestCase):
    def test_vendor_read_only_commands(self):
        cases = [
            ("show version", "Cisco Switch"),
            ("SH ip interface brief", "cisco_ios"),
            ("do show running-config", "cisco_ios"),
            ("get system status", "Fortinet"),
            ("get system status", "FortiOS"),
            ("diagnose sys session list", "fortinet"),
            ("display interfaces brief", "Aruba"),
            ("show system info", "paloalto_panos"),
        ]
        for command, vendor in cases:
            with self.subTest(command=command, vendor=vendor):
                self.assertIs(classify_command(command, vendor), CommandClass.READ_ONLY)

    def test_unknown_vendor_and_active_probes_fail_closed(self):
        commands = ["show clock", "display version", "ping 192.0.2.10", "traceroute example.net"]
        for command in commands:
            with self.subTest(command=command):
                self.assertIs(classify_command(command), CommandClass.UNKNOWN)
        for command, vendor in (
            ("ping 192.0.2.10", "cisco_ios"),
            ("execute ping 192.0.2.10", "fortinet"),
            ("traceroute example.net", "aruba_os"),
            ("traceroute host example.net", "paloalto_panos"),
        ):
            with self.subTest(command=command, vendor=vendor):
                self.assertIs(classify_command(command, vendor), CommandClass.UNKNOWN)

    def test_vendor_rules_do_not_make_every_operational_verb_globally_safe(self):
        self.assertIs(classify_command("get system status", "cisco_ios"), CommandClass.UNKNOWN)
        self.assertIs(
            classify_command("execute ping 192.0.2.10", "generic"),
            CommandClass.UNKNOWN,
        )
        self.assertIs(
            classify_command("diagnose debug enable", "fortinet"),
            CommandClass.UNKNOWN,
        )

    def test_configuration_commands_are_changes(self):
        cases = [
            ("configure terminal", "Cisco Switch"),
            ("interface GigabitEthernet1/0/1", "cisco_ios"),
            ("banner motd #Authorized users only#", "cisco_ios"),
            ("config system interface", "Fortinet"),
            ("set alias edge-uplink", "fortinet"),
            ("vlan 100", "Aruba"),
            ("set deviceconfig system hostname fw-01", "Palo Alto"),
            ("commit", "paloalto_panos"),
            ("copy running-config startup-config", "cisco_ios"),
        ]
        for command, vendor in cases:
            with self.subTest(command=command, vendor=vendor):
                self.assertIs(classify_command(command, vendor), CommandClass.CHANGE)

    def test_destructive_commands_take_precedence(self):
        cases = [
            ("reload", "Cisco Switch"),
            ("reload in 5", "cisco_ios"),
            ("delete flash:old-image.bin", "cisco_ios"),
            ("erase startup-config", "cisco_ios"),
            ("write erase", "cisco_ios"),
            ("execute reboot", "Fortinet"),
            ("execute factoryreset", "fortinet"),
            ("boot system primary", "Aruba"),
            ("request restart system", "Palo Alto"),
            ("request system private-data-reset", "paloalto_panos"),
        ]
        for command, vendor in cases:
            with self.subTest(command=command, vendor=vendor):
                self.assertIs(classify_command(command, vendor), CommandClass.DESTRUCTIVE)

    def test_full_configuration_replacement_and_wipe_commands_are_destructive(self):
        cases = [
            ("configure replace tftp://192.0.2.9/empty.cfg force", "cisco_ios"),
            ("configure replace flash:backup.cfg", "Cisco Switch"),
            ("config replace flash:backup.cfg", "cisco_ios"),
            ("reset system", "Cisco WLC"),
            ("reset system", "cisco_wlc"),
            ("clear config", "cisco_wlc"),
            ("execute factoryreset2", "Fortinet"),
        ]
        for command, vendor in cases:
            with self.subTest(command=command, vendor=vendor):
                self.assertIs(classify_command(command, vendor), CommandClass.DESTRUCTIVE)

    def test_empty_multiline_and_unrecognized_commands_are_unknown(self):
        self.assertIs(classify_command(""), CommandClass.UNKNOWN)
        self.assertIs(classify_command("monitor capture point start"), CommandClass.UNKNOWN)
        self.assertIs(
            classify_command("show version\nreload", "cisco_ios"),
            CommandClass.UNKNOWN,
        )

    def test_every_unicode_control_category_fails_closed(self):
        # Cc (tab), Cf (word joiner), and Cs (lone surrogate) cover the full
        # Unicode categories rather than a hand-maintained code-point list.
        for control in ("\t", "\u2060", "\ud800"):
            with self.subTest(control=ascii(control)):
                self.assertIs(
                    classify_command(f"show{control}version", "cisco_ios"),
                    CommandClass.UNKNOWN,
                )
                self.assertIs(
                    classify_command(f"show version{control}", "cisco_ios"),
                    CommandClass.UNKNOWN,
                )

    def test_chaining_is_not_allowlisted_and_preserves_destructive_warning(self):
        self.assertIs(
            classify_command("show clock; show version", "cisco_ios"),
            CommandClass.UNKNOWN,
        )
        self.assertIs(
            classify_command("show clock; reload", "cisco_ios"),
            CommandClass.DESTRUCTIVE,
        )

    def test_all_shell_like_metacharacters_prevent_read_only_classification(self):
        commands = (
            "show version | include uptime",
            "show version & reload",
            "show version > flash:version.txt",
            "show version < input.txt",
            "show `reload`",
            "show $(reload)",
            "show ${IFS}version",
            "show version ! reload",
            "show version (reload)",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNot(classify_command(command, "cisco_ios"), CommandClass.READ_ONLY)

        self.assertIs(
            classify_command(
                "show run | redirect flash:run.cfg; reload",
                "cisco_ios",
            ),
            CommandClass.DESTRUCTIVE,
        )

    def test_cisco_do_prefix_and_output_redirection_cannot_bypass_review(self):
        for command in ("do reload", "do write erase"):
            with self.subTest(command=command):
                self.assertIs(
                    classify_command(command, "cisco_ios"),
                    CommandClass.DESTRUCTIVE,
                )
        for command in ("show run | redirect flash:run.cfg", "sh run | append bootflash:all.cfg"):
            with self.subTest(command=command):
                self.assertIs(
                    classify_command(command, "cisco_ios"),
                    CommandClass.CHANGE,
                )


class PromptDetectionTests(unittest.TestCase):
    def test_exact_final_line_prompts_are_detected(self):
        cases = [
            ("Destination filename [startup-config]?", "\n", False),
            ("[confirm]", "\n", False),
            ("Proceed with reload? [confirm]", "\n", True),
            ("Do you want to continue? (y/n)", "y", True),
            ("Are you sure you want to restart the system? [yes/no]", "yes", True),
            ("Overwrite existing file? [confirm]", "\n", True),
        ]
        for output, reply, destructive in cases:
            with self.subTest(output=output):
                prompt = detect_follow_up_prompt(f"ordinary output\r\n{output}\r\n")
                self.assertIsNotNone(prompt)
                self.assertEqual(prompt.text, output)
                self.assertEqual(prompt.reply, reply)
                self.assertIs(prompt.requires_destructive_approval, destructive)

    def test_prompt_words_in_banner_or_non_exact_lines_do_not_match(self):
        outputs = [
            "Banner: maintenance asks 'are you sure?' but no input is needed.",
            "The word overwrite appears in this status message.",
            "Are you sure this banner is readable? [y/n]",
            "Destination filename [startup-config]? extra text",
            "Proceed with reload? [confirm] no",
        ]
        for output in outputs:
            with self.subTest(output=output):
                self.assertIsNone(detect_follow_up_prompt(output))

    def test_only_the_final_nonempty_line_can_be_a_prompt(self):
        output = "Are you sure? [y/n]\nThis is only banner documentation.\nrouter#"
        self.assertIsNone(detect_follow_up_prompt(output))

    def test_terminal_control_decorated_prompts_are_never_auto_recognized(self):
        cases = (
            "\x1b[31m[confirm]\x1b[0m",
            "\x1b]0;title\x07[confirm]",
            "[con\x08firm]",
            "[con\u202efirm]",
        )
        for output in cases:
            with self.subTest(output=output):
                self.assertIsNone(detect_follow_up_prompt(output))
                decision = decide_follow_up(output, "write memory", "cisco_ios")
                self.assertIs(decision.action, PromptAction.BLOCKED)
                self.assertEqual(decision.prompt.kind, "unrecognized_prompt")

        ordinary_prompt = decide_follow_up(
            "Copy complete.\n\x1b[32mrouter#\x1b[0m",
            "write memory",
            "cisco_ios",
        )
        self.assertIs(ordinary_prompt.action, PromptAction.BLOCKED)
        self.assertEqual(ordinary_prompt.prompt.text, "<terminal-control response>")

    def test_control_anywhere_in_response_blocks_an_otherwise_exact_prompt(self):
        for control in ("\x1b[31m", "\u2060", "\ud800"):
            with self.subTest(control=ascii(control)):
                decision = decide_follow_up(
                    f"ordinary{control} output\n[confirm]",
                    "write memory",
                    "cisco_ios",
                )
                self.assertIs(decision.action, PromptAction.BLOCKED)
                self.assertIsNone(decision.reply)

    def test_unterminated_terminal_strings_cannot_hide_the_entire_prompt(self):
        responses = (
            "\x1b]0;hidden\n[confirm]",
            "\x1bPpayload\n[confirm]",
            "\x9dhidden\n[confirm]",
            "\x90payload\n[confirm]",
        )
        for response in responses:
            with self.subTest(response=ascii(response)):
                decision = decide_follow_up(
                    response,
                    "write memory",
                    "cisco_ios",
                    allow_destructive=True,
                )
                self.assertIs(decision.action, PromptAction.BLOCKED)
                self.assertIsNone(decision.reply)
                self.assertEqual(
                    decision.prompt.text,
                    "<terminal-control response>",
                )


class CommandRedactionTests(unittest.TestCase):
    def test_sensitive_arguments_are_removed(self):
        cases = {
            "username admin secret swordfish": "username admin secret <redacted>",
            "snmp-server community public ro": "snmp-server community <redacted>",
            "set shared pre-shared-key abc123": "set shared pre-shared-key <redacted>",
            "set api token=abcd": "set api token <redacted>",
            "radius-server key radius-secret": "radius-server key <redacted>",  # pragma: allowlist secret
            "set psksecret SuperSecret123": "set psksecret <redacted>",  # pragma: allowlist secret
            "set passwd another-secret": "set passwd <redacted>",  # pragma: allowlist secret
            "set auth-pwd AuthSecret123": "set auth-pwd <redacted>",  # pragma: allowlist secret
            "set priv-pwd ENC PrivSecret456": "set priv-pwd <redacted>",  # pragma: allowlist secret
            "set auth-pass ArubaSecret123": "set auth-pass <redacted>",  # pragma: allowlist secret
            "set priv-password ENC ArubaPriv456": "set priv-password <redacted>",  # pragma: allowlist secret
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(redact_command(command), expected)

    def test_non_sensitive_command_is_unchanged(self):
        self.assertEqual(redact_command("show version"), "show version")

    def test_uri_userinfo_passwords_are_redacted_in_commands_and_output(self):
        schemes = ("https", "http", "ftp", "ftps", "scp", "sftp", "ssh", "git+ssh")
        for scheme in schemes:
            secret = f"{scheme}-Password123"  # pragma: allowlist secret
            uri = f"{scheme}://operator:{secret}@router.example.net/config"
            with self.subTest(scheme=scheme):
                command = redact_command(f"copy {uri} running-config")
                output = redact_text_block(f"Fetching {uri}\nComplete")
                self.assertNotIn(secret, command)
                self.assertNotIn(secret, output)
                self.assertIn(f"{scheme}://operator:<redacted>@", command)
                self.assertIn(f"{scheme}://operator:<redacted>@", output)

        empty_user_secret = "EmptyUserPassword123"  # pragma: allowlist secret
        empty_user_uri = f"custom+ssh://:{empty_user_secret}@router.example.net/config"
        redacted = redact_command(f"copy {empty_user_uri} running-config")
        self.assertNotIn(empty_user_secret, redacted)
        self.assertIn("custom+ssh://:<redacted>@", redacted)

        prefixed_secret = "PrefixedPassword123"  # pragma: allowlist secret
        prefixed_uri = f"value_https://operator:{prefixed_secret}@router.example.net/path"
        prefixed_output = redact_text_block(prefixed_uri)
        self.assertNotIn(prefixed_secret, prefixed_output)
        self.assertIn("https://operator:<redacted>@", prefixed_output)

    def test_all_unicode_control_categories_redact_the_entire_text_block(self):
        for control in ("\t", "\u2060", "\ud800"):
            with self.subTest(control=ascii(control)):
                self.assertEqual(
                    redact_text_block(f"safe{control}spoofed"),
                    "<redacted> (terminal-control output)",
                )

    def test_terminal_controls_cannot_split_secrets_or_spoof_transcripts(self):
        samples = (
            "username admin pass\x1b[31mword\x1b[0m swordfish",
            "username admin pass\x08word swordfish",
            "username admin pass\u202eword swordfish",
            "username admin pass\u200bword swordfish",
            "\x1b]0;forged title\x07username admin secret swordfish",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                redacted = redact_text_block(sample)
                self.assertNotIn("swordfish", redacted)
                self.assertNotIn("\x1b", redacted)
                self.assertIn("<redacted>", redacted)

    def test_positional_vendor_secrets_are_redacted(self):
        cases = [
            (
                "snmp-server user netadmin NETGROUP v3 auth sha AuthPass123 "  # pragma: allowlist secret
                "priv aes 128 PrivPass456",
                ("AuthPass123", "PrivPass456"),
            ),
            ("config radius auth add 1 192.0.2.1 1812 ascii RadSecret99", ("RadSecret99",)),
            ("config tacacs auth add 1 198.51.100.2 49 ascii TacSecret99", ("TacSecret99",)),
            ("config mgmtuser add operator SuperSecret99 read-write", ("SuperSecret99",)),
            (
                "config snmp v3user create v3op rw hmacsha aescfb128 "  # pragma: allowlist secret
                "AuthKey123 PrivKey456",
                ("AuthKey123", "PrivKey456"),
            ),
            ("mgmt-user admin root Secret123", ("Secret123",)),
            ("set mgt-config users admin phash q1w2e3r4", ("q1w2e3r4",)),
        ]
        for command, secrets in cases:
            with self.subTest(command=command):
                redacted = redact_command(command)
                self.assertIn("<redacted>", redacted)
                for secret in secrets:
                    self.assertNotIn(secret, redacted)

    def test_multiline_key_blocks_are_redacted_from_output(self):
        block = (
            'set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\n'  # pragma: allowlist secret
            "MIIabcDEF123\nGHI456\n"
            '-----END ENCRYPTED PRIVATE KEY-----"'
        )
        redacted = redact_text_block(block)
        self.assertNotIn("MIIabcDEF123", redacted)
        self.assertNotIn("BEGIN", redacted)

        unterminated = (
            "show output\n-----BEGIN RSA PRIVATE KEY-----\nAAAA1234"  # pragma: allowlist secret
        )
        redacted_unterminated = redact_text_block(unterminated)
        self.assertIn("show output", redacted_unterminated)
        self.assertNotIn("AAAA1234", redacted_unterminated)

        per_line = redact_text_block("hostname sw-1\nusername admin secret swordfish")
        self.assertNotIn("swordfish", per_line)
        self.assertIn("hostname sw-1", per_line)

        snmp_output = redact_text_block(
            "set auth-pwd AuthSecret123\nset priv-pwd ENC PrivSecret456"  # pragma: allowlist secret
        )
        self.assertNotIn("AuthSecret123", snmp_output)
        self.assertNotIn("PrivSecret456", snmp_output)

    def test_snmp_server_host_positional_community_is_redacted(self):
        cases = [
            ("snmp-server host 192.0.2.10 version 2c MyS3cretComm", "MyS3cretComm"),
            ("snmp-server host 192.0.2.11 traps version 2c TrapComm", "TrapComm"),
            ("snmp-server host 192.0.2.12 SecretV1Comm", "SecretV1Comm"),
            ("snmp-server host 192.0.2.13 informs version 3 priv snmpuser", "snmpuser"),
            ("snmp-server host 192.0.2.14 vrf mgmt traps version 2c VrfComm", "VrfComm"),
        ]
        for command, secret in cases:
            with self.subTest(command=command):
                redacted = redact_command(command)
                self.assertNotIn(secret, redacted)
                self.assertIn("<redacted>", redacted)
        # The same leak on a device-output line (e.g. a running-config dump).
        dumped = redact_text_block("snmp-server host 192.0.2.10 version 2c LeakedFromShowRun")
        self.assertNotIn("LeakedFromShowRun", dumped)
        # A host line with no trailing community has nothing to redact.
        self.assertEqual(
            redact_command("snmp-server host 192.0.2.10"),
            "snmp-server host 192.0.2.10",
        )


class PromptDecisionTests(unittest.TestCase):
    def test_change_command_can_accept_non_destructive_prompt(self):
        decision = decide_follow_up(
            "Destination filename [startup-config]?",
            "copy running-config startup-config",
            "cisco_ios",
        )
        self.assertIs(decision.action, PromptAction.REPLY)
        self.assertIs(decision.command_class, CommandClass.CHANGE)
        self.assertEqual(decision.reply, "\n")
        self.assertTrue(decision.should_reply)

    def test_destructive_command_is_blocked_without_explicit_opt_in(self):
        decision = decide_follow_up("Proceed with reload? [confirm]", "reload", "cisco_ios")
        self.assertIs(decision.action, PromptAction.BLOCKED)
        self.assertIs(decision.command_class, CommandClass.DESTRUCTIVE)
        self.assertIsNone(decision.reply)
        self.assertFalse(decision.should_reply)

    def test_destructive_command_can_be_confirmed_only_with_explicit_opt_in(self):
        decision = decide_follow_up(
            "Proceed with reload? [confirm]",
            "reload",
            "cisco_ios",
            allow_destructive=True,
        )
        self.assertIs(decision.action, PromptAction.REPLY)
        self.assertEqual(decision.reply, "\n")

    def test_destructive_prompt_after_change_is_also_gated(self):
        blocked = decide_follow_up(
            "Overwrite existing file? [confirm]",
            "copy running-config backup-config",
            "cisco_ios",
        )
        allowed = decide_follow_up(
            "Overwrite existing file? [confirm]",
            "copy running-config backup-config",
            "cisco_ios",
            allow_destructive=True,
        )
        self.assertIs(blocked.action, PromptAction.BLOCKED)
        self.assertIs(allowed.action, PromptAction.REPLY)
        self.assertEqual(allowed.reply, "\n")

    def test_unexpected_prompt_is_never_approved_for_read_only_or_unknown(self):
        cases = [
            ("show version", "cisco_ios"),
            ("frobnicate system", "generic"),
        ]
        for command, vendor in cases:
            with self.subTest(command=command, vendor=vendor):
                decision = decide_follow_up(
                    "[confirm]",
                    command,
                    vendor,
                    allow_destructive=True,
                )
                self.assertIs(decision.action, PromptAction.BLOCKED)
                self.assertIsNone(decision.reply)

    def test_no_prompt_is_reported_without_reply(self):
        decision = decide_follow_up("Copy complete.\nrouter#", "write memory", "cisco_ios")
        self.assertIs(decision.action, PromptAction.NO_PROMPT)
        self.assertIsNone(decision.prompt)
        self.assertIsNone(decision.reply)

    def test_unrecognized_interactive_prompt_is_blocked(self):
        prompts = (
            "Select target [primary/secondary]:",
            "How many bits in the modulus [2048]:",
            "Enter remote host:",
            "Enter remote host",
            "File name [config.txt]:",
            "Select destination",
            "Overwrite existing file? [yes]",
            "Proceed [yes]",
            "Continue",
            "Confirm",
            "Proceed",
            "Are you sure",
            "Continue " + ("x" * 129),
            "Enter " + ("x" * 129),
            "[" + ("a" * 129) + "/b]:",
            "(" + ("a" * 65) + "/b):",
            "[" * 100_000,
        )
        for output in prompts:
            with self.subTest(output=output):
                decision = decide_follow_up(
                    output,
                    "write memory",
                    "cisco_ios",
                    allow_destructive=True,
                )

                self.assertIs(decision.action, PromptAction.BLOCKED)
                self.assertIsNotNone(decision.prompt)
                self.assertEqual(decision.prompt.kind, "unrecognized_prompt")
                self.assertIsNone(decision.reply)

    def test_follow_up_replies_are_capped(self):
        # The documented cap is exactly three automatic replies; a silent
        # constant change must fail this pin, not slip through.
        self.assertEqual(MAX_FOLLOW_UPS, 3)
        decision = decide_follow_up(
            "[confirm]",
            "write memory",
            "cisco_ios",
            follow_up_count=MAX_FOLLOW_UPS,
        )
        self.assertIs(decision.action, PromptAction.LIMIT_REACHED)
        self.assertIsNone(decision.reply)

    def test_last_reply_before_cap_is_still_allowed(self):
        decision = decide_follow_up(
            "[confirm]",
            "write memory",
            "cisco_ios",
            follow_up_count=MAX_FOLLOW_UPS - 1,
        )
        self.assertIs(decision.action, PromptAction.REPLY)

    def test_invalid_decision_arguments_are_rejected(self):
        with self.assertRaises(TypeError):
            decide_follow_up("[confirm]", "write memory", allow_destructive="yes")
        with self.assertRaises(TypeError):
            decide_follow_up("[confirm]", "write memory", follow_up_count=True)
        with self.assertRaises(ValueError):
            decide_follow_up("[confirm]", "write memory", follow_up_count=-1)


if __name__ == "__main__":
    unittest.main()
