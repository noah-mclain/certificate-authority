import argparse
import sys
import ca_commands
import ca_config


def main():
    parser = argparse.ArgumentParser(description="Simple Certificate Authority")
    parser.add_argument(
        "--ca-pass", help="Passphrase for the CA private key (if encrypted)"
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Initialize the CA")

    p_issue = sub.add_parser("issue", help="Issue a certificate for a user")
    p_issue.add_argument("username")
    p_issue.add_argument("--email")
    p_issue.add_argument("--days", type=int, default=ca_config.CERT_VALIDITY_DAYS)

    p_revoke = sub.add_parser("revoke")
    p_revoke.add_argument("serial", type=int)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("cert_file")

    sub.add_parser("list")

    p_info = sub.add_parser("info")
    p_info.add_argument("cert_file")

    p_renew = sub.add_parser("renew")
    p_renew.add_argument("serial", type=int)
    p_renew.add_argument("--days", type=int, default=ca_config.CERT_VALIDITY_DAYS)

    p_export = sub.add_parser("export")
    p_export.add_argument("--serial", type=int, required=True)
    p_export.add_argument("--password")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "init": ca_commands.cmd_init,
        "issue": ca_commands.cmd_issue,
        "revoke": ca_commands.cmd_revoke,
        "verify": ca_commands.cmd_verify,
        "list": ca_commands.cmd_list,
        "info": ca_commands.cmd_info,
        "renew": ca_commands.cmd_renew,
        "export": ca_commands.cmd_export,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
