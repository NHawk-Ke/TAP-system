import argparse


def get_parser():
    parser = argparse.ArgumentParser(
        description="TAP system that allows you to customize monitor on "
                    "packets on any network interface."
    )
    parser.add_argument(
        "-ls", "--list-interfaces",
        action="store_true",
        help="""
            List all network interfaces from which packets will be captured.
        """
    )
    parser.add_argument(
        "-f", "--output-file",
        type=argparse.FileType('w', encoding='utf-8'),
        default=None,
        help="Redirect output to a file"
    )
    parser.add_argument(
        "-cfg", "--config-file",
        type=open,
        help="Required configuration file to run the system"
    )
    return parser
