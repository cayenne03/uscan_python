import sys
from devscript.DevOutput import DevOutput  # Reuse the existing DevOutput class

class UscanOutput:
    # Variables that mirror the Perl version
    dehs = 0  # Equivalent of Perl's $dehs
    dehs_tags = {}  # Equivalent of Perl's %dehs_tags
    dehs_start_output = 0  # Equivalent of Perl's $dehs_start_output
    dehs_end_output = 0  # Equivalent of Perl's $dehs_end_output
    found = 0  # Equivalent of Perl's $found
    progname = "Uscan"  # Just an example; in Perl, this uses the script's name

    _verbose = 0  # Internal tracking for verbosity

    @classmethod
    def set_verbose(cls, level):
        """Set verbosity for both UscanOutput and DevOutput."""
        cls._verbose = level
        DevOutput.verbose = level  # Sync with DevOutput

    @classmethod
    def get_verbose(cls):
        """Return the current verbosity level."""
        return cls._verbose

    @staticmethod
    def print_warn_raw(msg, warning=False):
        """Print warning messages directly (raw output)."""
        if warning or UscanOutput.dehs:
            print(f"{msg}", file=sys.stderr)
        else:
            print(f"{msg}")

    @staticmethod
    def print_warn(msg, warning=False):
        """Print a warning message with a newline."""
        msg = msg.rstrip()  # Equivalent of `chomp` in Perl
        UscanOutput.print_warn_raw(f"{msg}\n", warning)

    @staticmethod
    def uscan_msg_raw(msg):
        """Raw message printing without newline."""
        UscanOutput.print_warn_raw(msg)

    @staticmethod
    def uscan_msg(msg):
        """Print a message with a newline."""
        UscanOutput.print_warn(msg)

    @staticmethod
    def uscan_verbose(msg):
        """Print verbose messages based on verbosity level."""
        DevOutput.ds_verbose(msg)  # Call method from DevOutput

    @staticmethod
    def uscan_debug(msg):
        """Print debug messages based on verbosity level."""
        DevOutput.ds_debug(msg)  # Call method from DevOutput

    @staticmethod
    def uscan_extra_debug(msg):
        """Print extra debug messages based on verbosity level."""
        DevOutput.ds_extra_debug(msg)  # Call method from DevOutput

    @staticmethod
    def dehs_verbose(msg):
        """Add verbose messages to dehs_tags and print."""
        UscanOutput.dehs_tags.setdefault('messages', []).append(f"{msg}\n")
        UscanOutput.uscan_verbose(msg)

    @staticmethod
    def uscan_warn(msg):
        """Print a warning and append to dehs_tags if needed."""
        if UscanOutput.dehs:
            UscanOutput.dehs_tags.setdefault('warnings', []).append(msg)
        UscanOutput.print_warn(f"{UscanOutput.progname} warn: {msg}{DevOutput.who_called()}", True)

    @staticmethod
    def uscan_die(msg):
        """Handle fatal errors and optionally output dehs XML."""
        if UscanOutput.dehs:
            UscanOutput.dehs_tags = {'errors': f"{msg}"}
            UscanOutput.dehs_end_output = 1
            UscanOutput.dehs_output()

        msg = f"{UscanOutput.progname} die: {msg}{DevOutput.who_called()}"
        if DevOutput.die_on_error:
            raise SystemExit(msg)
        else:
            UscanOutput.print_warn(msg, True)

    @staticmethod
    def dehs_output():
        """Generate dehs XML output."""
        if not UscanOutput.dehs:
            return

        if not UscanOutput.dehs_start_output:
            print("<dehs>")
            UscanOutput.dehs_start_output = 1

        # Output dehs tags
        for tag in ['package', 'debian-uversion', 'debian-mangled-uversion',
                    'upstream-version', 'upstream-url', 'decoded-checksum',
                    'status', 'target', 'target-path', 'messages', 'warnings', 'errors']:
            if tag in UscanOutput.dehs_tags:
                tag_value = UscanOutput.dehs_tags[tag]
                if isinstance(tag_value, list):
                    for entry in tag_value:
                        entry = UscanOutput._escape_xml(entry)
                        print(f"<{tag}>{entry}</{tag}>")
                else:
                    tag_value = UscanOutput._escape_xml(tag_value)
                    print(f"<{tag}>{tag_value}</{tag}>")

        # Output components
        if 'component-name' in UscanOutput.dehs_tags:
            for cmp in UscanOutput.dehs_tags['component-name']:
                print(f"<component id=\"{cmp}\">")
                for tag in ['debian-uversion', 'debian-mangled-uversion',
                            'upstream-version', 'upstream-url', 'target', 'target-path']:
                    if f"component-{tag}" in UscanOutput.dehs_tags:
                        v = UscanOutput.dehs_tags[f"component-{tag}"].pop(0)
                        if v:
                            print(f"  <component-{tag}>{v}</component-{tag}>")
                print("</component>")

        if UscanOutput.dehs_end_output:
            print("</dehs>")

        # Clear dehs tags to avoid repetition
        UscanOutput.dehs_tags = {}

    @staticmethod
    def _escape_xml(text):
        """Helper to escape XML characters."""
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")

        return text
