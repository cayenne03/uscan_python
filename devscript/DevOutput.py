import sys
import inspect


class DevOutput:
    verbose = 0  # Controls verbosity level
    die_on_error = True  # Exit program on error
    ds_yes = False  # Auto-respond "yes" to prompts

    @staticmethod
    def print_warn(msg):
        """Print a warning message."""
        print(f"Warning: {msg}", file=sys.stderr)

    @staticmethod
    def ds_msg(msg):
        """Print a general message."""
        print(f"Message: {msg}")

    @staticmethod
    def ds_verbose(msg):
        """Print verbose output based on verbosity level."""
        if DevOutput.verbose > 0:
            print(f"Verbose: {msg}")

    @staticmethod
    def who_called():
        """Return caller information for debugging."""
        if DevOutput.verbose > 1:
            stack = inspect.stack()  # Get the current stack frames
            if len(stack) > 1:  # Ensure we have enough depth in the stack
                frame = stack[1]  # Get the frame two levels back (caller)
                return f"{frame.filename}:{frame.lineno}"  # Return file and line number
        return ""  # Return empty string if verbosity is not high enough or stack too shallow

    @staticmethod
    def ds_warn(msg):
        """Print a warning."""
        print(f"Warning: {msg}", file=sys.stderr)

    @staticmethod
    def ds_debug(msg):
        """Print debug output if verbosity level is high enough."""
        if DevOutput.verbose > 1:
            print(f"Debug: {msg}", file=sys.stderr)

    @staticmethod
    def ds_extra_debug(msg):
        """Print extra debug output if verbosity level is greater than 2."""
        if DevOutput.verbose > 2:
            print(f"Extra Debug: {msg}", file=sys.stderr)

    @staticmethod
    def ds_error(msg):
        """Print an error message and exit."""
        print(f"Error: {msg}", file=sys.stderr)
        if DevOutput.die_on_error:
            sys.exit(1)

    @staticmethod
    def ds_prompt(prompt):
        """Prompt the user for input, auto-respond 'yes' if ds_yes is set."""
        if DevOutput.ds_yes:
            return 'yes'
        else:
            return input(prompt)
