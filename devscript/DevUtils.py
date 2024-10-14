import subprocess
import sys


class DevUtils:
    @staticmethod
    def ds_debug(msg):
        """Log debug messages."""
        print(f"Debug: {msg}", file=sys.stderr)

    @staticmethod
    def ds_die(msg):
        """Log error and terminate the program."""
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(1)

    @staticmethod
    def ds_exec_no_fail(*args):
        """
        Executes a system command without failing, suppresses output.
        Returns the exit code of the command.
        """
        # Log the command being executed
        DevUtils.ds_debug(f"Execute: {' '.join(args)}...")

        # Execute the command and suppress the output
        result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Return the exit code
        return result.returncode

    @staticmethod
    def ds_exec(*args):
        """
        Executes a system command, terminates on failure.
        """
        # Log the command being executed
        DevUtils.ds_debug(f"Execute: {' '.join(args)}...")

        # Execute the command
        result = subprocess.run(args)

        # Check the return code and exit if non-zero
        if result.returncode != 0:
            DevUtils.ds_die(f"Command failed ({' '.join(args)})")