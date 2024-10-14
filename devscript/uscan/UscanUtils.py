import re
import UscanOutput

class UscanUtils:
    @staticmethod
    def fix_href(href):
        """
        Fixes an href string by removing newline characters and trimming whitespaces.
        Equivalent to Perl's fix_href subroutine.
        """
        href = href.replace("\n", "")  # Remove newline
        href = href.strip()  # Remove leading/trailing whitespace
        return href


    @staticmethod
    def recursive_regex_dir(line, base, dirversionmangle, watchfile, lineptr, download_version):
        """
        Processes directories recursively based on regex patterns.
        Equivalent to Perl's recursive_regex_dir subroutine.
        """
        match = re.match(r'^(\w+://[^/]+)/(.*)$', base)
        site = match.group(1) if match else ''
        dirs = re.split(r'(/)', match.group(2)) if match and match.group(2) else []
        dir_path = '/'

        for dirpattern in dirs:
            if re.search(r'\(.*\)', dirpattern):
                UscanOutput.uscan_verbose(f"dir=>{dir_path}  dirpattern=>{dirpattern}")
                newest_dir = UscanUtils.newest_dir(line, site, dir_path, dirpattern, dirversionmangle, watchfile,
                                                   lineptr, download_version)
                UscanOutput.uscan_verbose(f"newest_dir => '{newest_dir}'")
                if newest_dir != '':
                    dir_path += newest_dir
                else:
                    UscanOutput.uscan_debug("No $newest_dir")
                    return ''
            else:
                dir_path += dirpattern

        return site + dir_path

    @staticmethod
    def newest_dir(line, site, dir_path, pattern, dirversionmangle, watchfile, lineptr, download_version):
        """
        Finds the newest directory by checking site and directory patterns.
        Equivalent to Perl's newest_dir subroutine.
        """
        UscanOutput.uscan_verbose(f"Requesting URL:\n   {site}{dir_path}")

        if re.match(r'^https?://', site):
            import UscanHttp  # Dynamically importing HTTP module equivalent
            newdir = UscanHttp.http_newdir(line, site, dir_path, pattern, dirversionmangle, watchfile, lineptr,
                                           download_version)
        elif re.match(r'^ftp://', site):
            import UscanFtp  # Dynamically importing FTP module equivalent
            newdir = UscanFtp.ftp_newdir(line, site, dir_path, pattern, dirversionmangle, watchfile, lineptr,
                                         download_version)
        else:
            UscanOutput.uscan_warn("Neither HTTP nor FTP site, impossible case for newdir().")
            newdir = ''

        return newdir

    @staticmethod
    def get_compression(compression):
        """
        Normalizes compression methods to canonical names.
        Equivalent to Perl's get_compression subroutine.
        """
        opt2comp = {
            'gz': 'gzip',
            'gzip': 'gzip',
            'bz2': 'bzip2',
            'bzip2': 'bzip2',
            'lzma': 'lzma',
            'xz': 'xz',
            'zip': 'zip',
            'zst': 'zst',
            'zstd': 'zst'
        }

        if compression in opt2comp:
            return opt2comp[compression]
        else:
            UscanOutput.uscan_die(f"Invalid compression: {compression} given.")

    @staticmethod
    def get_suffix(compression):
        """
        Normalizes compression suffixes.
        Equivalent to Perl's get_suffix subroutine.
        """
        opt2suffix = {
            'gz': 'gz',
            'gzip': 'gz',
            'bz2': 'bz2',
            'bzip2': 'bz2',
            'lzma': 'lzma',
            'xz': 'xz',
            'zip': 'zip',
            'zst': 'zst',
            'zstd': 'zst'
        }

        if compression in opt2suffix:
            return opt2suffix[compression]
        elif compression == 'default':
            return 'xz'
        else:
            UscanOutput.uscan_die(f"Invalid suffix: {compression} given.")

    @staticmethod
    def get_priority(href):
        """
        Determines the priority based on the file extension.
        Equivalent to Perl's get_priority subroutine.
        """
        priority = 0
        if re.search(r'\.tar\.gz', href, re.IGNORECASE):
            priority = 1
        elif re.search(r'\.tar\.bz2', href, re.IGNORECASE):
            priority = 2
        elif re.search(r'\.tar\.lzma', href, re.IGNORECASE):
            priority = 3
        elif re.search(r'\.tar\.xz', href, re.IGNORECASE):
            priority = 4
        return priority

    @staticmethod
    def quoted_regex_parse(pattern):
        """
        Parses quoted regular expressions like s/old/new/flags in a safe way.
        Equivalent to Perl's quoted_regex_parse.
        """
        closers = {'{': '}', '[': ']', '(': ')', '<': '>'}
        match = re.match(r'^(s|tr|y)(.)(.*)$', pattern)
        if not match:
            return False, '', '', ''

        sep, rest = match.group(2), match.group(3) or ''
        closer = closers.get(sep, sep)

        parsed_ok = True
        regexp, replacement, flags = '', '', ''
        open_brackets = 1
        last_was_escape = False
        in_replacement = False

        for char in rest:
            if char == sep and not last_was_escape:
                open_brackets += 1
                if open_brackets == 1:
                    if in_replacement:
                        UscanOutput.uscan_warn(f'Extra "{sep}" after end of replacement.')
                        parsed_ok = False
                        break
                    in_replacement = True
                else:
                    if open_brackets > 1:
                        if in_replacement:
                            replacement += char
                        else:
                            regexp += char
            elif char == closer and not last_was_escape:
                open_brackets -= 1
                if open_brackets > 0:
                    if in_replacement:
                        replacement += char
                    else:
                        regexp += char
                elif open_brackets < 0:
                    UscanOutput.uscan_warn(f'Extra "{closer}" after end of replacement.')
                    parsed_ok = False
                    break
            else:
                if in_replacement:
                    if open_brackets:
                        replacement += char
                    else:
                        flags += char
                else:
                    if open_brackets:
                        regexp += char
                    elif not char.isspace():
                        UscanOutput.uscan_warn(
                            'Non-whitespace between <...> and <...> (or similar).'
                        )
                        parsed_ok = False
                        break

            last_was_escape = (char == '\\' and not last_was_escape)

        if not (in_replacement and open_brackets == 0):
            UscanOutput.uscan_warn("Empty replacement string.")
            parsed_ok = False

        return parsed_ok, regexp, replacement, flags

    @staticmethod
    def safe_replace(input_str, pat):
        """
        Safely performs regex-based replacements with specific patterns.
        Equivalent to Perl's safe_replace.
        """
        UscanOutput.uscan_debug(f'safe_replace input="{input_str}"')
        pat = pat.strip()

        match = re.match(r'^(s|tr|y)(.)', pat)
        if not match:
            return False

        op, sep = match.group(1), match.group(2)
        esc = re.escape(sep)

        parsed_ok, regexp, replacement, flags = UscanUtils.quoted_regex_parse(pat) if sep in "{[<(" else (
        False, '', '', '')

        if not parsed_ok:
            UscanOutput.uscan_warn(f"Stop mangling: rule=\"{pat}\"\nMangling rule with <...>, (...), {{...}} failed.")
            return False

        UscanOutput.uscan_debug(f'safe_replace with regexp="{regexp}", replacement="{replacement}", flags="{flags}"')

        if op in ('tr', 'y'):
            safeflags = re.sub(r'[^cds]', '', flags)
            if safeflags != flags:
                UscanOutput.uscan_warn(f"Stop mangling: rule=\"{pat}\"\nFlags must consist of \"cds\" only.")
                return False

            regexp = re.sub(r'\\(.)', r'\1', regexp)
            replacement = re.sub(r'\\(.)', r'\1', replacement)

            regexp = ''.join([f'\\x{ord(c):02x}' for c in regexp if c != '-'])
            replacement = ''.join([f'\\x{ord(c):02x}' for c in replacement if c != '-'])

            try:
                input_str = re.sub(regexp, replacement, input_str)
                return True
            except re.error:
                UscanOutput.uscan_warn(
                    f"Stop mangling: rule=\"{pat}\"\nMangling \"tr\" or \"y\" rule execution failed.")
                return False
        else:
            safeflags = re.sub(r'[^gix]', '', flags)
            if safeflags != flags:
                UscanOutput.uscan_warn(f"Stop mangling: rule=\"{pat}\"\nFlags must consist of \"gix\" only.")
                return False

            global_flag = 'g' in flags
            replacement = re.sub(r'(\\)([^\w])', r'\2', replacement)
            input_str = re.sub(regexp, replacement, input_str, count=0 if global_flag else 1)

            return True

    @staticmethod
    def mangle(watchfile, lineptr, name, rulesptr, verptr):
        """
        Mangles version strings based on given patterns.
        Equivalent to Perl's mangle.
        """
        for pat in rulesptr:
            if not UscanUtils.safe_replace(verptr, pat):
                UscanOutput.uscan_warn(
                    f"In {watchfile}, potentially unsafe or malformed {name} pattern:\n  '{pat}' found. Skipping watchline\n  {lineptr}")
                return True
            UscanOutput.uscan_debug(f"After {name} {verptr}")
        return False