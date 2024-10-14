from packaging.version import Version


class Versort:
    @staticmethod
    def versort(namever_pairs):
        """
        Sorts version numbers without strict checks.
        :param namever_pairs: List of [version, data]
        :return: List sorted by version in descending order.
        """
        return Versort._versort(check=False, getversion=lambda pair: pair[0], namever_pairs=namever_pairs)

    @staticmethod
    def deb_versort(namever_pairs):
        """
        Sorts Debian version numbers, which may include epoch and revision.
        :param namever_pairs: List of [version, data]
        :return: List sorted by version in descending order.
        """
        return Versort._versort(check=True, getversion=lambda pair: pair[0], namever_pairs=namever_pairs)

    @staticmethod
    def upstream_versort(namever_pairs):
        """
        Sorts upstream version numbers.
        :param namever_pairs: List of [version, data]
        :return: List sorted by version in descending order.
        """
        return Versort._versort(check=False, getversion=lambda pair: f"1:{pair[0]}-0", namever_pairs=namever_pairs)

    @staticmethod
    def _versort(check, getversion, namever_pairs):
        """
        Helper function for sorting versions.
        :param check: Boolean, whether to perform strict checking.
        :param getversion: Function to extract version.
        :param namever_pairs: List of [version, data]
        :return: List sorted by version in descending order.
        """
        # Convert versions to Version objects for comparison
        for pair in namever_pairs:
            version_str = getversion(pair)
            try:
                pair.insert(0, Version(version_str))
            except ValueError:
                # If there's an error with the version format, handle it here
                if check:
                    raise ValueError(f"Invalid version: {version_str}")
                else:
                    # For non-strict sorting, use a basic fallback
                    pair.insert(0, Version("0.0.0"))

        # Sort the pairs by the version object (first element) in descending order
        sorted_pairs = sorted(namever_pairs, key=lambda pair: pair[0], reverse=True)

        # Remove the added version object before returning
        for pair in sorted_pairs:
            pair.pop(0)

        return sorted_pairs