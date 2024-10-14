import requests


class CatchRedirections(requests.Session):
    def __init__(self):
        super().__init__()
        self.redirections = []

    def get(self, url, **kwargs):
        """
        Capture all redirects, starting from the initial URL.
        """
        # Add the starting URL to the redirections list
        self.redirections.append(url)

        # First request to capture the initial redirect
        response = super().get(url, allow_redirects=False, **kwargs)

        # Capture all subsequent redirects manually
        while response.is_redirect:
            next_url = response.headers.get('Location')
            if next_url and next_url not in self.redirections:
                self.redirections.append(next_url)
            response = super().get(next_url, allow_redirects=False, **kwargs)

        return response

    def get_redirections(self):
        """
        Get the list of captured redirections.
        """
        return self.redirections

    def clear_redirections(self):
        """
        Clear the list of redirections.
        """
        self.redirections = []
