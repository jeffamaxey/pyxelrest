from typing import Tuple

import requests
import requests.adapters
import os


class LocalFileAdapter(requests.adapters.BaseAdapter):
    """
    Protocol Adapter to allow Requests to GET file:/// URLs

    Example: file:///C:\\path\\to\\open_api_definition.json
    """

    @staticmethod
    def _check_path(method: str, path: str) -> Tuple[int, str]:
        """Return an HTTP status for the given filesystem path."""
        if os.path.isdir(path):
            return 400, "Path Not A File"
        elif not os.path.isfile(path):
            return 404, "File Not Found"
        elif not os.access(path, os.R_OK):
            return 403, "Access Denied"
        else:
            return 200, "OK"

    def send(self, request: requests.Request, *args, **kwargs):
        """Return the file specified by the given request"""
        path = os.path.normcase(os.path.normpath(request.url[8:]))
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        response = requests.Response()
        response.status_code, response.reason = self._check_path(request.method, path)
        if response.status_code == 200:
            try:
                response.raw = open(path, "rb")
            except (OSError, IOError) as err:
                response.status_code = 500
                response.reason = str(err)

        # TODO Get rid of bytes check if it cannot occurs
        if isinstance(path, bytes):
            response.url = path.decode("utf-8")
        else:
            response.url = path

        response.request = request
        response.connection = self

        return response

    def close(self):
        pass
