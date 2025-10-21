class UserVisibleError(Exception):
    """An exception that should be presented to the user without a traceback."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message
