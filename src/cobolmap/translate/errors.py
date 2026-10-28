"""Dependency-free translator refusal shared by the lazy facade and compiler."""


class TranslationRefusal(ValueError):
    def __init__(self, code, message, span=None):
        super().__init__(message)
        self.code, self.message, self.span = code, message, span
