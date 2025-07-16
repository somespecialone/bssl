from .base.socket import TLSSocket as _TLSSocket


class TLSSocket(_TLSSocket):
    def __init__(self, *args, **kwargs):
        raise TypeError("TLSSocket class does not define public constructor.")
