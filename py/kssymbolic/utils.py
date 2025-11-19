from logging import exception
from kssymbolic._lowlevel import ffi, lib

class RustObject:
    __dealloc_func__ = None
    _objptr = None
    _shared = False

    def __init__(self) -> None:
        raise TypeError("Cannot instanciate %r objects" % self.__class__.__name__)

    @classmethod
    def _from_objptr(cls, ptr, shared=False):
        rv = object.__new__(cls)
        rv._objptr = ptr
        rv._shared = shared
        return rv

    def _methodcall(self, func, *args):
        return rustcall(func, self._get_objptr(), *args)

    def _get_objptr(self):
        if not self._objptr:
            raise RuntimeError("Object is closed")
        return self._objptr

    def _move(self, target):
        self._shared = True
        ptr = self._get_objptr()
        self._objptr = None
        return ptr

    def __del__(self) -> None:
        if self._objptr is None or self._shared:
            return
        f = self.__class__.__dealloc_func__
        if f is not None:
            rustcall(f, self._objptr)
            self._objptr = None


def rustcall(func, *args):
    """Calls rust method and does some error handling."""
    lib.symbolic_err_clear()
    rv = func(*args)
    err = lib.symbolic_err_get_last_code()
    if not err:
        return rv
    # msg = lib.symbolic_err_get_last_message()
    # cls = exceptions_by_code.get(err, SymbolicError)
    # exc = cls(decode_str(msg, free=True))
    # backtrace = decode_str(lib.symbolic_err_get_backtrace(), free=True)
    # if backtrace:
    #     exc.rust_info = backtrace
    # raise exc
    raise ValueError("rustcall exception")

def decode_str(s, free: bool = False) -> str:
    """Decodes a SymbolicStr"""
    try:
        if s.len == 0:
            return ""
        return ffi.unpack(s.data, s.len).decode("utf-8", "replace")
    finally:
        if free and s.owned:
            lib.symbolic_str_free(ffi.addressof(s))

def encode_path(s) -> bytes:
    """Encodes a path value."""
    if isinstance(s, str):
        s = s.encode("utf-8")
    if 0 in s:
        raise TypeError("Null bytes are not allowed in paths")
    return s
