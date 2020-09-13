import math
import os
import re
import textwrap
from decimal import Decimal
from typing import Any, Sequence, Union, Iterator, Optional, List, Callable


def force_bytes(s: Union[str, bytes]) -> bytes:
    if isinstance(s, bytes):
        return s
    return s.encode()


def uniquify(seq: Sequence[Any]) -> Iterator[Any]:
    seen = set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            yield x


def indent(text: str, n: int = 4) -> str:
    return textwrap.indent(text, ' ' * n)


def parse_size(str_size: Optional[str]) -> Optional[int]:
    """
    Transforms "1K", "1k" or "1 kB"-like strings to actual integers.
    Returns None if input is None.
    """
    if str_size is None:
        return None
    str_size = str_size.lower().strip().rstrip('ib')
    for l, m in (('k', 1 << 10), ('m', 1 << 20), ('g', 1 << 30)):
        if str_size.endswith(l):
            return int(str_size.rstrip(l)) * m
    return int(str_size)


def parse_float(str_float: Optional[str]) -> Optional[float]:
    if str_float is None:
        return None
    return float(str_float)


def tabulate(
    rows: List[List[str]],
    headers: Optional[List[str]] = None,
    margin: int = 1,
    align: Optional[str] = None,
) -> Iterator[str]:
    ncols = len(rows[0])
    lengths = [-math.inf] * ncols
    if headers:
        # don't side-effect modify rows
        rows = [headers] + rows
    for row in rows:
        lengths = [max(length, len(col)) for length, col in zip(lengths, row)]
    lengths = [length + margin for length in lengths]
    if align is None:
        align = '<' * ncols
    fmt = "".join("{:%s{s%d}}%s" % (a, i, " | " if i < ncols - 1 else "")
                  for i, a in enumerate(align))
    for row in rows:
        yield fmt.format(*row, **{f's{i}': l for i, l in enumerate(lengths)})


def which(binary: str) -> str:
    search_prefixes = ['/usr', '/lib', '/bin']
    path = [*os.environ.get('PATH', '').split(os.pathsep),
            '/usr/bin',
            '/usr/local/bin'
            '/bin']
    if os.path.dirname(binary) and os.access(binary, os.X_OK):
        return binary
    for part in path:
        # Ignore matches that are not inside standard directories
        if not any(part.startswith(prefix) for prefix in search_prefixes):
            continue
        p = os.path.join(part, binary)
        if os.access(p, os.X_OK):
            return p
    return binary


class cached_classmethod:
    """
    Memoize a class method result.

    class Foo:
        @cached_classmethod
        def heavy_stuff(cls):
            return 42
    """
    def __init__(self, func: Callable, name: str = None):
        self.func = func
        self.__doc__ = getattr(func, '__doc__')
        self.name = name or func.__name__

    def __get__(self, instance, cls=None):
        if cls is None:  # noqa
            return self
        res = self.func(cls)
        setattr(cls, self.name, res)
        return res


class AcceptHeader:
    class AcceptableType:
        RE_TYPE = r"a-zA-Z0-9!#$%^&_\*\-\+\{\}\|'.`~"
        RE_MIME_TYPE = re.compile(rf"^([{RE_TYPE}]+)(/[{RE_TYPE}]+)?$")
        RE_Q = re.compile(r'(?:^|;)\s*q=([0-9.-]+)(?:$|;)')

        def __init__(self, raw_mime_type):
            bits = raw_mime_type.split(';', 1)
            mime_type = bits[0]
            if not self.RE_MIME_TYPE.match(mime_type):
                raise ValueError('"%s" is not a valid mime type' % mime_type)
            tail = ''
            if len(bits) > 1:
                tail = bits[1]
            self.mime_type = mime_type
            self.weight = self.get_weight(tail)
            self.pattern = self.get_pattern(mime_type)

        @classmethod
        def get_weight(cls, tail):
            match = cls.RE_Q.search(tail)
            try:
                return Decimal(match.group(1))
            except (AttributeError, ValueError):
                return Decimal(1)

        @staticmethod
        def get_pattern(mime_type):
            pat = mime_type.replace('*', '[a-zA-Z0-9_.$#!%^*-]+')
            return re.compile(f'^{pat}$')

        def matches(self, mime_type):
            return self.pattern.match(mime_type)

        def __repr__(self):
            return f"<AcceptableType {self.mime_type} = {self.weight}>"

    @classmethod
    def parse_header(cls, header):
        mime_types = []
        for raw_mime_type in header.split(','):
            try:
                mime_types.append(cls.AcceptableType(raw_mime_type.strip()))
            except ValueError:
                pass
        return sorted(mime_types, key=lambda x: x.weight, reverse=True)

    @classmethod
    def get_best_accepted_types(cls, header, available):
        available = list(available)
        for acceptable_type in cls.parse_header(header):
            for available_type in available[:]:
                if acceptable_type.matches(available_type):
                    yield available_type
                    available.remove(available_type)
                    if not available:
                        return
