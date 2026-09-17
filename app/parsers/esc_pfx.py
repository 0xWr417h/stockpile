import logging

from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship
from app.utility.base_parser import BaseParser


class Parser(BaseParser):
    """
    Emit one source-only fact per non-empty output line.

    Used by the per-ESC request abilities to capture the path of a written .pfx
    into a fact (esc.cert.pfx) that the auth ability then consumes. The request
    abilities echo the pfx path only if the file was actually created, so a
    failed request produces no fact and the auth branch simply does not fire.
    """

    def __init__(self, parser_info):
        super().__init__(parser_info)
        self.mappers = parser_info['mappers']
        self.log = logging.getLogger('Parser')

    def parse(self, blob):
        relationships = []
        if not isinstance(blob, str):
            return relationships
        for line in [ln.strip() for ln in blob.splitlines() if ln.strip()]:
            # Only accept a line that is actually a .pfx path. This makes the
            # parser robust even if certipy banner/log lines leak onto stdout,
            # so a stray line can never be captured as the cert path.
            if not line.endswith('.pfx'):
                continue
            for mp in self.mappers:
                relationships.append(Relationship(source=Fact(mp.source, line)))
        return relationships
