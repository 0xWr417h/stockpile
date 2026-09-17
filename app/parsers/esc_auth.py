import logging
import re

from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship
from app.utility.base_parser import BaseParser


class Parser(BaseParser):
    """
    Parse UnPAC-the-hash output from either certipy (Linux) or Rubeus (Windows)
    and extract the recovered NT hash. One parser serves both platforms so the
    auth ability emits identical facts regardless of which OS ran it.

    Linux, certipy v5.1.0 (logging, capture with 2>&1):
        Got hash for 'administrator@lab.local': aad3b435...:<nthash>

    Windows, Rubeus v2.2.0 (asktgt /getcredentials):
        ...
          UserName                 :  administrator
          UserRealm                :  DOMAIN.LOCAL
        ...
             NTLM              : 0F27ECA59F6B3B8CCF3AEAC813C44E6A

    Rubeus prints the NT hash uppercase and never prints a combined UPN, so the
    UPN is assembled from UserName + UserRealm. The hash is lowercased so the
    emitted domain.user.ntlm is identical to certipy's, keeping downstream
    stockpile pass-the-hash / DCSync chaining OS-agnostic.

    Emits, for the impersonated principal:
        domain.user.name  --has_hash-->  domain.user.ntlm
        esc.owned.upn
    """

    # Linux / certipy: UPN and NT hash on one line.
    CERTIPY_RE = re.compile(
        r"Got hash for '(?P<upn>[^']+)':\s*[0-9a-fA-F]{32}:(?P<nt>[0-9a-fA-F]{32})"
    )
    # Windows / Rubeus: NT hash on its own line under CredentialInfo.
    RUBEUS_NT_RE = re.compile(r"NTLM\s*:\s*(?P<nt>[0-9a-fA-F]{32})")
    # Windows / Rubeus: principal components, printed separately earlier.
    RUBEUS_USER_RE = re.compile(r"UserName\s*:\s*(?P<user>\S+)")
    RUBEUS_REALM_RE = re.compile(r"UserRealm\s*:\s*(?P<realm>\S+)")

    def __init__(self, parser_info):
        super().__init__(parser_info)
        self.mappers = parser_info['mappers']
        self.used_facts = parser_info['used_facts']
        self.log = logging.getLogger('Parser')

    def _emit(self, username, upn, nt):
        rels = [
            Relationship(source=Fact('domain.user.name', username),
                         edge='has_hash',
                         target=Fact('domain.user.ntlm', nt)),
            Relationship(source=Fact('esc.owned.upn', upn)),
        ]
        self.log.debug('ADCS esc_auth: recovered NT hash for {!r}'.format(upn))
        return rels

    def parse(self, blob):
        relationships = []
        if not isinstance(blob, str):
            return relationships

        # Linux / certipy
        for m in self.CERTIPY_RE.finditer(blob):
            upn = m.group('upn')
            nt = m.group('nt').lower()
            relationships.extend(self._emit(upn.split('@')[0], upn, nt))

        # Windows / Rubeus: only if certipy form was not present, to avoid
        # double-emitting if a blob somehow contained both.
        if not relationships:
            nt_m = self.RUBEUS_NT_RE.search(blob)
            if nt_m:
                nt = nt_m.group('nt').lower()
                user_m = self.RUBEUS_USER_RE.search(blob)
                realm_m = self.RUBEUS_REALM_RE.search(blob)
                if user_m:
                    username = user_m.group('user')
                    if realm_m:
                        upn = '{}@{}'.format(username, realm_m.group('realm').lower())
                    else:
                        upn = username
                    relationships.extend(self._emit(username, upn, nt))
                else:
                    # hash without a username is still worth emitting as a bare hash
                    self.log.warning('ADCS esc_auth: Rubeus NT hash found but no UserName line; '
                                     'emitting hash without principal name.')
                    relationships.append(Relationship(source=Fact('domain.user.ntlm', nt)))

        if not relationships:
            self.log.warning('ADCS esc_auth: no NT hash found in auth output (neither certipy '
                             'nor Rubeus format). Confirm the pfx was valid and PKINIT/UnPAC succeeded.')
        return relationships
