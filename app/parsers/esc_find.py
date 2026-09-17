import json
import logging
import re

from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship
from app.utility.base_parser import BaseParser


class Parser(BaseParser):
    """
    Parse vulnerable-template enumeration from either certipy (Linux, JSON) or
    Certify (Windows, text) and emit identical per-ESC facts, so the enumerate
    ability is OS-agnostic and the downstream request abilities branch the same
    way regardless of which tool ran.

        esc1.template.name  --issued_by-->  esc1.ca.name
        esc2.template.name  --issued_by-->  esc2.ca.name
        esc3.template.name  --issued_by-->  esc3.ca.name
        esc4.template.name  --issued_by-->  esc4.ca.name

    certipy emits per-ESC vulnerability labels directly in JSON. Certify's
    find /vulnerable output lists templates by AD name only, so the ESC class is
    derived here from the same signals both tools use (Certified Pre-Owned):
      ESC1: msPKI-Certificate-Name-Flag has ENROLLEE_SUPPLIES_SUBJECT AND a
            client-auth-capable EKU (Client Authentication / Smart Card Logon /
            PKINIT Client Authentication / Any Purpose).
      ESC2: pkiextendedkeyusage has 'Any Purpose' (or no EKU). Also flagged ESC3,
            matching certipy, because an Any Purpose cert is agent-capable.
      ESC3: pkiextendedkeyusage has 'Certificate Request Agent'.
      ESC4: a low-privileged principal (e.g. Domain Users) appears under any of
            the dangerous Object Control permissions (Full Control / WriteOwner /
            WriteDacl / WriteProperty / WriteProperty Principals).

    The dual-flag on ESC2 (also emitting esc3.template.name) is deliberate and
    matches the Linux fact set, so the ESC3 branch fires for the Any Purpose
    template on both platforms.
    """

    SUPPORTED = ("ESC1", "ESC2", "ESC3", "ESC4")

    # Low-priv principals that make an Object-Control permission an ESC4 signal.
    LOWPRIV = ("domain users", "authenticated users", "everyone", "users")
    CLIENT_AUTH_EKUS = ("client authentication", "smart card logon",
                        "pkinit client authentication", "any purpose")

    def __init__(self, parser_info):
        super().__init__(parser_info)
        self.mappers = parser_info['mappers']
        self.used_facts = parser_info['used_facts']
        self.log = logging.getLogger('Parser')

    def parse(self, blob):
        if not isinstance(blob, str):
            return []
        # Detect format: certipy is JSON, Certify is a text report.
        if 'Vulnerable Certificates Templates' in blob or '[*] Action: Find certificate templates' in blob:
            return self._parse_certify(blob)
        return self._parse_certipy(blob)

    # ---------- Linux / certipy (JSON) ----------
    def _parse_certipy(self, blob):
        relationships = []
        try:
            data = json.loads(self._strip_to_json(blob))
        except (ValueError, TypeError):
            self.log.warning('ADCS esc_find: output was not valid JSON and not a Certify report.')
            return relationships
        templates = data.get('Certificate Templates')
        if not isinstance(templates, dict):
            return relationships
        for _, entry in templates.items():
            if not isinstance(entry, dict):
                continue
            name = entry.get('Template Name')
            cas = entry.get('Certificate Authorities') or []
            ca = cas[0] if isinstance(cas, list) and cas else 'Unknown-CA'
            vulns = entry.get('[!] Vulnerabilities') or {}
            if not name or not isinstance(vulns, dict):
                continue
            for esc in vulns:
                self._emit(relationships, esc.strip().upper(), name, ca)
        return relationships

    # ---------- Windows / Certify (text) ----------
    def _parse_certify(self, blob):
        relationships = []
        # Split into per-template blocks. Each starts at a 'CA Name' line.
        # Keep it simple and robust: slice on the 'Template Name' anchor.
        blocks = re.split(r'\n(?=\s*CA Name\s*:)', blob)
        for b in blocks:
            name_m = re.search(r'Template Name\s*:\s*(\S+)', b)
            ca_m = re.search(r'CA Name\s*:\s*(\S+)', b)
            if not name_m:
                continue
            name = name_m.group(1).strip()
            ca_full = ca_m.group(1).strip() if ca_m else 'Unknown-CA'
            # Certify prints CA as HOST\CA-NAME; certipy facts use the CA-NAME
            # only, so take the part after the last backslash to stay symmetric.
            ca = ca_full.split('\\')[-1] if '\\' in ca_full else ca_full

            name_flags = self._field(b, 'msPKI-Certificate-Name-Flag')
            ekus = self._field(b, 'pkiextendedkeyusage')
            classes = self._classify(b, name_flags, ekus)
            for esc in classes:
                self._emit(relationships, esc, name, ca)
        return relationships

    def _classify(self, block, name_flags, ekus):
        classes = set()
        nf = (name_flags or '').lower()
        eku = (ekus or '').lower()
        has_client_auth = any(k in eku for k in self.CLIENT_AUTH_EKUS)

        # ESC1: enrollee supplies subject + client-auth EKU
        if 'enrollee_supplies_subject' in nf and has_client_auth:
            classes.add('ESC1')
        # ESC2: Any Purpose (or no EKU). Also dual-flag ESC3 like certipy.
        if 'any purpose' in eku or eku.strip() == '':
            classes.add('ESC2')
            classes.add('ESC3')
        # ESC3: Certificate Request Agent
        if 'certificate request agent' in eku:
            classes.add('ESC3')
        # ESC4: a low-priv principal under any dangerous Object Control right
        if self._esc4(block):
            classes.add('ESC4')
        return classes

    def _esc4(self, block):
        # Look only within the Object Control Permissions section for a
        # dangerous right granted to a low-priv principal.
        oc = block.split('Object Control Permissions', 1)
        if len(oc) < 2:
            return False
        section = oc[1].lower()
        danger_labels = ('full control principals', 'writeowner principals',
                        'writedacl principals', 'writeproperty principals')
        for label in danger_labels:
            # capture the lines belonging to this label until the next label
            m = re.search(re.escape(label) + r'\s*:(.*?)(?=\n\s*\w[\w ]*principals\s*:|\n\s*owner\s*:|\Z)',
                        section, re.S)
            if m and any(lp in m.group(1) for lp in self.LOWPRIV):
                return True
        return False

    def _field(self, block, label):
        m = re.search(re.escape(label) + r'\s*:\s*(.+)', block)
        return m.group(1).strip() if m else ''

    def _emit(self, relationships, esc_key, name, ca):
        if esc_key not in self.SUPPORTED:
            return
        prefix = esc_key.lower()
        relationships.append(
            Relationship(source=Fact('{}.template.name'.format(prefix), name),
                        edge='issued_by',
                        target=Fact('{}.ca.name'.format(prefix), ca))
        )
        self.log.debug('ADCS esc_find: {} vulnerable template {!r} on CA {!r}'
                    .format(esc_key, name, ca))

    @staticmethod
    def _strip_to_json(blob):
        if not isinstance(blob, str):
            return blob
        start = blob.find('{'); end = blob.rfind('}')
        if start == -1 or end == -1 or end < start:
            return blob
        return blob[start:end + 1]
