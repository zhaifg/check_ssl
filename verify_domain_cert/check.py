# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna


import argparse
import concurrent.futures
from collections import namedtuple
from socket import socket
from urllib.parse import urlparse

import idna
from cryptography import x509
from cryptography.x509.oid import NameOID
from OpenSSL import SSL

HostInfo = namedtuple(field_names="cert hostname peername", typename="HostInfo")


def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer


def get_certificate(hostname, port=443):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD)  # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)


def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None


def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def print_basic_info(hostinfo):
    s = """» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    """.format(
        hostname=hostinfo.hostname,
        peername=hostinfo.peername,
        commonname=get_common_name(hostinfo.cert),
        SAN=get_alt_names(hostinfo.cert),
        issuer=get_issuer(hostinfo.cert),
        notbefore=hostinfo.cert.not_valid_before_utc,
        notafter=hostinfo.cert.not_valid_after_utc,
    )
    print(s)


def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


def main():
    parser = argparse.ArgumentParser(description="get certificate  expire date")
    # parser.add_argument("hosts")
    parser.add_argument("hosts", metavar="N", type=str, nargs="*", help="hosts")
    parser.add_argument(
        "--install-skill",
        action="store_true",
        help="write the verify_domain_cert Agent Skill (SKILL.md) into an agent skills directory and exit",
    )
    parser.add_argument(
        "--skill-dir",
        default=None,
        help="skill directory used by --install-skill (default: ~/.agents/skills/verify-domain-cert)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing SKILL.md when used with --install-skill",
    )

    args = parser.parse_args()

    if args.install_skill:
        from verify_domain_cert.skill import install_skill

        try:
            skill_file = install_skill(args.skill_dir, force=args.force)
        except (FileExistsError, NotADirectoryError) as exc:
            parser.exit(1, f"error: {exc}\n")
            return
        print(f"installed agent skill: {skill_file}")
        return

    if not args.hosts:
        parser.error("provide at least one host or use --install-skill")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for hostname in args.hosts:
            hostname = hostname.strip()

            h = urlparse(hostname)
            h_list = h.netloc.split(":")
            (hostname, port) = (h_list[0], int(h_list[1]) if len(h_list) > 1 else 443)
            executor.submit(check_it_out, hostname, port)


if __name__ == "__main__":
    main()
