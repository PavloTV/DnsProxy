import configparser as configparser

from dnslib import *
from dnslib import server, proxy

config_file_name = 'config.ini'

config = configparser.ConfigParser()
config.read(config_file_name)

# DEFAULTS
upstream = '8.8.8.8'


def read_config():
    global upstream
    global config

    if 'SERVER' in config.sections():
        if "upstream" in config['SERVER']:
            upstream = config['SERVER']['upstream']

    print('Using upstream server: %s' % upstream)


class BlacklistFilter:
    def resolve(self, request, handler):
        reply = request.reply()
        question = request.get_q()
        question_name = ("%s" % question.qname)
        requested_domain = question_name[:-1]

        # Check if blacklisted
        if 'BLACKLIST' in config.sections() and requested_domain in config['BLACKLIST']:
            print('Request Blacklisted %s -> "%s"' % (requested_domain, config['BLACKLIST'][requested_domain]))
            # Return fake address if avail
            if config['BLACKLIST'][requested_domain]:
                # Create fake reply
                rid = request.header.id
                reply = DNSRecord(DNSHeader(id=rid), q=question,
                                  a=RR(requested_domain, rdata=A(config['BLACKLIST'][requested_domain])))
        else:
            print('Request redirected to upstream')
            try:
                if handler.protocol == 'udp':
                    proxy_r = request.send(upstream)
                else:
                    proxy_r = request.send(upstream, tcp=True)
                reply = DNSRecord.parse(proxy_r)
            except socket.timeout:
                reply.header.rcode = getattr(RCODE, 'SERVFAIL')
        return reply


def start_server():
    # Using custom resolver
    resolver = BlacklistFilter()
    s = server.DNSServer(resolver)
    s.start()


if __name__ == "__main__":
    read_config()
    start_server()
