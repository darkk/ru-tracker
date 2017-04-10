#!/usr/bin/env python2.7

from contextlib import closing
import traceback
import hashlib
import zlib
import getpass
import sys
import re
import sqlite3
import time
import xml.etree.ElementTree as ElementTree

import requests

# Global object for transparent gzip and keep-alive!
ReqSession = requests.Session()
ReqSession.headers.update({
    'User-Agent': 'ru-tracker/0.0; ' + requests.utils.default_user_agent() + '; +https://github.com/darkk/ru-tracker'
})

FRESHNESS = 8 * 3600
TRACK_PER_TICKET = 100 # 3000 max, but it leads to error(104, 'Connection reset by peer')

def now():
    return int(time.time())

def scheme_update(db):
    db.execute('PRAGMA foreign_keys = ON')

    version = None
    try:
        for row in db.execute('SELECT scheme_version FROM scheme_version'):
            version = row[0]
    except sqlite3.OperationalError:
        # probably, there is no such table
        db.execute('CREATE TABLE scheme_version(scheme_version INTEGER)')
    if version is None:
        version = 0
        db.execute('INSERT INTO scheme_version VALUES(?)', (version,) )

    schemes = (
        """
        CREATE TABLE credentials (
            login       TEXT NOT NULL,
            password    TEXT NOT NULL)
        """, """
        CREATE TABLE log_single (
            timestamp   INTEGER NOT NULL,
            barcode     TEXT NOT NULL,
            req_xmlz    BLOB NOT NULL,
            status_code INTEGER,
            resp_xmlz   BLOB,
            oper_cnt    INTEGER,
            oper_sha256 BLOB)
        """, """
        CREATE UNIQUE INDEX log_single_barcode_timestamp ON log_single (barcode, timestamp)
        """, """
        CREATE TABLE log_ticket (
            batch_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            req_xmlz    BLOB NOT NULL,
            status_code INTEGER,
            resp_xmlz   BLOB,
            ticket      TEXT)
        """, """
        CREATE TABLE batch (
            batch_id    INTEGER NOT NULL REFERENCES log_ticket (batch_id),
            barcode     TEXT NOT NULL,
            oper_cnt    INTEGER,
            oper_sha256 BLOB)
        """, """
        CREATE INDEX batch_barcode_batch_id ON batch (barcode, batch_id)
        """, """
        CREATE TABLE log_batch (
            batch_id    INTEGER NOT NULL REFERENCES log_ticket (batch_id),
            timestamp   INTEGER NOT NULL,
            req_xmlz    BLOB NOT NULL,
            status_code INTEGER,
            resp_xmlz   BLOB)
        """, """
        CREATE INDEX log_batch_batch_id ON log_batch (batch_id)
        """
    )
    for i in xrange(version, len(schemes)):
        query = schemes[i]
        print >>sys.stderr, 'scheme_update: %s' % query
        db.execute(query)
        db.execute('UPDATE scheme_version SET scheme_version = scheme_version + 1')
        db.commit()

def assert_login(login, password):
    req = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:oper="http://russianpost.org/operationhistory" '
                   'xmlns:data="http://russianpost.org/operationhistory/data" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
      '<soap:Header/>'
        '<soap:Body>'
          '<oper:getOperationHistory>'
            '<data:OperationHistoryRequest>'
              '<data:Barcode>{barcode}</data:Barcode>'
              '<data:MessageType>0</data:MessageType>'
              '<data:Language>RUS</data:Language>'
            '</data:OperationHistoryRequest>'
            '<data:AuthorizationHeader soapenv:mustUnderstand="1">'
              '<data:login>{login}</data:login>'
              '<data:password>{password}</data:password>'
            '</data:AuthorizationHeader>'
          '</oper:getOperationHistory>'
      '</soap:Body>'
    '</soap:Envelope>'
    ).format(barcode='01234567890123', login=login, password=password)
    # 01234567890123 is good enough to check for AuthorizationFaultReason
    resp = ReqSession.post('https://tracking.russianpost.ru/rtm34', data=req)
    try:
        et = ElementTree.fromstring(resp.content) # can't handle `resp.text` here
    except Exception:
        print >>sys.stderr, 'Non-XML response:'
        print >>sys.stderr, resp
        print >>sys.stderr, resp.text
        raise
    if et.find('.//{http://russianpost.org/operationhistory}getOperationHistoryResponse') is not None:
        pass
    elif et.find('.//{http://russianpost.org/operationhistory/data}AuthorizationFaultReason') is not None:
        raise RuntimeError('Authorization failure', resp.text)
    else:
        raise RuntimeError('Unable to validate login', resp.text)

def get_password(db):
    c = db.cursor()
    c.execute('SELECT login, password FROM credentials LIMIT 1')
    row = c.fetchone()
    if row is not None:
        login, password = row
    else:
        login = getpass.getpass('Super-secret login: ')
        password = getpass.getpass('Super-secret password: ')
        assert_login(login, password)
        with db:
            c.execute('INSERT INTO credentials (login, password) VALUES(?, ?)', (login, password))
    return login, password

def xmlz(string):
    assert isinstance(string, str)
    return sqlite3.Binary(zlib.compress(string))

# https://tracking.russianpost.ru/fc endpoint requires ABSENCE of any Content-Type header!
def record_ticket(db, barcodes):
    login, password = get_password(db)
    items = ''.join('<ns1:Item Barcode="{}"/>'.format(_) for _ in barcodes)
    req = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope xmlns:ns0="http://fclient.russianpost.org/postserver" xmlns:ns1="http://fclient.russianpost.org" '
                       'xmlns:ns2="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                       'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
      '<SOAP-ENV:Header/>'
      '<ns2:Body>'
        '<ns0:ticketRequest>'
          '<request>'
            '{items}'
          '</request>'
          '<login>{login}</login>'
          '<password>{password}</password>'
          '<language>RUS</language>'
        '</ns0:ticketRequest>'
      '</ns2:Body>'
    '</SOAP-ENV:Envelope>').format(items=items, login=login, password=password)
    timestamp = now()
    c = db.cursor()
    with db:
        c.execute('INSERT INTO log_ticket (timestamp, req_xmlz) VALUES (?, ?)', (timestamp, xmlz(req)))
        batch_id = c.lastrowid
        c.executemany('INSERT INTO batch (batch_id, barcode) VALUES (?, ?)', ((batch_id, _) for _ in barcodes))
    resp = ReqSession.post('https://tracking.russianpost.ru/fc', data=req)
    with db:
        c.execute('UPDATE log_ticket SET status_code = ?, resp_xmlz = ? WHERE batch_id = ?',
                    (resp.status_code, xmlz(resp.content), batch_id))
    resp.raise_for_status()
    et = ElementTree.fromstring(resp.content)
    ticket = et.find('.//{http://fclient.russianpost.org/postserver}ticketResponse/value')
    if ticket is None:
        raise RuntimeError('No ticketResponse', resp.text)
    with db:
        c.execute('UPDATE log_ticket SET ticket = ? WHERE batch_id = ?', (ticket.text, batch_id))

def hash_opkeys(opkeys):
    return sqlite3.Binary(hashlib.sha256('\n'.join('|'.join(_) for _ in opkeys)).digest())

def record_batch(db, batch_id, ticket):
    login, password = get_password(db)
    req = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope xmlns:ns0="http://fclient.russianpost.org/postserver" xmlns:ns1="http://schemas.xmlsoap.org/soap/envelope/" '
                       'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
      '<SOAP-ENV:Header/>'
      '<ns1:Body>'
        '<ns0:answerByTicketRequest>'
          '<ticket>{ticket}</ticket>'
          '<login>{login}</login>'
          '<password>{password}</password>'
        '</ns0:answerByTicketRequest>'
      '</ns1:Body>'
    '</SOAP-ENV:Envelope>').format(ticket=ticket, login=login, password=password)
    timestamp = now()
    c = db.cursor()
    with db:
        c.execute('INSERT INTO log_batch (batch_id, timestamp, req_xmlz) VALUES (?, ?, ?)', (batch_id, timestamp, xmlz(req)))
    resp = ReqSession.post('https://tracking.russianpost.ru/fc', data=req)
    with db:
        c.execute('UPDATE log_batch SET status_code = ?, resp_xmlz = ? WHERE batch_id = ? AND timestamp = ? AND status_code IS NULL',
                    (resp.status_code, xmlz(resp.content), batch_id, timestamp))
    resp.raise_for_status()
    et = ElementTree.fromstring(resp.content)
    items = et.findall('.//{http://fclient.russianpost.org/postserver}answerByTicketResponse/value/{http://fclient.russianpost.org}Item')
    if not items:
        raise RuntimeError('Empty answerByTicketResponse', resp.text)
    with db:
        for i in items:
            barcode = i.get('Barcode')
            # date is not added as it has different formatting at different endpoints
            opkeys = sorted([(op.get('IndexOper'), op.get('OperTypeID'), op.get('OperCtgID'))
                                for op in i.findall('./{http://fclient.russianpost.org}Operation')])
            oper_sha256 = hash_opkeys(opkeys)
            oper_cnt = len(opkeys)
            c.execute('UPDATE batch SET oper_cnt = ?, oper_sha256 = ? WHERE batch_id = ? AND barcode = ?',
                      (oper_cnt, oper_sha256, batch_id, barcode))

def record_single(db, barcode):
    login, password = get_password(db)
    req = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soap:Envelope xmlns:oper="http://russianpost.org/operationhistory" xmlns:data="http://russianpost.org/operationhistory/data" xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
      '<soap:Header/>'
      '<soap:Body>'
        '<oper:getOperationHistory>'
          '<data:OperationHistoryRequest>'
            '<data:Barcode>{barcode}</data:Barcode>'
            '<data:MessageType>0</data:MessageType>'
            '<data:Language>RUS</data:Language>'
          '</data:OperationHistoryRequest>'
          '<data:AuthorizationHeader soapenv:mustUnderstand="1">'
            '<data:login>{login}</data:login>'
            '<data:password>{password}</data:password>'
          '</data:AuthorizationHeader>'
        '</oper:getOperationHistory>'
      '</soap:Body>'
    '</soap:Envelope>').format(barcode=barcode, login=login, password=password)
    timestamp = now()
    c = db.cursor()
    with db:
        c.execute('INSERT INTO log_single (timestamp, barcode, req_xmlz) VALUES (?, ?, ?)', (timestamp, barcode, xmlz(req)))
    resp = ReqSession.post('https://tracking.russianpost.ru/rtm34', data=req)
    with db:
        c.execute('UPDATE log_single SET status_code = ?, resp_xmlz = ? WHERE timestamp = ? AND barcode = ? AND status_code IS NULL',
                    (resp.status_code, xmlz(resp.content), timestamp, barcode))
    et = ElementTree.fromstring(resp.content)
    ns = {'ns7': 'http://russianpost.org/operationhistory', 'ns3': 'http://russianpost.org/operationhistory/data'}
    with db:
        opkeys = sorted([
            (i.find('ns3:AddressParameters/ns3:OperationAddress/ns3:Index', ns).text,
             i.find('ns3:OperationParameters/ns3:OperType/ns3:Id', ns).text,
             i.find('ns3:OperationParameters/ns3:OperAttr/ns3:Id', ns).text)
            for i in et.findall('.//ns7:getOperationHistoryResponse/ns3:OperationHistoryData/ns3:historyRecord', ns)])
        oper_sha256 = hash_opkeys(opkeys)
        oper_cnt = len(opkeys)
        c.execute('UPDATE log_single SET oper_cnt = ?, oper_sha256 = ? WHERE timestamp = ? AND barcode = ?',
                  (oper_cnt, oper_sha256, timestamp, barcode))

def print_barcode(db, barcode):
    ns = {'ns3': 'http://russianpost.org/operationhistory/data'}
    c = db.cursor()
    c.execute('SELECT resp_xmlz, timestamp '
              'FROM (SELECT barcode, MAX(timestamp) AS timestamp FROM log_single WHERE barcode = ?) '
              'JOIN log_single USING (barcode, timestamp) LIMIT 1', (barcode, ))
    et, timestamp = c.fetchone()
    et = ElementTree.fromstring(zlib.decompress(et))
    header = et.findall('.//ns3:UserParameters/ns3:SendCtg/ns3:Id/../../..', ns)
    if not header:
        raise RuntimeError('No destination for', barcode)
    if len(header) > 1:
        print >>sys.stderr, len(header), 'destinations for', barcode
    header = header[0]
    out = u'{};\n'.format(barcode)
    out += (u';{}*rus*[LOC[EVENT_SENDER]]: {}, [LOC[EVENT_RCPT]]: {}, [LOC[EVENT_TYPE]]: {}\n'.format(
        time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(timestamp)),
        header.find('ns3:UserParameters/ns3:Sndr', ns).text,
        header.find('ns3:UserParameters/ns3:Rcpn', ns).text,
        header.find('ns3:ItemParameters/ns3:ComplexItemName', ns).text
    ))
    for hr in et.findall('.//ns3:historyRecord', ns):
        mass = hr.find('ns3:ItemParameters/ns3:Mass', ns)
        mass = ', [LOC[EVENT_WEIGHT]]: {}[LOC[EVENT_WEIGHT_GRAM]]'.format(mass.text) if mass is not None else ''
        out += (u';{}*rus*{}{}, {} {} {}\n'.format(
            hr.find('ns3:OperationParameters/ns3:OperDate', ns).text.split('.', 1)[0],
            hr.find('ns3:OperationParameters/ns3:OperAttr/ns3:Name', ns).text,
            mass,
            hr.find('ns3:AddressParameters/ns3:OperationAddress/ns3:Index', ns).text,
            hr.find('ns3:AddressParameters/ns3:OperationAddress/ns3:Description', ns).text,
            hr.find('ns3:AddressParameters/ns3:CountryOper/ns3:NameRU', ns).text
        ))
    sys.stdout.write(out.encode('utf-8'))

def main():
    barcode_re = re.compile(r'^(?:[A-Z]{2}\d{9}[A-Z]{2}|\d{14})$')
    with closing(sqlite3.connect('ru-tracker.sqlite')) as db:
        scheme_update(db)
        login, password = get_password(db)

        barcodes = []
        for fname in sys.argv[1:]:
            with open(fname) as fd:
                barcodes.extend(filter(None, fd.read().strip().split()))
        valid = set(filter(barcode_re.match, barcodes))

        c = db.cursor()
        c.execute('CREATE TEMPORARY TABLE valid (barcode TEXT)')
        c.executemany('INSERT INTO valid (barcode) VALUES (?)', ((_,) for _ in valid))

        ticket_birth = now() - FRESHNESS

        c.execute('SELECT barcode FROM valid WHERE NOT EXISTS '
                    '(SELECT 1 FROM batch JOIN log_ticket USING (batch_id) '
                        'WHERE valid.barcode = batch.barcode AND ticket IS NOT NULL AND ? < timestamp)',
            (ticket_birth,))
        stale = [_[0] for _ in c]
        print >>sys.stderr, len(stale), 'barcodes without fresh ticket'
        chunks = []
        while stale:
            chunks.append(stale[:TRACK_PER_TICKET])
            del stale[:TRACK_PER_TICKET]
        print >>sys.stderr, len(chunks), 'tickets to get'
        for _ in chunks:
            record_ticket(db, _)
        print >>sys.stderr, 'Got all tickets'

        # FIXME: graceful delay!
        c.execute('SELECT batch_id, ticket FROM log_ticket tkt WHERE ticket IS NOT NULL AND ? < timestamp AND EXISTS '
                    '(SELECT 1 FROM batch WHERE tkt.batch_id = batch.batch_id AND oper_cnt IS NULL)',
            (ticket_birth,))
        fresh_tickets = list(c)
        print >>sys.stderr, len(fresh_tickets), 'tickets to validate'
        for batch_id, ticket in fresh_tickets:
            record_batch(db, batch_id, ticket)
        print >>sys.stderr, 'Validated all tickets'

        # last timestamp for valid barcode
        c.execute('CREATE TEMPORARY TABLE last AS SELECT barcode, MAX(timestamp) AS timestamp '
                  'FROM batch JOIN log_batch USING (batch_id) '
                  'WHERE barcode IN (SELECT barcode FROM valid) GROUP BY barcode')
        # fresh operations for latest barcode info
        c.execute('CREATE TEMPORARY TABLE fresh AS '
            'SELECT last.barcode, batch.oper_cnt, batch.oper_sha256 FROM last, batch, log_batch '
            'WHERE last.timestamp = log_batch.timestamp AND last.barcode = batch.barcode AND batch.batch_id = log_batch.batch_id')
        c.execute('SELECT barcode FROM valid v WHERE barcode NOT IN '
                    '(SELECT barcode FROM fresh JOIN log_single USING (barcode, oper_cnt, oper_sha256))')
        singles = [_[0] for _ in c]
        print >>sys.stderr, len(singles), 'barcodes to get'
        report_point = len(singles) / 25
        for ndx, _ in enumerate(singles):
            record_single(db, _)
            if report_point and (ndx + 1) % report_point == 0:
                print >>sys.stderr, 'Got', ndx + 1, 'barcodes'
        print >>sys.stderr, 'Got all barcodes'

        sys.stdout.write('id_Track;id_Event\n')
        for _ in barcodes:
            try:
                print_barcode(db, _)
            except Exception, exc:
                print >>sys.stderr, 'Unable to print', _
                traceback.print_exc(file=sys.stderr)

if __name__ == '__main__':
    main()
