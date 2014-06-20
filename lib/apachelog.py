import re

"""
break up in blocks separated by double quotes
"""
APACHE_LOG_BREAKUP_PATTERN = re.compile(
    r"""^(?P<group1>.+)"(?P<group2>((GET|POST).*HTTP[0-9/.]+)|-)"(?P<group3>[0-9 -]+)"(?P<group4>.+)" "(?P<group5>.+)" "(?P<group6>.+)" "(?P<group7>.+)"(?P<group8>.+)$"""
)


"""
domain
ip
client
user
timestamp
timezone
"""
APACHE_LOG_PATTERN_GROUP1 = re.compile(
    r"""^(?P<domain>[0-9A-Za-z:\.\-]+)\s(?P<ip>[0-9A-Za-z\.\-]+)\s(?P<client>\-)\s(?P<user>[A-Za-z-]+)\s\[(?P<timestamp>[0-9/A-Za-z:]+)\s(?P<timezone>(\+|\-)[0-9]{4})\]\s$"""
)

"""
action
url
method
OR '-'
"""
APACHE_LOG_PATTERN_GROUP2 = re.compile(
    r"""^(\-|(?P<action>[A-Z]+)\s(?P<url>.*)\s(?P<method>HTTP[0-9/.]+))$"""
)

"""
resultcode
bytes
"""
APACHE_LOG_PATTERN_GROUP3 = re.compile(
    r"""^\s(?P<resultcode>[0-9]+)\s(?P<bytes>[0-9-]+)\s$"""
)

"""
referer
"""
APACHE_LOG_PATTERN_GROUP4 = re.compile(
    r"""^(?P<referer>\S+)$"""
)

"""
useragent
"""
APACHE_LOG_PATTERN_GROUP5 = re.compile(
    r"""^(?P<useragent>[\S ]+)$"""
)

"""
via
"""
APACHE_LOG_PATTERN_GROUP6 = re.compile(
    r"""^(?P<via>.+)$"""
)

"""
forwardedfor
"""
APACHE_LOG_PATTERN_GROUP7 = re.compile(
    r"""^(?P<forwardedfor>[0-9.-]+)$"""
)

"""
percenta: %a
pid
percentD: %D
ACCutime
ACCstime
ACCcutime
ACCcstime
"""
APACHE_LOG_PATTERN_GROUP8 = re.compile(
    r"""\s(?P<percenta>[0-9.-]+)\spid:(?P<pid>[0-9]+)\s(?P<percentD>[0-9]+)\s(?P<ACCutime>[0-9-]+)\s(?P<ACCstime>[0-9-]+)\s(?P<ACCcutime>[0-9-]+)\s(?P<ACCcstime>[0-9-]+)"""
)


def break_up_into_blocks(regex, line):
    # sane_line = line.replace('\\"', "'")
    match = regex.match(line)
    if not match:
        return None
    return match.groupdict()


def sanitize_items(log_items):
    log_items['resultcode'] = int(log_items['resultcode'])
    if log_items['bytes'] == '-':
        log_items['bytes'] = 0
    log_items['pid'] = int(log_items['pid'])
    log_items['percentD'] = int(log_items['percentD'])
    if log_items['ACCutime'] == '-':
        log_items['ACCutime'] = 0
    log_items['ACCutime'] = int(log_items['ACCutime'])
    if log_items['ACCstime'] == '-':
        log_items['ACCstime'] = 0
    log_items['ACCstime'] = int(log_items['ACCstime'])
    if log_items['ACCcutime'] == '-':
        log_items['ACCcutime'] = 0
    log_items['ACCcutime'] = int(log_items['ACCcutime'])
    if log_items['ACCcstime'] == '-':
        log_items['ACCcstime'] = 0
    log_items['ACCcstime'] = int(log_items['ACCcstime'])

    return log_items


def parse_log_line(line):
    blocks = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, line)
    if not blocks:
        return None
    group1 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP1, blocks['group1'])
    group2 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP2, blocks['group2'])
    group3 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP3, blocks['group3'])
    group4 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP4, blocks['group4'])
    group5 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP5, blocks['group5'])
    group6 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP6, blocks['group6'])
    group7 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP7, blocks['group7'])
    group8 = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP8, blocks['group8'])
    all = dict(group1.items() + group2.items() + group3.items() +
               group4.items() + group5.items() + group6.items() +
               group7.items() + group8.items())

    sanitized = sanitize_items(all)
    return sanitized


def analyze_log(logfile):
    f = open(logfile, 'r')
    count = 0

    for line in (l.rstrip() for l in f):
        print line
        r = parse_log_line(line)
        if r:
            #print r['useragent']
            count += 1
        else:
            print line
#            print "NOT MATCHING: %s" % line
    # for line in access_iter(f):
    #     print line

    print "\nfound %d matches" % count