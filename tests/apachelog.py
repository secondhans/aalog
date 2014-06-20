import unittest
from lib.apachelog import parse_log_line, break_up_into_blocks
from lib.apachelog import APACHE_LOG_BREAKUP_PATTERN, \
    APACHE_LOG_PATTERN_GROUP1, APACHE_LOG_PATTERN_GROUP2, \
    APACHE_LOG_PATTERN_GROUP3, APACHE_LOG_PATTERN_GROUP4, \
    APACHE_LOG_PATTERN_GROUP5, APACHE_LOG_PATTERN_GROUP6, \
    APACHE_LOG_PATTERN_GROUP7, APACHE_LOG_PATTERN_GROUP8



class AaLog(unittest.TestCase):
    def setUp(self):
        pass


class TestReadApacheLog(AaLog):
    def setUp(self):
        self.logline1 = """www.loadbalancercheck.nl 10.1.2.122 - - [18/Jun/2014:06:26:49 +0200] "GET / HTTP/1.1" 200 - "-" "check_http/v1.4.16 (nagios-plugins 1.4.16)" "-" "10.1.2.122" 10.1.2.122 pid:2610 741 0 0 0 0"""
        self.logline2 = """boekwinkel.dizzie.nl 194.104.130.85 - - [18/Jun/2014:07:46:41 -0200] "GET /wegadmin HTTP/1.1" 302 26 "-" "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36" "1.1 SCWTMG003" "194.104.130.85" 194.104.130.85 pid:11118 100824 88005 4000 0 0"""
        self.logline3 = """- 194.104.130.85 - - [18/Jun/2014:11:43:08 +0200] "-" 408 - "-" "-" "-" "-" 194.104.130.85 pid:11112 37 - - - -"""
        self.logline4 = """www.connectingarts.org 111.11.27.194 - - [18/Jun/2014:06:30:11 +0200] "GET http://www.connectingarts.org/en/organisation-/verantwoording/item/322-anbi/322-anbi.html?start=3060+Result:+chosen+nickname+%22nsmpalxq27%22;+success; Result: chosen nickname "ksgxspii98"; success; HTTP/1.0" 404 1390 "http://www.connectingarts.org/en/organisation-/verantwoording/item/322-anbi/322-anbi.html?start=3060+Result:+chosen+nickname+%22nsmpalxq27%22;+success; Result: chosen nickname "ksgxspii98"; success;" "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.107 Safari/537.36" "-" "-" 111.11.27.194 pid:3999 204766 0 8001 128008 36002"""
        self.logline5 = """www.connectingarts.org 118.97.95.185 - - [18/Jun/2014:06:28:01 +0200] "POST /index2.php HTTP/1.0" 200 62 "http://www.connectingarts.org/en/organisation-/verantwoording/item/322-anbi/322-anbi.html?start=2610" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" "1.1 cakcuk:9128 (squid/2.6.STABLE21)" "10.178.59.222" 118.97.95.185 pid:4198 473776 0 8000 120007 68004"""

    def test_that_breakup_pattern_of_logline1_is_parsed_correctly(self):
        result = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 8)

    def test_that_group1_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP1, groups['group1'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 6)
        self.assertEqual(result['domain'], 'www.loadbalancercheck.nl')
        self.assertEqual(result['ip'], '10.1.2.122')
        self.assertEqual(result['client'], '-')
        self.assertEqual(result['user'], '-')
        self.assertEqual(result['timestamp'], '18/Jun/2014:06:26:49')
        self.assertEqual(result['timezone'], '+0200')

    def test_that_group2_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP2, groups['group2'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 3)
        self.assertEqual(result['action'], 'GET')
        self.assertEqual(result['url'], '/')
        self.assertEqual(result['method'], 'HTTP/1.1')

    def test_that_group3_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP3, groups['group3'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 2)
        self.assertEqual(result['resultcode'], '200')
        self.assertEqual(result['bytes'], '-')

    def test_that_group4_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP4, groups['group4'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['referer'], '-')

    def test_that_group5_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP5, groups['group5'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['useragent'], 'check_http/v1.4.16 (nagios-plugins 1.4.16)')

    def test_that_group6_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP6, groups['group6'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['via'], '-')

    def test_that_group7_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP7, groups['group7'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['forwardedfor'], '10.1.2.122')

    def test_that_group8_of_logline1_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline1)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP8, groups['group8'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 7)
        self.assertEqual(result['percenta'], '10.1.2.122')
        self.assertEqual(result['pid'], '2610')
        self.assertEqual(result['percentD'], '741')
        self.assertEqual(result['ACCutime'], '0')
        self.assertEqual(result['ACCstime'], '0')
        self.assertEqual(result['ACCcutime'], '0')
        self.assertEqual(result['ACCcstime'], '0')

    def test_that_breakup_pattern_of_logline2_is_parsed_correctly(self):
        result = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 8)

    def test_that_group1_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP1, groups['group1'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 6)
        self.assertEqual(result['domain'], 'boekwinkel.dizzie.nl')
        self.assertEqual(result['ip'], '194.104.130.85')
        self.assertEqual(result['client'], '-')
        self.assertEqual(result['user'], '-')
        self.assertEqual(result['timestamp'], '18/Jun/2014:07:46:41')
        self.assertEqual(result['timezone'], '-0200')

    def test_that_group2_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP2, groups['group2'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 3)
        self.assertEqual(result['action'], 'GET')
        self.assertEqual(result['url'], '/wegadmin')
        self.assertEqual(result['method'], 'HTTP/1.1')

    def test_that_group3_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP3, groups['group3'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 2)
        self.assertEqual(result['resultcode'], '302')
        self.assertEqual(result['bytes'], '26')

    def test_that_group4_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP4, groups['group4'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['referer'], '-')

    def test_that_group5_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP5, groups['group5'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['useragent'], 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36')

    def test_that_group6_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP6, groups['group6'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['via'], '1.1 SCWTMG003')

    def test_that_group7_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP7, groups['group7'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['forwardedfor'], '194.104.130.85')

    def test_that_group8_of_logline2_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline2)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP8, groups['group8'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 7)
        self.assertEqual(result['percenta'], '194.104.130.85')
        self.assertEqual(result['pid'], '11118')
        self.assertEqual(result['percentD'], '100824')
        self.assertEqual(result['ACCutime'], '88005')
        self.assertEqual(result['ACCstime'], '4000')
        self.assertEqual(result['ACCcutime'], '0')
        self.assertEqual(result['ACCcstime'], '0')

    def test_that_breakup_pattern_of_logline3_is_parsed_correctly(self):
        result = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 8)

    def test_that_group1_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP1, groups['group1'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 6)
        self.assertEqual(result['domain'], '-')
        self.assertEqual(result['ip'], '194.104.130.85')
        self.assertEqual(result['client'], '-')
        self.assertEqual(result['user'], '-')
        self.assertEqual(result['timestamp'], '18/Jun/2014:11:43:08')
        self.assertEqual(result['timezone'], '+0200')

    def test_that_group2_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP2, groups['group2'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 3)
        self.assertEqual(result['action'], None)
        self.assertEqual(result['url'], None)
        self.assertEqual(result['method'], None)

    def test_that_group3_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP3, groups['group3'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 2)
        self.assertEqual(result['resultcode'], '408')
        self.assertEqual(result['bytes'], '-')

    def test_that_group4_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP4, groups['group4'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['referer'], '-')

    def test_that_group5_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP5, groups['group5'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['useragent'], '-')

    def test_that_group6_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP6, groups['group6'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['via'], '-')

    def test_that_group7_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP7, groups['group7'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['forwardedfor'], '-')

    def test_that_group8_of_logline3_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline3)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP8, groups['group8'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 7)
        self.assertEqual(result['percenta'], '194.104.130.85')
        self.assertEqual(result['pid'], '11112')
        self.assertEqual(result['percentD'], '37')
        self.assertEqual(result['ACCutime'], '-')
        self.assertEqual(result['ACCstime'], '-')
        self.assertEqual(result['ACCcutime'], '-')
        self.assertEqual(result['ACCcstime'], '-')

    def test_that_parse_log_line_returns_none_when_breakup_returns_none(self):
        pass
    #
    def test_that_parse_log_line_with_logline1_returns_sanitized_output(self):
        result = parse_log_line(self.logline1)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 22)
        self.assertEqual(result['resultcode'], 200)
        self.assertEqual(result['bytes'], 0)
        self.assertEqual(result['pid'], 2610)
        self.assertEqual(result['percentD'], 741)
        self.assertEqual(result['ACCutime'], 0)
        self.assertEqual(result['ACCstime'], 0)
        self.assertEqual(result['ACCcutime'], 0)
        self.assertEqual(result['ACCcstime'], 0)

    def test_that_breakup_pattern_of_logline4_is_parsed_correctly(self):
        result = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 8)

    def test_that_group1_of_logline4_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP1, groups['group1'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 6)
        # self.assertEqual(result['domain'], '-')
        self.assertEqual(result['ip'], '111.11.27.194')
        self.assertEqual(result['client'], '-')
        self.assertEqual(result['user'], '-')
        self.assertEqual(result['timestamp'], '18/Jun/2014:06:30:11')
        self.assertEqual(result['timezone'], '+0200')

    def test_that_group2_of_logline4_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP2, groups['group2'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 3)
        self.assertEqual(result['action'], 'GET')
        self.assertEqual(result['url'], """http://www.connectingarts.org/en/organisation-/verantwoording/item/322-anbi/322-anbi.html?start=3060+Result:+chosen+nickname+%22nsmpalxq27%22;+success; Result: chosen nickname "ksgxspii98"; success;""")
        self.assertEqual(result['method'], 'HTTP/1.0')

    def test_that_group3_of_logline4_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP3, groups['group3'])
        print groups['group3']
        print groups['group4']
        print groups['group5']
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 2)
        self.assertEqual(result['resultcode'], '404')
        self.assertEqual(result['bytes'], '1390')

    def test_that_group5_of_logline4_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP5, groups['group5'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['useragent'], 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.107 Safari/537.36')

    def test_that_group6_of_logline4_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP6, groups['group6'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['via'], '-')

    def test_that_group7_of_logline4_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP7, groups['group7'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['forwardedfor'], '-')

    def test_that_group8_of_logline4_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline4)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP8, groups['group8'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 7)
        self.assertEqual(result['percenta'], '111.11.27.194')
        self.assertEqual(result['pid'], '3999')
        self.assertEqual(result['percentD'], '204766')
        self.assertEqual(result['ACCutime'], '0')
        self.assertEqual(result['ACCstime'], '8001')
        self.assertEqual(result['ACCcutime'], '128008')
        self.assertEqual(result['ACCcstime'], '36002')

    def test_that_breakup_pattern_of_logline5_is_parsed_correctly(self):
        result = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 8)

    def test_that_group1_of_logline5_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP1, groups['group1'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 6)
        # self.assertEqual(result['domain'], '-')
        self.assertEqual(result['ip'], '118.97.95.185')
        self.assertEqual(result['client'], '-')
        self.assertEqual(result['user'], '-')
        self.assertEqual(result['timestamp'], '18/Jun/2014:06:28:01')
        self.assertEqual(result['timezone'], '+0200')

    def test_that_group2_of_logline5_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP2, groups['group2'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 3)
        self.assertEqual(result['action'], 'POST')
        self.assertEqual(result['url'], """/index2.php""")
        self.assertEqual(result['method'], 'HTTP/1.0')

    def test_that_group3_of_logline5_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP3, groups['group3'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 2)
        self.assertEqual(result['resultcode'], '200')
        self.assertEqual(result['bytes'], '62')

    def test_that_group5_of_logline5_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP5, groups['group5'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['useragent'], 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)')

    def test_that_group6_of_logline5_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP6, groups['group6'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['via'], '1.1 cakcuk:9128 (squid/2.6.STABLE21)')

    def test_that_group7_of_logline5_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP7, groups['group7'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 1)
        self.assertEqual(result['forwardedfor'], '10.178.59.222')

    def test_that_group8_of_logline5_is_parsed_correctly(self):
        groups = break_up_into_blocks(APACHE_LOG_BREAKUP_PATTERN, self.logline5)
        result = break_up_into_blocks(APACHE_LOG_PATTERN_GROUP8, groups['group8'])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 7)
        self.assertEqual(result['percenta'], '118.97.95.185')
        self.assertEqual(result['pid'], '4198')
        self.assertEqual(result['percentD'], '473776')
        self.assertEqual(result['ACCutime'], '0')
        self.assertEqual(result['ACCstime'], '8000')
        self.assertEqual(result['ACCcutime'], '120007')
        self.assertEqual(result['ACCcstime'], '68004')
