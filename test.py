#!/usr/bin/env python
from lib.apachelog import analyze_log


if __name__ == '__main__':
    log = 'fixtures/access.log'
    log = 'fixtures/webaccess.log'
    analyze_log(log)
