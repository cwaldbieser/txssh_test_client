#! /usr/bin/env python

from __future__ import print_function
import sys
import time

def main():
    """
    act like `cat`, but delayed.
    """
    time.sleep(10)
    for line in sys.stdin:
        print(line, end='')
    
if __name__ == "__main__":
    main()
