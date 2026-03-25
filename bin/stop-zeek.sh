#!/bin/bash
export PATH="/opt/zeek/bin:$PATH"
/opt/zeek/bin/zeekctl stop 2>/dev/null || true
