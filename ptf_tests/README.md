# P4OVS tests using PTF framework

---

# Introduction

PTF is a Python based dataplane test framework. It is based on unittest, which
is included in the standard Python distribution. 
More details on PTF: https://github.com/p4lang/ptf 

This document is meant to provide a step by step guide on how to run the p4ovs tests using the ptf framework

---

# Directory Structure

The following directory structure is a pre-requisite to run the tests. All steps should be run from the main directory, ptf_tests.

<pre>
'''
.
├── common
│   ├── config
│   │   └── l3_exact_match_dst_ip_tap.json
│   ├── __init__.py
│   ├── lib
│   │   ├── __init__.py
│   │   └── ovs_p4ctl.py
│   ├── p4c_artifacts
│   │   └── l3_exact_match_dst_ip
│   │       ├── p4Info.txt
│   │       └── simple_l3.pb.bin
│   └── utils
│       ├── __init__.py
│       └── ovsp4ctl_utils.py
├── __init__.py
├── pre_test.sh
├── requirements.txt
└── tests
    ├── __init.py__
    └── l3_exact_match_dst_ip_with_tap_port.py

'''
</pre>

---

# Pre-requisite

P4OVS and P4SDE should be installed before running the tests

---

# Installing Dependencies

~ cd <ptf_tests>

~ python3 -m pip install -r requirements.txt

# Pre Test

~ source pre_test.sh <SDE_INSTALL_PATH> <P4OVS_INSTALL_PATH> [P4OVS_DEPS_INSTALL_PATH]

# Running the test

~ ptf --test-dir tests/ <test_script_name_without_extension> --pypath $PWD --test-params="config_json='<config json file name>'" --platform=dummy

E.g. ptf --test-dir tests/ l3_exact_match_with_tap_port --pypath $PWD --test-params="config_json='l3_exact_match.json'" --platform=dummy


# Post Test

[TBD]

# Reading Results

## Log File
All logs can be found at ptf_tests/ptf.log

## Console Output

Individual steps start with "PASS" or "FAIL" which shows their execution status.

E.g.

FAIL: ovs-p4ctl set pipe Failed with error: P4Runtime RPC error (FAILED_PRECONDITION): Only a single forwarding pipeline can be pushed for any node so far.

Scenario1 : l3 exact match with destination IP

Adding rule for port 0 and 1 with destination IP

PASS: ovs-p4ctl add entry: headers.ipv4.dst_addr=1.1.1.1,action=ingress.send(0)

PASS: ovs-p4ctl add entry: headers.ipv4.dst_addr=1.1.1.2,action=ingress.drop(1)

Test has PASSED


## Consolidated output
[TBD]

---
