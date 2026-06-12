./pcap-gen --count 100000 --cores 4 --rate 0 \
    | python3 test-json.py --count 100000 --expected-cores 4

date +%s%6N
jq .timestamp ./json-samples/sample_100000.json