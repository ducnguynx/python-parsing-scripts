

file_us=$(stat -c %Y ./json-samples/sample_10000.json)
json_us=$(jq .timestamp ./json-samples/sample_10000.json)
echo $(( file_us * 1000000 - json_us ))

