curl --location --request POST 'http://192.168.110.139:8080/api/manual/rules' \
--header 'Content-Type: application/json' \
--data-raw '{
    "value": "192.168.110.138"
}' 

# curl --location --request POST 'http://192.168.110.139:8080/api/manual/rules' \
# --header 'Content-Type: application/json' \
# --data-raw '{
#     "value": "192.168.110.1/24"
# }'  | jq

