#!/bin/bash

username=root@openhim.org;
pass=password;

auth=`curl -k -s -H "Accept: application/json" -H "Content-Type: application/json" -X GET https://10.0.0.1:8080/authenticate/root@openhim.org`;
salt=`echo $auth | perl -pe 's|.*"salt":"(.*?)".*|\1|'`;
ts=`echo $auth | perl -pe 's|.*"ts":"(.*?)".*|\1|'`;

passhash=`echo -n "$salt$pass" | shasum -a 512 | awk '{print $1}'`;
token=`echo -n "$passhash$salt$ts" | shasum -a 512 | awk '{print $1}'`;


#echo "";

channelId='5ad5b728b907335f9b5c0628';
#jsonString='{"routes":[{"host":"10.0.0.3"}]}';
#jsonString='{"name":"Tutorial Channel"}'

#channelOriginal=`curl -k -H "auth-username: $username" -H "auth-ts: $ts" -H "auth-salt: $salt" -H "auth-token: $token" -X GET https://10.0.0.1:8080/channels/$channelId`

#jsonString='{"_id":"59f9bbd0dbfde616b6cecd1e","requestBody":true,"responseBody":true,"name":"\"Tutorial%20Channel\"","urlPattern":"^/encounters/.*$","matchContentRegex":null,"matchContentXpath":null,"matchContentValue":null,"matchContentJson":null,"pollingSchedule":null,"tcpHost":null,"tcpPort":null,"__v":0,"autoRetryPeriodMinutes":60,"autoRetryEnabled":false,"rewriteUrlsConfig":[],"addAutoRewriteRules":true,"rewriteUrls":false,"status":"enabled","alerts":[],"txRerunAcl":[],"txViewFullAcl":[],"txViewAcl":[],"properties":[],"matchContentTypes":[],"routes":[{"name":"Tutorial%20Route","secured":false,"host":"10.0.0.3","port":3444,"path":"","pathTransform":"","primary":true,"username":"","password":"","_id":"59f9bbd0dbfde616b6cecd1f","forwardAuthHeader":false,"status":"enabled","type":"http"}],"authType":"private","whitelist":[],"allow":["tut"],"type":"http"}'

#echo https://10.0.0.1:8080/channels/:$channelId
#curl -k -g -H "auth-username: $username" -H "auth-ts: $ts" -H "auth-salt: $salt" -H "auth-token: $token" -H 'Content-Type: application/json' -H 'Accept: application/json' -X GET 'https://10.0.0.1:8080/channels'

#curl -k -i 'https://10.0.0.1:8080/channels/:$channelId' -X PUT -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/json;charset=utf-8' -H "auth-username: $username" -H "auth-ts: $ts" -H "auth-salt: $salt" -H "auth-token: $token" --data '{"_id":"59f9bbd0dbfde616b6cecd1e","requestBody":true,"responseBody":true,"name":"Tutorial Channel","urlPattern":"^/encounters/.*$","matchContentRegex":null,"matchContentXpath":null,"matchContentValue":null,"matchContentJson":null,"pollingSchedule":null,"tcpHost":null,"tcpPort":null,"__v":0,"autoRetryPeriodMinutes":60,"autoRetryEnabled":false,"rewriteUrlsConfig":[],"addAutoRewriteRules":true,"rewriteUrls":false,"status":"enabled","alerts":[],"txRerunAcl":[],"txViewFullAcl":[],"txViewAcl":[],"properties":[],"matchContentTypes":[],"routes":[{"name":"Tutorial Route","secured":false,"host":"10.0.0.3","port":3444,"path":"","pathTransform":"","primary":true,"username":"","password":"","_id":"59f9bbd0dbfde616b6cecd1f","forwardAuthHeader":false,"status":"enabled","type":"http"}],"authType":"private","whitelist":[],"allow":["tut"],"type":"http"}'

# string='{"_id":"5ad5b728b907335f9b5c0628","requestBody":true,"responseBody":true,"name":"Tutorial Channel","urlPattern":"^/encounters/.*$","matchContentRegex":null,"matchContentXpath":null,"matchContentValue":null,"matchContentJson":null,"pollingSchedule":null,"tcpHost":null,"tcpPort":null,"__v":0,"autoRetryPeriodMinutes":60,"autoRetryEnabled":false,"rewriteUrlsConfig":[],"addAutoRewriteRules":true,"rewriteUrls":false,"status":"enabled","alerts":[],"txRerunAcl":[],"txViewFullAcl":[],"txViewAcl":[],"properties":[],"matchContentTypes":[],"routes":[{"_id":"59f9bbd0dbfde616b6cecd1f","password":"","username":"","primary":true,"pathTransform":"","path":"","port":3444,"host":"10.0.0.2","secured":false,"name":"Tutorial Route","forwardAuthHeader":false,"status":"enabled","type":"http"}],"authType":"private","whitelist":[],"allow":["tut"],"type":"http"}'
# chnlOrig=`curl -k -i "https://10.0.0.1:8080/channels" -X GET -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/json;charset=utf-8' -H "auth-username: $username" -H "auth-ts: $ts" -H "auth-salt: $salt" -H "auth-token: $token" -H 'Connection: keep-alive'`
# echo $chnlOrig
# echo $string

curl -k -i "https://10.0.0.1:8080/channels/$channelId" -X PUT -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/json;charset=utf-8' -H "auth-username: $username" -H "auth-ts: $ts" -H "auth-salt: $salt" -H "auth-token: $token" -H 'Connection: keep-alive' --data '{"_id":"5ad5b728b907335f9b5c0628","requestBody":true,"responseBody":true,"name":"Tutorial Channel","urlPattern":"^/encounters/.*$","matchContentRegex":null,"matchContentXpath":null,"matchContentValue":null,"matchContentJson":null,"pollingSchedule":null,"tcpHost":null,"tcpPort":null,"__v":0,"autoRetryPeriodMinutes":60,"autoRetryEnabled":false,"rewriteUrlsConfig":[],"addAutoRewriteRules":true,"rewriteUrls":false,"status":"enabled","alerts":[],"txRerunAcl":[],"txViewFullAcl":[],"txViewAcl":[],"properties":[],"matchContentTypes":[],"routes":[{"_id":"59f9bbd0dbfde616b6cecd1f","password":"","username":"","primary":true,"pathTransform":"","path":"","port":3444,"host":"10.0.0.2","secured":false,"name":"Tutorial Route","forwardAuthHeader":false,"status":"enabled","type":"http"}],"authType":"private","whitelist":[],"allow":["tut"],"type":"http"}';