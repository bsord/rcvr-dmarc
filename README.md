
## Build the dmarc processor service
```docker build -t rcvr-dmarc .```

## Start the dmarc processor service
```docker run -d --name rcvr-dmarc --network rcvr-net -e "SQLDSN=rcvr-dbuser:receiverdbpassword@tcp(rcvr-db:3306)/rcvr-db?readTimeout=10s&writeTimeout=10s" -e REDISHOST=rcvr-queue --restart always rcvr-dmarc```
# rcvr-dmarc
# rcvr-dmarc
