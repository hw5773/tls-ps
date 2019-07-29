export LD_LIBRARY_PATH=/home/hwlee/drive/tls-ps/tlsps-lib:/home/hwlee/drive/tls-ps/openssl/lib
./mosquitto_tlsps_sub -t hello --cafile ../certs/demoCA/cacert.pem -h www.rsa.com --key ../certs/subscriber_priv.pem --cert ../certs/subscriber_pub.pem
