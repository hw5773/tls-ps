PWD=`pwd`
echo $PWD
export LD_LIBRARY_PATH=$PWD/../tlsps-lib:$PWD/../openssl/lib
./mosquitto_tlsps_sub -t hello --cafile ../certs/demoCA/cacert.pem -h www.rsa.com --key ../certs/subscriber8_priv.pem --cert ../certs/subscriber8_pub.pem
