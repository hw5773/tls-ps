PWD=`pwd`
echo $PWD
export LD_LIBRARY_PATH=$PWD/../tlsps-lib:$PWD/../openssl/lib
./mosquitto_tlsps_sub -t hello --cafile ../certs/demoCA/cacert.pem -h www.rsa.com --key ../certs/subscriber5_priv.pem --cert ../certs/subscriber5_pub.pem
