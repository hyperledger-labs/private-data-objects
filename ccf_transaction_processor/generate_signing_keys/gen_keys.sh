# Copy KEYs for test
cp ../CCF/build/workspace/pdo_tp_common/user1_privk.pem .
cp ../CCF/build/workspace/pdo_tp_common/user1_cert.pem .
cp ../CCF/build/workspace/pdo_tp_common/networkcert.pem .

# Copy the infra folder
cp -r ../CCF/tests/infra infra

# activate the env
source ../CCF/build/env/bin/activate

echo "start ping test : 100 pings"
python key_gen.py --host $1



