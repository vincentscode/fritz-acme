import os

from config import domain, cf_token, cf_account_id, cf_zone_id, out_path

acme_args =  f' --issue'
acme_args +=  f' --dns dns_cf'
acme_args +=  f' -d "{domain}"'
acme_args += f' --server  letsencrypt'

env =  f' -e CF_Token="{cf_token}"'
env += f' -e CF_Account_ID="{cf_account_id}"'
env += f' -e CF_Zone_ID="{cf_zone_id}"'

cmd = f'docker run --rm {env} -it -v "$(pwd)/{out_path}":/acme.sh neilpang/acme.sh {acme_args}'


if __name__ == '__main__':
	resp = os.popen(cmd).read()
	print("ACME", resp)
    
    cert_path = f"{out_path}/{domain}/{domain}.cer"
    with open(cert_path) as cert_file:
        cert = cert_file.read()

    key_path = f"{out_path}/{domain}/{domain}.key"
    with open(key_path) as key_file:
        key = key_file.read()

    result = upload_key_cert(key, cert)
    print("Upload", result)