# Terraform code for a standalone dex server in AWS EC2

### Directory Layout
- [certs](certs) Directory for the PKI used by this dex instance
- [route53\_zone](route53_zone) Directory for the route53 zone terraform code
- [scripts](scripts) General scripts for the dex instance
- [templates](templates) Templates for the dex instance config

### How to run 
1. First fill the variables for terraform in the route53\_zone dir
2. Do a `terraform apply` in route53\_zone dir (The generated nameservers for the zone should be your preferred dns provider i.e (Godaddy, namecheap, etc))
3. Fill the terraform variables in this dir
4. Generate the PKI in the certs dir with the script certs.sh (i.e. ./certs.sh)
5. Do a `terraform apply` in this dir
6. You can verify that dex is working with  `http --verify=no https://YOUR.DOMAIN.NAME/dex/.well-known/openid-configuration`
7. Be happy :grin:
