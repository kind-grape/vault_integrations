export instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
export region=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -c -r .region)
export is_active=$(curl --silent -k $VAULT_ADDR/v1/sys/leader | jq -r .is_self)
if if_active==true; then
    echo 'this is active node, tag second'
    aws ec2 create-tags --region $region --resources $instance_id --tags Key='Patch Group',Value='prd-rhel-security-critical-second'
else
    echo 'this is passive node, tag first'
    aws ec2 create-tags --region $region --resources $instance_id --tags Key='Patch Group',Value='prd-rhel-security-critical-first'
fi
