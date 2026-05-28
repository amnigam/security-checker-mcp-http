export AWS_REGION=ap-south-1

aws secretsmanager create-secret \
  --name security-checker/mcp-auth-token \
  --secret-string "$(openssl rand -hex 24)" \
  --region $AWS_REGION
# copy the full returned ARN (ends with a -XXXXXX suffix) into
# deploy/express-primary-container.json under secrets[0].valueFrom
