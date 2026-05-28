AWS_REGION=ap-south-1                      # your region
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

aws ecs create-express-gateway-service \
  --service-name security-checker-mcp \
  --execution-role-arn arn:aws:iam::$ACCOUNT:role/ecsTaskExecutionRole \
  --infrastructure-role-arn arn:aws:iam::$ACCOUNT:role/ecsInfrastructureRoleForExpressServices \
  --health-check-path /healthz \
  --primary-container file://express-primary-container.json \
  --monitor-resources \
  --region $AWS_REGION