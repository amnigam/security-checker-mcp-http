REAL_ARN=$(aws secretsmanager describe-secret --secret-id security-checker/mcp-auth-token \
  --query ARN --output text --region ap-south-1)

sed -i "s#arn:aws:secretsmanager:ap-south-1:389192019675:secret:security-checker/mcp-auth-token-XXXXXX#$REAL_ARN#" express-primary-container.json

grep valueFrom express-primary-container.json    # should now show the real suffix, not XXXXXX
