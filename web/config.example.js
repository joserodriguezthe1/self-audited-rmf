// Example only. Terraform renders the real config.js from config.js.tftpl (terraform/web.tf).
window.SAS_CONFIG = {
  cognitoDomain: "https://REPLACE.auth.us-east-1.amazoncognito.com", // Cognito > User pool > Domain
  clientId: "REPLACE_APP_CLIENT_ID",                                 // Cognito > App clients
  redirectUri: "https://REPLACE.cloudfront.net/",                     // CloudFront domain, with trailing slash
  apiUrl: "https://REPLACE.execute-api.us-east-1.amazonaws.com"       // API Gateway invoke URL, no trailing slash
};
