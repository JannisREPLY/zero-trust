###############################################
# PRINCIPLE #5 - Zero Trust Access
###############################################
/*
resource "aws_lb_listener_rule" "oidc_auth_rule" {
  listener_arn = aws_lb_listener.alb_https_listener.arn
  priority     = 100

  # Conditions determine when this rule applies. In this case,
  # you might require a specific host header.
  condition {
    host_header {
      values = ["example.com"]
    }
  }

  action {
    type = "authenticate-oidc"

    authenticate_oidc {
      authorization_endpoint = "https://example.com/authorization_endpoint"
      client_id              = "client_id"
      client_secret          = "client_secret"
      issuer                 = "https://example.com"
      token_endpoint         = "https://example.com/token_endpoint"
      user_info_endpoint     = "https://example.com/user_info_endpoint"
    }
  }

  # After successful authentication, forward the request to the target group.
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tg.arn
  }
}
*/