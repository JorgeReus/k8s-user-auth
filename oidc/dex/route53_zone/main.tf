resource "aws_route53_zone" "primary" {
  name = var.zone_name
}

resource "aws_eip" "lb" {
  vpc = true

  tags = {
    service_name = "dex"
  }
}

resource "aws_route53_record" "www" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "dex"
  type    = "A"
  ttl     = "300"
  records = [aws_eip.lb.public_ip]
}
