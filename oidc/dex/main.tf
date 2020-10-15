resource "aws_key_pair" "ssh-key" {
  key_name_prefix = "dex"
  public_key      = file("~/.ssh/id_rsa.pub")
}

locals {
  dex-config = {
    record-name      = "dex"
    domain-name      = "dex.jreus.xyz"
    dex-home-path    = "/home/ubuntu/dex"
    gitlab-client-id = var.gitlab-client-id
    gitlab-secret    = var.gitlab-secret
    gitlab-groups    = var.gitlab-groups
  }
}

resource "aws_eip_association" "eip_assoc" {
  instance_id   = aws_instance.dex.id
  allocation_id = data.aws_eip.selected.id
}

resource "aws_instance" "dex" {
  ami                    = data.aws_ami.ubuntu.id
  vpc_security_group_ids = [aws_security_group.allow_dex.id]
  key_name               = aws_key_pair.ssh-key.key_name
  instance_type          = "t3.micro"

  provisioner "remote-exec" {
    inline = ["mkdir -p /home/ubuntu/dex"]
    connection {
      type = "ssh"
      user = "ubuntu"
      host = self.public_ip
    }
  }

  provisioner "file" {
    content     = templatefile("./templates/dex-server-config.yml", local.dex-config)
    destination = "${local.dex-config.dex-home-path}/server-config.yaml"
    connection {
      type = "ssh"
      user = "ubuntu"
      host = self.public_ip
    }
  }

  provisioner "file" {
    source      = "certs"
    destination = "${local.dex-config.dex-home-path}/certs"
    connection {
      type = "ssh"
      user = "ubuntu"
      host = self.public_ip
    }
  }
}

resource "null_resource" "provisioner" {
  depends_on = [aws_instance.dex]
  provisioner "remote-exec" {
    script = "${path.root}/init.sh"
    connection {
      type = "ssh"
      user = "ubuntu"
      host = data.aws_eip.selected.public_ip
    }
  }
}
