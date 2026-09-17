# The pinned bench runner (bench/RUNNER.md): a c7i.2xlarge that is STOPPED between runs.
# bench-runner.yml starts it through the release role; the box shuts itself down after 20 idle
# minutes (instance_initiated_shutdown_behavior = stop), so a failed workflow never leaves it running.
data "aws_ssm_parameter" "ubuntu_2404" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

resource "aws_iam_role" "bench_runner" {
  name = "omium-mark1-bench-runner"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = { Service = "ci", Purpose = "instance role of the pinned bench runner - SSM access plus the one-shot registration token" }
}

resource "aws_iam_role_policy_attachment" "bench_runner_ssm" {
  role       = aws_iam_role.bench_runner.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# The GitHub registration token is a 1-hour secret written to this parameter right before the first
# boot and deleted after; the runner keeps its own credentials in /opt/runner from then on.
resource "aws_iam_role_policy" "bench_runner_token" {
  name = "registration-token"
  role = aws_iam_role.bench_runner.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "ssm:GetParameter", Resource = "arn:aws:ssm:us-east-1:${local.account_id}:parameter/omium/mark1/bench-runner/registration-token" }]
  })
}

resource "aws_iam_instance_profile" "bench_runner" {
  name = "omium-mark1-bench-runner"
  role = aws_iam_role.bench_runner.name
}

resource "aws_security_group" "bench_runner" {
  name        = "omium-mark1-bench-runner"
  description = "Pinned bench runner: egress only (GitHub, SSM, crates.io via the NAT)"
  vpc_id      = data.terraform_remote_state.platform.outputs.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Service = "ci" }
}

resource "aws_instance" "bench_runner" {
  ami                                  = data.aws_ssm_parameter.ubuntu_2404.value
  instance_type                        = "c7i.2xlarge"
  subnet_id                            = data.terraform_remote_state.platform.outputs.private_subnets[0]
  vpc_security_group_ids               = [aws_security_group.bench_runner.id]
  iam_instance_profile                 = aws_iam_instance_profile.bench_runner.name
  instance_initiated_shutdown_behavior = "stop"
  user_data                            = file("${path.module}/bench_runner_cloud_init.sh")

  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    volume_type = "gp3"
    volume_size = 100
    encrypted   = true
  }
  # A new AMI or a cloud-init edit must not replace a registered runner; rebuild deliberately with taint.
  lifecycle {
    ignore_changes = [ami, user_data]
  }
  tags = {
    Name    = "omium-mark1-bench-runner"
    Service = "ci"
    Purpose = "pinned bench runner (bench/RUNNER.md) - started only by bench-runner.yml; self-stops when idle"
  }
}

output "bench_runner_instance_id" {
  description = "Set as repo variable MARK1_BENCH_INSTANCE_ID"
  value       = aws_instance.bench_runner.id
}
