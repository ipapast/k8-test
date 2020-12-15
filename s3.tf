/* s3_state.tf
    S3 bucket for terraform state files
*/

locals {
  binary_bucket_name                                      = "ob-binary-bucket-${var.region}-${var.acc_short_name}"
  s3_server_access_logs_bucket_name                       = "ob-s3-server-access-logs-${var.region}-${var.acc_short_name}"
  ssm_inspec_bucket_name                                  = "ob-ssm-inspec-bucket-${var.region}-${var.acc_short_name}"
  elb_access_logs_bucket_name                             = "ob-elb-access-logs-${var.region}-${var.acc_short_name}"
  cloudfront_logs_bucket_name                             = "ob-cloudfront-logs-${var.region}-${var.acc_short_name}"
  cmdb_bucket_name                                        = "ob-cmdb-bucket-${var.acc_short_name}"
  session_manager_bucket_name                             = "ob-session-manager-${var.region}-${var.acc_short_name}"
  common_lambda_bucket_name                               = "ob-common-lambda-${var.acc_short_name}"
  state_manager_output_bucket_name                        = "ob-state-manager-output-${var.acc_short_name}"
  pingone_wiam_user_detailed_status_report_bucket_name    = "ob-wiam-user-status-report-${var.acc_short_name}"
  splunk_cloud_log_storage_bucket_name                    = "openbanking-m6prj01czuxx-scls-${var.acc_short_name}"
  splunk_config_bucket_name                               = "ob-sccs-${var.acc_short_name}"
  splunk_vpc_endpoint                                     = "vpce-6505c50c"
  dev_data_bucket_name                                    = "ob-ddtfr-${var.acc_short_name}"
  log_backups_bucket_name                                 = "ob-instance-log-backups-${var.acc_short_name}"
}

#
# S3 bucket for storing binaries.
#
resource "aws_s3_bucket" "binary_bucket" {
  count  = "${var.binary_bucket_enabled}"
  bucket = "${local.binary_bucket_name}"
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"
    target_prefix = "${local.binary_bucket_name}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.ob_binary_bucket_kms_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = "${var.tags}"
}

data "aws_iam_policy_document" "ob_binary_bucket_policy_document" {
  statement {
    sid    = "AllowReadOnly"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${formatlist("arn:aws:iam::%s:root", "${var.all_accounts}")}"
    }

    actions = ["s3:GetObject", "s3:ListBucket"]

    resources = [
      "arn:aws:s3:::${local.binary_bucket_name}/*",
      "arn:aws:s3:::${local.binary_bucket_name}",
    ]
  }

  statement {
    sid    = "AllowTerraform"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ]
    }

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::${local.binary_bucket_name}",
      "arn:aws:s3:::${local.binary_bucket_name}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "ob_binary_bucket_policy" {
  count  = "${var.binary_bucket_enabled}"
  bucket = "${local.binary_bucket_name}"
  policy = "${data.aws_iam_policy_document.ob_binary_bucket_policy_document.json}"
}

resource "aws_kms_key" "ob_binary_bucket_kms_key" {
  count               = "${var.binary_bucket_enabled}"
  description         = "${local.binary_bucket_name}"
  key_usage           = "ENCRYPT_DECRYPT"
  is_enabled          = true
  enable_key_rotation = false

  policy = "${data.aws_iam_policy_document.ob_binary_bucket_kms_key_policy_document.json}"

  tags {
    Name = "${local.binary_bucket_name}"
  }
}

resource "aws_kms_alias" "ob_binary_bucket_kms_key_alias" {
  count         = "${var.binary_bucket_enabled}"
  name          = "alias/${local.binary_bucket_name}"
  target_key_id = "${aws_kms_key.ob_binary_bucket_kms_key.key_id}"
}

data "aws_iam_policy_document" "ob_binary_bucket_kms_key_policy_document" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"]
    }

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"),list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ))}"
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]

    resources = ["*"]
  }
}

#
# S3 bucket for storing s3 server access logs.
#
resource "aws_s3_bucket" "s3_server_access_logs_bucket" {
  bucket = "${local.s3_server_access_logs_bucket_name}"
  acl    = "log-delivery-write"

  // Everything in the log bucket rotates to infrequent access and expires.
  lifecycle_rule {
    id      = "log_expiration"
    prefix  = ""
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = "${var.s3_log_expiration_days}"
    }

    // Old/deleted object versions are permanently removed after 1 day.
    noncurrent_version_expiration {
      days = 1
    }
  }

  logging {
    target_bucket = "${local.s3_server_access_logs_bucket_name}"
    target_prefix = "${local.s3_server_access_logs_bucket_name}/"
  }

  tags = "${var.tags}"
}

// resource "aws_s3_bucket_notification" "s3_server_access_logs_bucket_notification" {
//   bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"

//   queue {
//     id        = "splunk_sqs"
//     queue_arn = "${aws_sqs_queue.splunk_s3_access_logs_queue.arn}"
//     events    = ["s3:ObjectCreated:*"]
//   }
// }

#
# S3 bucket for storing elb access logs.
#
resource "aws_s3_bucket" "elb_logs_bucket" {
  bucket = "${local.elb_access_logs_bucket_name}"
  acl    = "log-delivery-write"

  # Everything in the log bucket rotates to infrequent access and expires.
  lifecycle_rule {
    id      = "log_expiration"
    prefix  = ""
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = "${var.s3_log_expiration_days}"
    }

    # Old/deleted object versions are permanently removed after 1 day.
    noncurrent_version_expiration {
      days = 1
    }
  }

  logging {
    target_bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"
    target_prefix = "${local.elb_access_logs_bucket_name}/"
  }

  tags = "${var.tags}"
}

resource "aws_s3_bucket_notification" "elb_logs_bucket_notification" {
  bucket = "${aws_s3_bucket.elb_logs_bucket.id}"

  queue {
    id        = "splunk_sqs"
    queue_arn = "${aws_sqs_queue.splunk_elb_logs_queue.arn}"
    events    = ["s3:ObjectCreated:*"]
  }
}

resource "aws_s3_bucket_policy" "elb_logs_bucket_policy" {
  bucket = "${aws_s3_bucket.elb_logs_bucket.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow Load Balancers to push logs on this bucket",
      "Action": [
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.elb_logs_bucket.arn}/*",
      "Principal": {
        "AWS": [
          "${var.lb_account_id}"
        ]
      }
    }
  ]
}
POLICY
}

#
# S3 bucket for storing cloudfront logs.
#
resource "aws_s3_bucket" "cloudfront_logs_bucket" {
  count  = "${var.cloudfront_bucket_enabled}"
  bucket = "${local.cloudfront_logs_bucket_name}"
  acl    = "log-delivery-write"

  # Everything in the log bucket rotates to infrequent access and expires.
  lifecycle_rule {
    id      = "log_expiration"
    prefix  = ""
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = "${var.s3_log_expiration_days}"
    }

    # Old/deleted object versions are permanently removed after 1 day.
    noncurrent_version_expiration {
      days = 1
    }
  }

  logging {
    target_bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"
    target_prefix = "${local.cloudfront_logs_bucket_name}/"
  }

  tags = "${var.tags}"
}

resource "aws_s3_bucket_policy" "cloudfront_logs_bucket_policy" {
  count  = "${var.cloudfront_bucket_enabled}"
  bucket = "${aws_s3_bucket.cloudfront_logs_bucket.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow Cloudfront to push logs on this bucket",
      "Action": [
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.cloudfront_logs_bucket.arn}/*",
      "Principal": {
        "Service": [
          "cloudfront.amazonaws.com"
        ]
      }
    }
  ]
}
POLICY
}

#
# S3 bucket for SSM InSpec Checks
#
resource "aws_s3_bucket" "ssm_inspec_bucket" {
  count  = "${var.ssm_inspec_bucket_enabled}"
  bucket = "${local.ssm_inspec_bucket_name}"
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"
    target_prefix = "${local.ssm_inspec_bucket_name}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.ob_ssm_inspec_bucket_kms_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = "${var.tags}"
}

data "aws_iam_policy_document" "ob_ssm_inspec_bucket_policy_document" {
  statement {
    sid    = "AllowReadOnly"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${formatlist("arn:aws:iam::%s:root", "${var.all_accounts}")}"
    }

    actions = ["s3:GetObject", "s3:ListBucket"]

    resources = [
      "arn:aws:s3:::${local.ssm_inspec_bucket_name}/*",
      "arn:aws:s3:::${local.ssm_inspec_bucket_name}",
    ]
  }

  statement {
    sid    = "AllowTerraform"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ]
    }

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::${local.ssm_inspec_bucket_name}",
      "arn:aws:s3:::${local.ssm_inspec_bucket_name}/*",
    ]
  }

  statement {
    sid    = "AllowJenkinsAgent"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_ssm_agent_role}",
      ]
    }

    actions = ["s3:Put*"]

    resources = [
      "arn:aws:s3:::${local.ssm_inspec_bucket_name}",
      "arn:aws:s3:::${local.ssm_inspec_bucket_name}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "ob_ssm_inspec_bucket_policy" {
  count  = "${var.ssm_inspec_bucket_enabled}"
  bucket = "${local.ssm_inspec_bucket_name}"
  policy = "${data.aws_iam_policy_document.ob_ssm_inspec_bucket_policy_document.json}"
}

resource "aws_kms_key" "ob_ssm_inspec_bucket_kms_key" {
  count               = "${var.ssm_inspec_bucket_enabled}"
  description         = "${local.ssm_inspec_bucket_name}"
  key_usage           = "ENCRYPT_DECRYPT"
  is_enabled          = true
  enable_key_rotation = false

  policy = "${data.aws_iam_policy_document.ob_ssm_inspec_bucket_kms_key_policy_document.json}"

  tags {
    Name = "${local.ssm_inspec_bucket_name}"
  }
}

resource "aws_kms_alias" "ob_ssm_inspec_bucket_kms_key_alias" {
  count         = "${var.ssm_inspec_bucket_enabled}"
  name          = "alias/${local.ssm_inspec_bucket_name}"
  target_key_id = "${aws_kms_key.ob_ssm_inspec_bucket_kms_key.key_id}"
}

data "aws_iam_policy_document" "ob_ssm_inspec_bucket_kms_key_policy_document" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"]
    }

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_ssm_agent_role}",
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"), list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"
      ))}"
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]

    resources = ["*"]
  }
}

#
# S3 bucket for storing binaries.
#
resource "aws_s3_bucket" "cmdb_bucket" {
  count  = "${var.cmdb_bucket_enabled}"
  bucket = "${local.cmdb_bucket_name}"
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"
    target_prefix = "${local.cmdb_bucket_name}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.ob_cmdb_bucket_kms_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = "${var.tags}"
}

data "aws_iam_policy_document" "ob_cmdb_bucket_policy_document" {
  statement {
    sid    = "AWSConfigAndSSMBucketPermissionsCheck"
    effect = "Allow"

    principals {
      type = "Service"

      identifiers = [
        "config.amazonaws.com",
        "ssm.amazonaws.com",
      ]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${local.cmdb_bucket_name}"]
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"

    principals {
      type = "Service"

      identifiers = [
        "config.amazonaws.com",
      ]
    }

    actions   = ["s3:PutObject"]
    resources = "${formatlist("arn:aws:s3:::%s/AWSLogs/%s/Config/*", "${local.cmdb_bucket_name}", "${var.all_accounts}")}"

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }

  statement {
    sid    = "SSMBucketDelivery"
    effect = "Allow"

    principals {
      type = "Service"

      identifiers = [
        "ssm.amazonaws.com",
      ]
    }

    actions = ["s3:PutObject"]

    resources = "${formatlist("arn:aws:s3:::%s/*/accountid=%s/*", "${local.cmdb_bucket_name}", "${var.all_accounts}")}"

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }

  statement {
    sid    = "AllowTerraform"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ]
    }

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::${local.cmdb_bucket_name}",
      "arn:aws:s3:::${local.cmdb_bucket_name}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "ob_cmdb_bucket_policy" {
  count  = "${var.cmdb_bucket_enabled}"
  bucket = "${local.cmdb_bucket_name}"
  policy = "${data.aws_iam_policy_document.ob_cmdb_bucket_policy_document.json}"
}

resource "aws_kms_key" "ob_cmdb_bucket_kms_key" {
  count               = "${var.cmdb_bucket_enabled}"
  description         = "${local.cmdb_bucket_name}"
  key_usage           = "ENCRYPT_DECRYPT"
  is_enabled          = true
  enable_key_rotation = false

  policy = "${data.aws_iam_policy_document.ob_cmdb_bucket_kms_key_policy_document.json}"

  tags {
    Name = "${local.cmdb_bucket_name}"
  }
}

resource "aws_kms_alias" "ob_cmdb_bucket_kms_key_alias" {
  count         = "${var.cmdb_bucket_enabled}"
  name          = "alias/${local.cmdb_bucket_name}"
  target_key_id = "${aws_kms_key.ob_cmdb_bucket_kms_key.key_id}"
}

data "aws_iam_policy_document" "ob_cmdb_bucket_kms_key_policy_document" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"]
    }

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"), list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ))}"
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]

    resources = ["*"]
  }
}

#
# S3 bucket for session manager logs
#
resource "aws_s3_bucket" "session_manager_bucket" {
  bucket = "${local.session_manager_bucket_name}"
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"
    target_prefix = "${local.session_manager_bucket_name}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        // kms_master_key_id = "${aws_kms_key.ob_session_manager_bucket_kms_key.arn}"
        // sse_algorithm     = "aws:kms"
        sse_algorithm = "AES256"
      }
    }
  }

  tags = "${var.tags}"
}

data "aws_iam_policy_document" "ob_session_manager_bucket_policy_document" {
  statement {
    sid    = "AllowTerraform"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ]
    }

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::${local.session_manager_bucket_name}",
      "arn:aws:s3:::${local.session_manager_bucket_name}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "ob_session_manager_bucket_policy" {
  bucket = "${local.session_manager_bucket_name}"
  policy = "${data.aws_iam_policy_document.ob_session_manager_bucket_policy_document.json}"
}

resource "aws_kms_key" "ob_session_manager_bucket_kms_key" {
  description         = "${local.session_manager_bucket_name}"
  key_usage           = "ENCRYPT_DECRYPT"
  is_enabled          = true
  enable_key_rotation = false

  policy = "${data.aws_iam_policy_document.ob_session_manager_bucket_kms_key_policy_document.json}"

  tags {
    Name = "${local.session_manager_bucket_name}"
  }
}

resource "aws_kms_alias" "ob_session_manager_bucket_kms_key_alias" {
  name          = "alias/${local.session_manager_bucket_name}"
  target_key_id = "${aws_kms_key.ob_session_manager_bucket_kms_key.key_id}"
}

data "aws_iam_policy_document" "ob_session_manager_bucket_kms_key_policy_document" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"]
    }

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"), list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ))}"
    }

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]

    resources = ["*"]
  }
}

#
# Common Lambda S3 Bucket
#
data "aws_iam_policy_document" "ob_common_lambda_bucket_policy_document" {
  statement {
    sid    = "AllowReadOnly"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${formatlist("arn:aws:iam::%s:root", "${var.all_accounts}")}"
    }

    actions = ["s3:GetObject", "s3:ListBucket"]

    resources = [
      "arn:aws:s3:::${local.common_lambda_bucket_name}/*",
      "arn:aws:s3:::${local.common_lambda_bucket_name}",
    ]
  }

  statement {
    sid    = "AllowLogsWrite"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:root",
      ]
    }

    actions = ["s3:PutObject"]

    resources = [
      "arn:aws:s3:::${local.common_lambda_bucket_name}/logs/*",
    ]
  }

  statement {
    sid    = "AllowTerraform"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
        "arn:aws:iam::283114852454:role/ob-jenkins-terraform-role",      # mgmtdev
        "arn:aws:iam::482681734622:role/tops-jenkins-terraform-role",    # dev
        "arn:aws:iam::495768503152:role/tops-jenkins-terraform-role",    # ppe
        "arn:aws:iam::024762423152:role/tops-jenkins-terraform-role",    # prd
        "arn:aws:iam::608578871059:role/ob-jenkins-terraform-role",      # mgmt
      ]
    }

    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::${local.common_lambda_bucket_name}",
      "arn:aws:s3:::${local.common_lambda_bucket_name}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "ob_common_lambda_bucket_policy" {
  count  = "${var.common_lambda_bucket_enabled}"
  bucket = "${local.common_lambda_bucket_name}"
  policy = "${data.aws_iam_policy_document.ob_common_lambda_bucket_policy_document.json}"
}

resource "aws_s3_bucket" "ob_common_lambda_bucket" {
  count  = "${var.common_lambda_bucket_enabled}"
  bucket = "${local.common_lambda_bucket_name}"
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${local.common_lambda_bucket_name}"
    target_prefix = "log/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.ob_common_lambda_kms_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

data "aws_iam_policy_document" "ob_common_lambda_kms_key_policy_document" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"]
    }

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"), list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ), "${var.additional_lambda_kms_roles}")}"
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"), list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ))}"
    }

    actions = [
      "kms:RevokeGrant",
      "kms:ListGrants",
      "kms:CreateGrant",
    ]

    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"

      values = [
        "true",
      ]
    }
  }
}

resource "aws_kms_key" "ob_common_lambda_kms_key" {
  count               = "${var.common_lambda_bucket_enabled}"
  description         = "${local.common_lambda_bucket_name}"
  key_usage           = "ENCRYPT_DECRYPT"
  is_enabled          = true
  enable_key_rotation = false

  policy = "${data.aws_iam_policy_document.ob_common_lambda_kms_key_policy_document.json}"

  tags {
    Name = "${local.common_lambda_bucket_name}"
  }
}

resource "aws_kms_alias" "ob_common_lambda_kms_key_alias" {
  count         = "${var.common_lambda_bucket_enabled}"
  name          = "alias/${local.common_lambda_bucket_name}"
  target_key_id = "${aws_kms_key.ob_common_lambda_kms_key.key_id}"
}

resource "aws_s3_bucket" "state_manager_output_bucket" {
  count  = "${var.state_manager_output_bucket_enabled}"
  bucket = "${local.state_manager_output_bucket_name}"
  acl    = "private"
}

data "aws_iam_policy_document" "state_manager_output_bucket_policy" {
  statement {
    sid       = "Allow State Manager Logging"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${local.state_manager_output_bucket_name}/*"]

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "state_manager_output_bucket_policy" {
  bucket = "${aws_s3_bucket.state_manager_output_bucket.id}"
  policy = "${data.aws_iam_policy_document.state_manager_output_bucket_policy.json}"
}

#
# S3 Bucket for WIAM User Detailed Reports
#
resource "aws_kms_key" "wiam_user_detailed_reports" {
  count                        = "${var.wiam_status_reports_lambda_s3_bucket_enabled}"
  description                  = "WIAM user detailed report KMS key (S3)"
  deletion_window_in_days      = 30
  key_usage                    = "ENCRYPT_DECRYPT"
  is_enabled                   = true
  enable_key_rotation          = false

  tags {
    Name                       = "${local.pingone_wiam_user_detailed_status_report_bucket_name}"
  }
}

resource "aws_kms_alias" "wiam_user_detailed_reports" {
  count                        = "${var.wiam_status_reports_lambda_s3_bucket_enabled}"
  name                         = "alias/${local.pingone_wiam_user_detailed_status_report_bucket_name}"
  target_key_id                = "${aws_kms_key.wiam_user_detailed_reports.key_id}"
}

resource "aws_s3_bucket" "wiam_user_detailed_reports" {
  count                        = "${var.wiam_status_reports_lambda_s3_bucket_enabled}"
  bucket                       = "${local.pingone_wiam_user_detailed_status_report_bucket_name}"
  acl                          = "private"
  versioning {
    enabled                    = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # kms_master_key_id     = "${aws_kms_key.wiam_user_detailed_reports.arn}" # Commented out due to Splunk cloud limitations. To be re-reabled later on
        sse_algorithm         = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "wiam_user_detailed_reports" {
  count                       = "${var.wiam_status_reports_lambda_s3_bucket_enabled}"
  bucket                      = "${aws_s3_bucket.wiam_user_detailed_reports.id}"
  block_public_acls           = true
  block_public_policy         = true
  ignore_public_acls          = true
  restrict_public_buckets     = true
}

resource "aws_s3_bucket_policy" "wiam_user_detailed_reports" {
  count                        = "${var.wiam_status_reports_lambda_s3_bucket_enabled}"
  bucket                       = "${aws_s3_bucket.wiam_user_detailed_reports.id}"
  policy                       = <<POLICY
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Action": [
               "s3:Get*",
               "s3:List*"
           ],
           "Effect": "Allow",
           "Resource": [
               "arn:aws:s3:::${local.pingone_wiam_user_detailed_status_report_bucket_name}",
               "arn:aws:s3:::${local.pingone_wiam_user_detailed_status_report_bucket_name}/*"
           ],
           "Principal": {
               "AWS": [
                 "arn:aws:iam::608578871059:role/OB_DevOps_Role",
                 "arn:aws:iam::608578871059:role/OB_SOC_Role"
               ]
           },
           "Condition": {
             "IpAddress": {
               "aws:SourceIp": [
                 "31.221.31.169/32"
               ]
             }
           }
       },
       {
           "Action": [
               "s3:Get*",
               "s3:List*"
           ],
           "Effect": "Allow",
           "Resource": [
               "arn:aws:s3:::${local.pingone_wiam_user_detailed_status_report_bucket_name}",
               "arn:aws:s3:::${local.pingone_wiam_user_detailed_status_report_bucket_name}/*"
           ],
           "Principal": {
               "AWS": [
                 "arn:aws:iam::630172805352:role/openbanking"
               ]
           },
           "Condition": {
             "StringEquals": {
               "aws:sourceVpce": [
                 "${local.splunk_vpc_endpoint}"
               ]
             }
           }
       }
   ]
}
POLICY
}


resource "aws_s3_bucket_notification" "wiam_user_detailed_reports" {
  count                       = "${var.wiam_status_reports_lambda_s3_bucket_enabled}"
  bucket                      = "${aws_s3_bucket.wiam_user_detailed_reports.id}"

  queue {
    queue_arn                 = "${aws_sqs_queue.wiam_user_detailed_reports.arn}"
    events                    = [ "s3:ObjectCreated:*", "s3:ObjectRemoved:*" ]
  }
}

#
# S3 Buckets for Splunk
#

# Splunk logs bucket
resource "aws_kms_key" "splunk_cloud_logs_storage" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  description                  = "Splunk Cloud Log Storage KMS key (S3)"
  deletion_window_in_days      = 30
  key_usage                    = "ENCRYPT_DECRYPT"
  is_enabled                   = true
  enable_key_rotation          = true
  policy                       = "${data.aws_iam_policy_document.splunk_cloud_logs_storage.json}"

  tags {
    Name                       = "${local.splunk_cloud_log_storage_bucket_name}"
  }
}

data "aws_iam_policy_document" "splunk_cloud_logs_storage" {
  statement {
    sid    = "key-default-1"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::${var.account_id}:root",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
        "arn:aws:iam::${var.account_id}:role/OB_SOC_Role"
      ]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow splunk cloud account"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::630172805352:role/openbanking"
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }
}


resource "aws_kms_alias" "splunk_cloud_logs_storage" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  name                         = "alias/${local.splunk_cloud_log_storage_bucket_name}"
  target_key_id                = "${aws_kms_key.splunk_cloud_logs_storage.key_id}"
}

resource "aws_s3_bucket" "splunk_cloud_logs_storage" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  bucket                       = "${local.splunk_cloud_log_storage_bucket_name}"
  acl                          = "private"

  tags {
    Description                = "S3 bucket for Splunk Cloud log data storage"
    Environment                = "${var.acc_short_name}"
  }
  versioning {
    enabled                    = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm          = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "splunk_cloud_logs_storage" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  bucket                       = "${aws_s3_bucket.splunk_cloud_logs_storage.id}"
  block_public_acls            = true
  block_public_policy          = true
  ignore_public_acls           = true
  restrict_public_buckets      = true
}

resource "aws_s3_bucket_policy" "splunk_cloud_logs_storage" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  bucket                       = "${aws_s3_bucket.splunk_cloud_logs_storage.id}"
  policy                       = <<POLICY
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Action": [
               "s3:Get*",
               "s3:List*"
           ],
           "Effect": "Allow",
           "Resource": [
               "arn:aws:s3:::${local.splunk_cloud_log_storage_bucket_name}",
               "arn:aws:s3:::${local.splunk_cloud_log_storage_bucket_name}/*"
           ],
           "Principal": {
               "AWS": [
                 "arn:aws:iam::608578871059:role/OB_DevOps_Role",
                 "arn:aws:iam::608578871059:role/OB_SOC_Role"
               ]
           },
           "Condition": {
             "IpAddress": {
               "aws:SourceIp": [
                 "31.221.31.169/32"
               ]
             }
           }
       },
       {
           "Action": [
               "s3:PutObject",
               "s3:ListBucket"
           ],
           "Effect": "Allow",
           "Resource": [
               "arn:aws:s3:::${local.splunk_cloud_log_storage_bucket_name}",
               "arn:aws:s3:::${local.splunk_cloud_log_storage_bucket_name}/*"
           ],
           "Principal": {
               "AWS": [
                 "arn:aws:iam::630172805352:role/openbanking"
               ]
           },
           "Condition": {
             "StringEquals": {
               "aws:sourceVpce": [
                 "${local.splunk_vpc_endpoint}"
               ]
             }
           }
       }
   ]
}
POLICY
}

# Splunk config (tmp)
resource "aws_s3_bucket" "splunk_config_tmp" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  bucket                       = "${local.splunk_config_bucket_name}"
  acl                          = "private"

  tags {
    Description                = "Temp S3 bucket for Splunk Config"
    Environment                = "${var.acc_short_name}"
  }
  versioning {
    enabled                    = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm          = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "splunk_config_tmp" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  bucket                       = "${aws_s3_bucket.splunk_config_tmp.id}"
  block_public_acls            = true
  block_public_policy          = true
  ignore_public_acls           = true
  restrict_public_buckets      = true
}

resource "aws_s3_bucket_policy" "splunk_config_tmp" {
  count                        = "${var.splunk_cloud_logs_storage_bucket_enabled}"
  bucket                       = "${aws_s3_bucket.splunk_config_tmp.id}"
  policy                       = <<POLICY
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Action": [
               "s3:*"
           ],
           "Effect": "Allow",
           "Resource": [
               "arn:aws:s3:::${local.splunk_config_bucket_name}",
               "arn:aws:s3:::${local.splunk_config_bucket_name}/*"
           ],
           "Principal": {
               "AWS": [
                 "arn:aws:iam::608578871059:role/OB_DevOps_Role",
                 "arn:aws:iam::608578871059:role/OB_SOC_Role"
               ]
           }
       }
   ]
}
POLICY
}


# Developers Data Transfer Bucket
resource "aws_kms_key" "dev_data_bucket" {
  count                        = "${var.dev_data_bucket_enabled}"
  description                  = "Developers KMS key (S3)"
  deletion_window_in_days      = 30
  key_usage                    = "ENCRYPT_DECRYPT"
  is_enabled                   = true
  enable_key_rotation          = true
  policy                       = "${data.aws_iam_policy_document.dev_data_bucket.json}"

  tags {
    Name                       = "${local.dev_data_bucket_name}"
  }
}

data "aws_iam_policy_document" "dev_data_bucket" {
  statement {
    sid    = "key-default-1"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [
        "arn:aws:iam::${var.account_id}:root",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"
      ]
    }

    actions   = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:Create*",
      "kms:Put*",
      "kms:GenerateDataKey*",
      "kms:Get*",
      "kms:List*",
      "kms:EnableKeyRotation",
      "kms:Describe*"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "enable-developer-access"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "arn:aws:iam::${var.account_id}:role/OB_Developer_Role",
        "arn:aws:iam::${var.account_id}:role/OB_DevOps_Role"
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }
}


resource "aws_kms_alias" "dev_data_bucket" {
  count                        = "${var.dev_data_bucket_enabled}"
  name                         = "alias/${local.dev_data_bucket_name}"
  target_key_id                = "${aws_kms_key.dev_data_bucket.key_id}"
}

resource "aws_s3_bucket" "dev_data_bucket" {
  count                        = "${var.dev_data_bucket_enabled}"
  bucket                       = "${local.dev_data_bucket_name}"
  acl                          = "private"

  tags {
    Description                = "S3 bucket for developer use"
    Environment                = "${var.acc_short_name}"
  }
  versioning {
    enabled                    = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = "${aws_kms_key.dev_data_bucket.arn}"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "dev_data_bucket" {
  count                        = "${var.dev_data_bucket_enabled}"
  bucket                       = "${aws_s3_bucket.dev_data_bucket.id}"
  block_public_acls            = true
  block_public_policy          = true
  ignore_public_acls           = true
  restrict_public_buckets      = true
}

resource "aws_s3_bucket_policy" "dev_data_bucket" {
  count                        = "${var.dev_data_bucket_enabled}"
  bucket                       = "${aws_s3_bucket.dev_data_bucket.id}"
  policy                       = <<POLICY
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Action": [
               "s3:Get*",
               "s3:List*",
               "s3:AbortMultipartUpload",
               "s3:BypassGovernanceRetention",
               "s3:DeleteObject",
               "s3:DeleteObjectTagging",
               "s3:DeleteObjectVersion",
               "s3:DeleteObjectVersionTagging",
               "s3:PutObject",
               "s3:PutObjectAcl",
               "s3:PutObjectLegalHold",
               "s3:PutObjectRetention",
               "s3:PutObjectTagging",
               "s3:PutObjectVersionAcl",
               "s3:PutObjectVersionTagging",
               "s3:RestoreObject"
           ],
           "Effect": "Allow",
           "Resource": [
               "arn:aws:s3:::${local.dev_data_bucket_name}",
               "arn:aws:s3:::${local.dev_data_bucket_name}/*"
           ],
           "Principal": {
               "AWS": [
                 "arn:aws:iam::${var.account_id}:role/OB_Developer_Role",
                 "arn:aws:iam::${var.account_id}:role/OB_DevOps_Role"
               ]
           }
       },
       {
           "Action": [
               "s3:*"
           ],
           "Effect": "Allow",
           "Resource": [
               "arn:aws:s3:::${local.dev_data_bucket_name}",
               "arn:aws:s3:::${local.dev_data_bucket_name}/*"
           ],
           "Principal": {
               "AWS": [
                 "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"
               ]
           }
       }
   ]
}
POLICY
}

// AWS Instance logs backup

resource "aws_s3_bucket" "log_backups_bucket_name" {
  bucket = "${local.log_backups_bucket_name}"
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "${aws_s3_bucket.s3_server_access_logs_bucket.id}"
    target_prefix = "${local.log_backups_bucket_name}/"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.log_backups_bucket_kms_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_kms_key" "log_backups_bucket_kms_key" {
  description         = "${local.log_backups_bucket_name}"
  key_usage           = "ENCRYPT_DECRYPT"
  is_enabled          = true
  enable_key_rotation = true

  policy = "${data.aws_iam_policy_document.log_backups_bucket_kms_key_policy_document.json}"

  tags {
    Name = "${local.log_backups_bucket_name}"
  }
}

data "aws_iam_policy_document" "log_backups_bucket_kms_key_policy_document" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:role/${var.account_admin_role}"]
    }

    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"), list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ))}"
    }

    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = "${concat(formatlist("arn:aws:iam::%s:root", "${var.all_accounts}"), list(
        "arn:aws:iam::${var.account_id}:role/${var.jenkins_role}",
        "arn:aws:iam::${var.account_id}:role/${var.account_admin_role}",
      ))}"
    }

    actions = [
      "kms:RevokeGrant",
      "kms:ListGrants",
      "kms:CreateGrant",
    ]

    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"

      values = [
        "true",
      ]
    }
  }
}