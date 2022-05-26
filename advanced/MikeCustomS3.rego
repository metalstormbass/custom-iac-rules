
package rules.bucketagdevmustbeprivate
import data.fugue

__rego__metadoc__ := {
  "title": "AWS S3 buckets tagged 'Environment:Dev' must have private ACLs",
  "description": "S3 buckets with the tag key 'Environment' and value 'Dev' must have private ACLs",
  "custom": {
    "providers": ["AWS", "Repository"],
    "severity": "High"
  }
}

# Note that the input type is set to "cfn" for CloudFormation.
input_type = "tf"

resource_type = "MULTIPLE"

buckets = fugue.resources("aws_s3_bucket")
buckets_acl = fugue.resources("aws_s3_bucket_acl")
# If a bucket is tagged stage:prod and its ACL is private, it passes.
# If it's tagged stage:prod and its ACL is NOT private, it fails.
# If it doesn't have a stage:prod tag, it is ignored.
policy[r] {
  bucket := buckets[_]
  bucket_acl := buckets_acl[_]
  bucket.tags[_].key == "Environment"
  bucket.tags[_].value == "Dev"
  buckets_acl.acl == "Private"
  r = fugue.allow_resource(bucket)
} {
  bucket := buckets[_]
  bucket_acl := buckets_acl[_]
  bucket.tags[_].key == "Environment"
  bucket.tags[_].value == "Production"
  not buckets_acl.acl == "Private"
  r = fugue.deny_resource(bucket)
}