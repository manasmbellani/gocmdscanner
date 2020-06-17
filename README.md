# GoCmdScanner
This is a Golang script to run scan across multiple hostnames/ports and identify hostnames/port which return output matching specific regex pattern. Where a pattern is not matched, raw output can also be directly displayed.

The regex, pattern is provided as an input signature file in YAML pattern. 

The tool can also be used to run the same command and store the output utilising Go's powerful concurrency pattern across multiple host/port OR in case of AWS across multiple profiles/regions.

In addition the following new features have been added: 
* Support for providing AWS profile, region to run tests on an environment
* Support for performing web requests, and checking output via regex similar to `nuclei`

The project is inspired by the [nuclei](https://github.com/projectdiscovery/nuclei) project.

## Examples

### Standard Usage
To scan for targets which could have SMB Ghost vulnerability in file `smb_smbghost_check.yaml`, the following signature example can be used:

```
id: smb_smbghost_check 

info:
    name: "Check for SMB Ghostcheck vuln (CVE-2020-0796)"
    author: manasmbellani
    severity: high

checks:
    - cmd:
      -  "nmap -sS -Pn --script=smb-protocols -p{port} {hostname}"
      outfile: "/tmp/out-smb-ghostcheck-cve-2020-0796-{hostname}-{port}.txt"
      matchers:
        - type: regex
          regex: "3\\.11"
```

The following placeholders are accepted in the `cmd`, `outfile`: `protocol`, `hostname` and `port`

The targets can be specified via `echo -e` or from a file one-per-line in following format `protocol://hostname:port` as follows:
```
$ cat targets.txt
smb://www.google.com:445
smb://165.234.132.178:445
smb://125.231.106.110:445
```

Run the check on all targets via the command: 
```
cat /tmp/targets.txt | go run cmdscanner.go -paths smb_smbghost_check.yaml cat 
```

### URL Usage
`GoCmdScanner` can also be used for making HTTP requests and check response received, similar to how nuclei works.

Example, if we create a signature for robots.txt file in file `http_robots_file.yaml`:

```
id: http_robots_file

info:
  name: Look for HTTP Robots.txt file that contain hidden paths generally
  author: manasmbellani
  severity: low

checks:
  - method: GET
    url:
      - "{basepath}/robots.txt"
      - "{basepath}/.robots.txt"
    matchers:
      - type: regex
        regex: "(?i)(Allow: |Disallow: |Sitemap: )"
```

We can then run the check with a number of URL base-paths (without extensions) defined in file: `/tmp/urls.txt`
```
$ cat /tmp/urls.txt
https://www.google.com
https://www.msn.com
https://zol.au

$ cat /tmp/urls.txt | go run gocmdscanner.go -paths http_elmah_logs.yaml
https://www.google.com:443/robots.txt
https://www.msn.com:443/robots.txt
```

### AWS-based Usage

By providing `aws://` as the protocol, one or more `profile:region` can be provided to run scans for particular AWS creds profile and the specific region. E.g

```
$ cat aws_profiles.txt
aws://default:ap-southeast-2

$ echo aws_profiles.txt | go run gocmdscanner.go -t test.yaml
$ cat out-aws-get-caller-identity-sts-flaws_cloud_level_6-ap-southeast-2.txt 

{
    "UserId": "AI.......",
    "Account": "97......",
    "Arn": "arn:aws:iam::97.......:user/L...."
}
```

Here test.yaml can contain commands based on `awscli` where the output of command get  stored within the outfile: `out-aws-get-caller-identity-sts-....txt` within the current directory.

```
id: aws_get_user_identity

info:
    name: "Discover the identity of the user within the given profile/region"
    author: manasmbellani
    severity: low

checks:
    # Via aws sts get-caller-identity command
    - cmd:
      -  "aws sts get-caller-identity --profile={profile} --region={region}"
      outfile: "out-aws-get-caller-identity-sts-{profile}-{region}.txt"
```