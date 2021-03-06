# GoCmdScanner
This is a Golang script to run scan across multiple hostnames/ports and identify hostnames/port which return output matching specific regex pattern. Where a pattern is not matched, raw output can also be directly displayed.

The regex, pattern is provided as an input signature file in YAML pattern. 

The tool can also be used to run the same command and store the output utilising Go's powerful concurrency pattern across multiple host/port OR in case of AWS across multiple profiles/regions.

In addition the following new features have been added: 
* Support for providing AWS profile, region to run tests on an environment
* Support for performing web requests, and checking output via regex similar to `nuclei`

The project is inspired by the [nuclei](https://github.com/projectdiscovery/nuclei) project.

## Available substitution parameters
The following lists the parameters available for substitution in cmd, url, notes
and other fields within a signature file. 

For example, if a user supplies the following line as input to `gocmdscanner`, then the following fields will be available:
```
https://www.google.com:443/test/test.txt?q=1&q=2
```

* `owd`: Original current working directory aka directory user executes gocmdscanner from on the workstation.
* `input`: Raw input line from user aka `https://www.google.com/test.txt?q=1&q=2`
* `hostname`|`host`|`domain`: Hostname present as input aka `www.google.com`
* `protocol`: protocol supplied aka `https`. By default, `https` is chosen.
* `port`: port supplied aka `443`. By default, `80` if `http` supplied as protocol, or `443` if `https` supplied as protocol. 
* `basepath`: Basepath of URL without the trailing path aka `https://www.google.com:443`
* `path`: Path without the basepath aka `/test/test.txt?q=1&q=2`

For AWS, checks where the following path is specified:
```
aws://default:us-west-2
```

* `owd`: Same as above.
* `input`: Same as above aka `aws://default:us-west-2`
* `profile`: Profile extracted from input aka `default`
* `region`: Region extracted from input aka `us-west-2`

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
    - tag: 
       - nmap
      cmd:
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

Run the check on all targets via the command using 10 goroutines ("light-threads") for concurrency, use `-mt`: 
```
$ cat /tmp/targets.txt | go run cmdscanner.go -paths smb_smbghost_check.yaml cat -mt 10
```

To show the targets that are being processed, use `-st` command to write progress to STDERR location, and write discovered assets to `out.txt`:
```
$ cat /tmp/targets.txt | go run cmdscanner.go -paths smb_smbghost_check.yaml cat -st | tee out.txt
Testing sigfile: smb_smbghost_check on target: map[basepath:https://www.google.com]
...

```

It is possible to optionally specify multiple methods of running a check using tags via `tag` param in signature file, as shown above. By then, specifying `-t` to `gocmdscanner`, it is possible to determine which checks to perform from signature files using these tags. By default, ALL checks get `auto` tags when not specificed

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

## TODO
- [ ] Need to fix bug where cmdtimeout applies to a command and not to appended `cd`
- [ ] Need to encode colons in URL path and query parameters to prevent `400` errors.
- [ ] Need to make de-duplicate the URLs and reuse the output, instead of making too many duplicated requests via a `map`. Also, use `usecached` boolean param to determine whether to serve cached response OR always get response again (useful for web cache poisoning checks).
