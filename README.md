# About SOOS

SOOS is an independent software security company, located in Winooski, VT USA, building security software for your team. [SOOS, Software security, simplified](https://soos.io).

Use SOOS to scan your software for [vulnerabilities](https://app.soos.io/research/vulnerabilities) and [open source license](https://app.soos.io/research/licenses) issues with [SOOS Core SCA](https://soos.io/products/sca). [Generate and ingest SBOMs](https://soos.io/products/sbom-manager). [Export reports](https://kb.soos.io/help/soos-reports-for-export) to industry standards. Govern your open source dependencies. Run the [SOOS DAST vulnerability scanner](https://soos.io/products/dast) against your web apps or APIs. [Scan your Docker containers](https://soos.io/products/containers) for vulnerabilities. Check your source code for issues with [SAST Analysis](https://soos.io/products/sast).

[Demo SOOS](https://app.soos.io/demo) or [Register for a Free Trial](https://app.soos.io/register).

If you maintain an Open Source project, sign up for the Free as in Beer [SOOS Community Edition](https://soos.io/products/community-edition).

## Requirements
- [Docker](https://www.docker.com/get-started)

## How to Use
To start the scan you need to run this command from a terminal:
``` shell
docker run -it --rm soosio/csa <parameters>
```

The basic command to run a scan would look like:
```
docker run -it --rm \
  soosio/csa \
  --clientId=<YOUR_CLIENT_ID> \
  --apiKey=<YOUR_API_KEY> \
  --projectName="<YOUR_PROJECT_NAME>" \
  <CONTAINER_NAME>:<TAG_NAME>
```

## Client Parameters

| Argument | Default | Description |
| --- | --- | --- |
| `--apiKey` |  | SOOS API Key - get yours from [SOOS Integration](https://app.soos.io/integrate/containers). Uses `SOOS_API_KEY` env value if present. |
| `--branchName` |  | The name of the branch from the SCM System. |
| `--branchURI` |  | The URI to the branch from the SCM System. |
| `--buildURI` |  | URI to CI build info. |
| `--buildVersion` |  | Version of application build artifacts. |
| `--clientId` |  | SOOS Client ID - get yours from [SOOS Integration](https://app.soos.io/integrate/containers). Uses `SOOS_API_CLIENT` env value if present. |
| `--commitHash` |  | The commit hash value from the SCM System. |
| `--logLevel` |  | Minimum level to show logs: DEBUG INFO, WARN, FAIL, ERROR. |
| `--onFailure` | `continue_on_failure` | Action to perform when the scan fails. Options: fail_the_build, continue_on_failure. |
| `--operatingEnvironment` |  | Set Operating environment for information purposes only. |
| `--otherOptions` |  | Other Options to pass to Syft. |
| `--outputFormat` |  | Output format for vulnerabilities: only the value SARIF is available currently. Be sure to use -v on the Docker command to mount an output directory. |
| `--projectName` |  | Project Name - this is what will be displayed in the SOOS app. |
| `targetToScan` |  | The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile. |

## Scanning Private Images with Authentication
To scan an image from a private registry, follow these steps:

1. Authenticate the Host: Ensure that the Docker daemon on your host machine is authenticated with the private registry.

2. Run the Scan: Use the following command, passing the Docker socket into the container:
```
docker run -it \
  -v /var/run/docker.sock:/var/run/docker.sock \
  soosio/csa \
  --clientId=<YOUR_CLIENT_ID> \
  --apiKey=<YOUR_API_KEY> \
  --projectName="<YOUR_PROJECT_NAME>" \
  <CONTAINER_NAME>:<TAG_NAME>
```
## Writing SARIF results or Retrieving the Results File for Troubleshooting
If you need to output a SARIF file or retrieve the intermediary result file, you can do so by mounting a volume.

This binds the container's results directory to a directory on your host machine. 

In the following example, `c:/temp` is the local folder on the host where the results will be stored:

```
docker run -it -v c:/temp:/usr/src/app/:rw soosio/csa --clientId=<YOUR_CLIENT_ID> --apiKey=<YOUR_API_KEY> --projectName="<YOUR_PROJECT_NAME>" <CONTAINER_NAME>:<TAG_NAME>
```

Note: The path c:/results is specific to Windows. If you're using Linux or macOS, adjust the path format accordingly.
