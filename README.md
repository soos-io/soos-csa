# About SOOS

SOOS is an independent software security company, located in Winooski, VT USA, building security software for your team. [SOOS, Software security, simplified](https://soos.io).

Use SOOS to scan your software for [vulnerabilities](https://app.soos.io/research/vulnerabilities) and [open source license](https://app.soos.io/research/licenses) issues with [SOOS Core SCA](https://soos.io/sca-product). [Generate SBOMs](https://kb.soos.io/help/generating-a-software-bill-of-materials-sbom). Govern your open source dependencies. Run the [SOOS DAST vulnerability scanner](https://soos.io/dast-product) against your web apps or APIs.

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

## Parameters

| Argument | Default | Description |
| --- | --- | --- |
| `--apiKey` | None | SOOS API Key - get yours from https://app.soos.io/integrate/containers |
| `--apiURL` | https://api.soos.io/api/ | SOOS API URL - Intended for internal use only, do not modify. |
| `--appVersion` | None | App Version - Intended for internal use only. |
| `--branchName` | null | The name of the branch from the SCM System. |
| `--branchURI` | null | The URI to the branch from the SCM System. |
| `--buildURI` | null | URI to CI build info. |
| `--buildVersion` | null | Version of application build artifacts. |
| `--clientId` | None | SOOS Client ID - get yours from https://app.soos.io/integrate/containers |
| `--commitHash` | null | The commit hash value from the SCM System. |
| `--integrationName` | null | Integration Name - Intended for internal use only. |
| `--integrationType` | null | Integration Type - Intended for internal use only. |
| `--logLevel` | INFO | Minimum level to show logs: PASS, IGNORE, INFO, WARN, or FAIL. |
| `--onFailure` | continue_on_failure | Action to perform when the scan fails. Options: fail_the_build, continue_on_failure. |
| `--operatingEnvironment` | null | Set Operating environment for information purposes only. |
| `--otherOptions` | None | Other Options to pass to syft. |
| `--projectName` | None | Project Name - this is what will be displayed in the SOOS app. |
| `--scriptVersion` | null | N/A |
| `--verbose` | false | Enable verbose logging. |
| `targetToScan` | N/A | The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile. |

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
## Retrieving the Results File for Troubleshooting
If you need to retrieve the results file for troubleshooting or any other reason, you can do so by mounting a volume. This binds the container's results directory to a directory on your host machine.
In the following example, c:/results is the local folder on the host where the results will be stored:
```
docker run -it \
  -v c:/results:/usr/src/app/results \
  soosio/csa \
  --clientId=<YOUR_CLIENT_ID> \
  --apiKey=<YOUR_API_KEY> \
  --projectName="<YOUR_PROJECT_NAME>" \
  <CONTAINER_NAME>:<TAG_NAME>
```

Note: The path c:/results is specific to Windows. If you're using Linux or macOS, adjust the path format accordingly.
