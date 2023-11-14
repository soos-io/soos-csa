import { ArgumentParser } from "argparse";
import * as FileSystem from "fs";
import { exit } from "process";
import { spawn } from "child_process";
import FormData from "form-data";
import { CONSTANTS } from "./utils/Constants";
import {
  ensureEnumValue,
  ensureValue,
  getEnvVariable,
  obfuscateProperties,
  sleep,
} from "@soos-io/api-client/dist/utilities";
import SOOSAnalysisApiClient from "@soos-io/api-client/dist/api/SOOSAnalysisApiClient";
import { ScanStatus, ScanType, soosLogger, SOOS_CONSTANTS, LogLevel } from "@soos-io/api-client";
import { OnFailure } from "./utils/enums";

interface SOOSCSAAnalysisArgs {
  apiKey: string;
  apiURL: string;
  appVersion: string;
  branchName: string;
  branchUri: string;
  buildUri: string;
  buildVersion: string;
  clientId: string;
  commitHash: string;
  integrationName: string;
  integrationType: string;
  logLevel: LogLevel;
  onFailure: string;
  operatingEnvironment: string;
  otherOptions: string;
  projectName: string;
  scriptVersion: string;
  targetToScan: string;
  verbose: boolean;
}
class SOOSCSAAnalysis {
  constructor(private args: SOOSCSAAnalysisArgs) {}
  static parseArgs(): SOOSCSAAnalysisArgs {
    const parser = new ArgumentParser({ description: "SOOS Csa" });

    parser.add_argument("--apiKey", {
      help: "SOOS API Key - get yours from https://app.soos.io/integrate/containers",
      default: getEnvVariable(CONSTANTS.SOOS.API_KEY_ENV_VAR),
      required: false,
    });

    parser.add_argument("--apiURL", {
      help: "SOOS API URL - Intended for internal use only, do not modify.",
      default: "https://api.soos.io/api/",
      required: false,
    });

    parser.add_argument("--appVersion", {
      help: "App Version - Intended for internal use only.",
      required: false,
    });

    parser.add_argument("--branchName", {
      help: "The name of the branch from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--branchURI", {
      help: "The URI to the branch from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--buildURI", {
      help: "URI to CI build info.",
      default: null,
      required: false,
    });

    parser.add_argument("--buildVersion", {
      help: "Version of application build artifacts.",
      default: null,
      required: false,
    });

    parser.add_argument("--clientId", {
      help: "SOOS Client ID - get yours from https://app.soos.io/integrate/containers",
      default: getEnvVariable(CONSTANTS.SOOS.CLIENT_ID_ENV_VAR),
      required: false,
    });

    parser.add_argument("--commitHash", {
      help: "The commit hash value from the SCM System.",
      default: null,
      required: false,
    });

    parser.add_argument("--integrationName", {
      help: "Integration Name - Intended for internal use only.",
      required: false,
      default: CONSTANTS.SOOS.DEFAULT_INTEGRATION_NAME,
    });

    parser.add_argument("--integrationType", {
      help: "Integration Type - Intended for internal use only.",
      required: false,
      default: CONSTANTS.SOOS.DEFAULT_INTEGRATION_TYPE,
    });

    parser.add_argument("--logLevel", {
      help: "Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.",
      default: LogLevel.INFO,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(LogLevel, value);
      },
    });

    parser.add_argument("--onFailure", {
      help: "Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.",
      default: OnFailure.Continue,
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OnFailure, value);
      },
    });

    parser.add_argument("--operatingEnvironment", {
      help: "Set Operating environment for information purposes only.",
      default: null,
      required: false,
    });

    parser.add_argument("--otherOptions", {
      help: "Other Options to pass to syft.",
      required: false,
      nargs: "*",
    });

    parser.add_argument("--projectName", {
      help: "Project Name - this is what will be displayed in the SOOS app.",
      required: true,
    });

    parser.add_argument("--scriptVersion", {
      required: false,
    });

    parser.add_argument("--verbose", {
      help: "Enable verbose logging.",
      action: "store_true",
      default: false,
      required: false,
    });

    parser.add_argument("targetToScan", {
      help: "The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile",
    });

    soosLogger.info("Parsing arguments");
    return parser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    const soosAnalysisApiClient = new SOOSAnalysisApiClient(this.args.apiKey, this.args.apiURL);
    try {
      soosLogger.info("Starting SOOS CSA Analysis");
      soosLogger.info(`Creating scan for project '${this.args.projectName}'...`);
      soosLogger.info(`Branch Name: ${this.args.branchName}`);

      const result = await soosAnalysisApiClient.createScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branch: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildUri,
        branchUri: this.args.branchUri,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scriptVersion: null,
        contributingDeveloperAudit: undefined,
        scanType: ScanType.CSA,
        toolName: CONSTANTS.CSA.TOOL_NAME,
        toolVersion: null,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;

      soosLogger.info(`Project Hash: ${projectHash}`);
      soosLogger.info(`Branch Hash: ${branchHash}`);
      soosLogger.info(`Scan Id: ${analysisId}`);
      soosLogger.info("Scan created successfully.");
      soosLogger.logLineSeparator();

      soosLogger.info("Generating container file for scan");
      await this.runSyft();
      soosLogger.info("Container file generation completed successfully");
      soosLogger.info("Uploading results");
      const fileReadStream = FileSystem.createReadStream(CONSTANTS.FILES.DEFAULT_FILE_PATH, {
        encoding: SOOS_CONSTANTS.FileUploads.Encoding,
      });

      const formData = new FormData();
      formData.append("file", fileReadStream);

      const containerFileUploadResponse = await soosAnalysisApiClient.uploadManifestFiles({
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        analysisId,
        manifestFiles: formData,
      });

      soosLogger.info(
        ` Container Files: \n`,
        `  ${containerFileUploadResponse.message} \n`,
        containerFileUploadResponse.manifests
          ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
          .join("\n")
      );

      soosLogger.logLineSeparator();
      soosLogger.info("Starting analysis scan");
      await soosAnalysisApiClient.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId: analysisId,
      });

      soosLogger.info(
        `Analysis scan started successfully, to see the results visit: ${result.scanUrl}`
      );

      if (this.args.onFailure === OnFailure.Fail) {
        soosLogger.info("Waiting for scan to finish...");
        await this.waitForScanToFinish({
          apiClient: soosAnalysisApiClient,
          scanStatusUrl: result.scanStatusUrl,
          attempt: 0,
        });
      }
    } catch (error) {
      if (projectHash && branchHash && analysisId)
        await soosAnalysisApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType: ScanType.CSA,
          scanId: analysisId,
          status: ScanStatus.Error,
          message: `Error while performing scan.`,
        });
      soosLogger.error(error);
      exit(1);
    }
  }

  async runSyft(): Promise<void> {
    return new Promise((resolve, reject) => {
      const args = [
        this.args.targetToScan,
        `-o json=${CONSTANTS.FILES.DEFAULT_FILE_PATH}`,
        this.args.otherOptions,
      ];
      soosLogger.info(`Running syft with args: ${args}`);
      const syftProcess = spawn("syft", args, {
        shell: true,
        stdio: "inherit",
      });

      syftProcess.on("close", (code) => {
        soosLogger.verboseDebug(`syft: child process exited with code ${code}`);
        if (code === 0) {
          resolve();
        } else {
          reject(`syft: child process exited with code ${code}`);
        }
      });
    });
  }

  async waitForScanToFinish({
    apiClient,
    scanStatusUrl,
    attempt,
  }: {
    apiClient: SOOSAnalysisApiClient;
    scanStatusUrl: string;
    attempt: number;
  }): Promise<void> {
    const status = await apiClient.getScanStatus({ scanStatusUrl });

    if (!status.isComplete) {
      soosLogger.info(`Scan status: ${status.status}...`);
      if (attempt >= CONSTANTS.STATUS.MAX_ATTEMPTS) {
        soosLogger.error("Max attempts reached fetching scan status.");
        soosLogger.error("Failing the build.");
        process.exit(1);
      }
      soosLogger.info(
        `Waiting ${CONSTANTS.STATUS.DELAY_TIME / 1000} seconds before trying again...`
      );
      await sleep(CONSTANTS.STATUS.DELAY_TIME);
      return this.waitForScanToFinish({ apiClient, scanStatusUrl, attempt: attempt++ });
    }

    soosLogger.info(`Scan status is complete: ${status.status}`);

    if (status.status === ScanStatus.FailedWithIssues) {
      soosLogger.info("Analysis complete - Failures reported");
      soosLogger.info("Failing the build.");
      process.exit(1);
    } else if (status.status === ScanStatus.Incomplete) {
      soosLogger.info(
        "Analysis Incomplete. It may have been cancelled or superseded by another scan."
      );
      soosLogger.info("Failing the build.");
      process.exit(1);
    } else if (status.status === ScanStatus.Error) {
      soosLogger.info("Analysis Error.");
      soosLogger.info("Failing the build.");
      process.exit(1);
    } else if (scanStatusUrl === "finished") {
      return;
    } else {
      process.exit(0);
    }
  }

  static async createAndRun(): Promise<void> {
    soosLogger.info("Starting SOOS CSA Analysis");
    soosLogger.logLineSeparator();
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.setVerbose(args.verbose);
      soosLogger.info("Configuration read");
      soosLogger.verboseDebug(
        JSON.stringify(
          obfuscateProperties(args as unknown as Record<string, unknown>, ["apiKey"]),
          null,
          2
        )
      );
      ensureValue(args.clientId, "clientId");
      ensureValue(args.apiKey, "apiKey");
      const csaAnalysis = new SOOSCSAAnalysis(args);
      await csaAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      exit(1);
    }
  }
}

SOOSCSAAnalysis.createAndRun();
