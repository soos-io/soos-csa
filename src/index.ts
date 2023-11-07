import { ArgumentParser } from "argparse";
import * as FileSystem from "fs";
import { exit } from "process";
import { spawn } from "child_process";
import FormData from "form-data";
import { CONSTANTS } from "./utils/Constants";
import { LogLevel, Logger } from "./utils/Logger";
import { ensureValue, getEnvVariable } from "./utils/Utilities";
import SOOSAnalysisApiClient from "@soos-io/api-client/dist/api/SOOSAnalysisApiClient";
import { ScanStatus, ScanType, soosLogger, SOOS_CONSTANTS } from "@soos-io/api-client";

interface SOOSCsaAnalysisArgs {
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

class SOOSCsaAnalysis {
  constructor(private args: SOOSCsaAnalysisArgs) {}
  static parseArgs(): SOOSCsaAnalysisArgs {
    const parser = new ArgumentParser({ description: "SOOS Csa" });

    parser.add_argument("targetToScan", {
      help: "The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile",
    });
    parser.add_argument("--clientId", {
      help: "SOOS Client ID - get yours from https://app.soos.io/integrate/sca",
      default: getEnvVariable(CONSTANTS.SOOS.CLIENT_ID_ENV_VAR),
      required: false,
    });
    parser.add_argument("--apiKey", {
      help: "SOOS API Key - get yours from https://app.soos.io/integrate/sca",
      default: getEnvVariable(CONSTANTS.SOOS.API_KEY_ENV_VAR),
      required: false,
    });
    parser.add_argument("--projectName", {
      help: "Project Name - this is what will be displayed in the SOOS app.",
      required: true,
    });
    parser.add_argument("--apiURL", {
      help: "SOOS API URL - Intended for internal use only, do not modify.",
      default: "https://api.soos.io/api/",
      required: false,
    });
    parser.add_argument("--logLevel", {
      help: "Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.",
      default: LogLevel.INFO,
      required: false,
      type: (value: string) => {
        const upperCaseValue = value.toUpperCase();
        if (upperCaseValue in LogLevel) {
          return LogLevel[upperCaseValue as keyof typeof LogLevel];
        } else {
          throw new Error(`Invalid log level: ${value}`);
        }
      },
    });
    parser.add_argument("--otherOptions", {
      help: "Other Options to pass to syft.",
      default: null,
      required: false,
    });
    parser.add_argument("--integrationName", {
      help: "Integration Name - Intended for internal use only.",
      type: String,
      required: false,
    });
    parser.add_argument("--integrationType", {
      help: "Integration Type - Intended for internal use only.",
      type: String,
      required: false,
    });
    parser.add_argument("--scriptVersion", {
      help: "Script Version - Intended for internal use only.",
      type: String,
      required: false,
    });
    parser.add_argument("--appVersion", {
      help: "App Version - Intended for internal use only.",
      type: String,
      required: false,
    });
    parser.add_argument("--onFailure", {
      help: "Action to perform when the scan fails. Options: fail_the_build, continue_on_failure.",
      type: String,
      default: "continue_on_failure",
      required: false,
    });
    parser.add_argument("--commitHash", {
      help: "The commit hash value from the SCM System.",
      type: String,
      default: null,
      required: false,
    });
    parser.add_argument("--branchName", {
      help: "The name of the branch from the SCM System.",
      type: String,
      default: null,
      required: false,
    });
    parser.add_argument("--branchURI", {
      help: "The URI to the branch from the SCM System.",
      default: null,
      required: false,
    });
    parser.add_argument("--buildVersion", {
      help: "Version of application build artifacts.",
      type: String,
      default: null,
      required: false,
    });
    parser.add_argument("--buildURI", {
      help: "URI to CI build info.",
      type: String,
      default: null,
      required: false,
    });
    parser.add_argument("--operatingEnvironment", {
      help: "Set Operating environment for information purposes only.",
      type: String,
      default: null,
      required: false,
    });
    parser.add_argument("--verbose", {
      help: "Enable verbose logging.",
      action: "store_true",
      default: false,
      required: false,
    });

    logger.info("Parsing arguments");
    return parser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    const soosAnalysisApiClient = new SOOSAnalysisApiClient(this.args.apiKey, this.args.apiURL);
    try {
      logger.info("Starting SOOS CSA Analysis");
      logger.info(`Creating scan for project '${this.args.projectName}'...`);
      logger.info(`Branch Name: ${this.args.branchName}`);

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

      logger.info(`Project Hash: ${projectHash}`);
      logger.info(`Branch Hash: ${branchHash}`);
      logger.info(`Scan Id: ${analysisId}`);
      logger.info("Scan created successfully.");
      logger.logLineSeparator();

      logger.info("Generating container file for scan");
      await this.runSyft();
      logger.info("Container file generation completed successfully");
      logger.info("Uploading results");
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

      logger.info(
        ` Container Files: \n`,
        `  ${containerFileUploadResponse.message} \n`,
        containerFileUploadResponse.manifests
          ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
          .join("\n")
      );

      logger.logLineSeparator();
      logger.info("Starting analysis scan");
      await soosAnalysisApiClient.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId: analysisId,
      });
      logger.info(
        `Analysis scan started successfully, to see the results visit: ${result.scanUrl}`
      );
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
      logger.error(error);
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
      logger.info(`Running syft with args: ${args}`);
      const syftProcess = spawn("syft", args, {
        shell: true,
        stdio: "inherit",
      });

      syftProcess.on("close", (code) => {
        logger.verboseDebug(`syft: child process exited with code ${code}`);
        if (code === 0) {
          resolve();
        } else {
          reject(`syft: child process exited with code ${code}`);
        }
      });
    });
  }

  static async createAndRun(): Promise<void> {
    global.logger = new Logger();
    try {
      const args = this.parseArgs();
      global.logger.setMinLogLevel(args.logLevel);
      global.logger.setVerbose(args.verbose);
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.setVerbose(args.verbose);
      ensureValue(args.clientId, "clientId");
      ensureValue(args.apiKey, "apiKey");
      const csaAnalysis = new SOOSCsaAnalysis(args);
      await csaAnalysis.runAnalysis();
    } catch (error) {
      logger.error(`Error: ${error}`);
      exit(1);
    }
  }
}

SOOSCsaAnalysis.createAndRun();
