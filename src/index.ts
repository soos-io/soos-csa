import { version } from "../package.json";
import * as FileSystem from "fs";
import { exit } from "process";
import { spawn } from "child_process";
import FormData from "form-data";
import {
  ensureEnumValue,
  getAnalysisExitCode,
  obfuscateProperties,
} from "@soos-io/api-client/dist/utilities";
import {
  ScanStatus,
  ScanType,
  soosLogger,
  SOOS_CONSTANTS,
  IntegrationName,
  OutputFormat,
  IntegrationType,
} from "@soos-io/api-client";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import { SOOS_CSA_CONSTANTS } from "./constants";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";

interface SOOSCSAAnalysisArgs extends IBaseScanArguments {
  outputFormat: OutputFormat;
  otherOptions: string;
  targetToScan: string;
  workingDirectory: string;
}
class SOOSCSAAnalysis {
  constructor(private args: SOOSCSAAnalysisArgs) {}
  static parseArgs(): SOOSCSAAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(ScanType.CSA);

    analysisArgumentParser.addBaseScanArguments(
      IntegrationName.SoosCsa,
      IntegrationType.Script,
      version,
    );

    analysisArgumentParser.argumentParser.add_argument("--outputFormat", {
      help: "Output format for vulnerabilities: only the value SARIF is available at the moment",
      required: false,
      type: (value: string) => {
        return ensureEnumValue(OutputFormat, value);
      },
    });

    analysisArgumentParser.argumentParser.add_argument("--otherOptions", {
      help: "Other Options to pass to syft.",
      required: false,
      nargs: "*",
    });

    analysisArgumentParser.argumentParser.add_argument("--workingDirectory", {
      help: "Directory where the SARIF file will be created, used by Github Actions.",
      required: false,
      nargs: "*",
      default: process.cwd(),
    });

    analysisArgumentParser.argumentParser.add_argument("targetToScan", {
      help: "The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile",
    });

    soosLogger.info("Parsing arguments");
    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.CSA;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;

    try {
      const result = await soosAnalysisService.setupScan({
        clientId: this.args.clientId,
        projectName: this.args.projectName,
        commitHash: this.args.commitHash,
        branchName: this.args.branchName,
        buildVersion: this.args.buildVersion,
        buildUri: this.args.buildURI,
        branchUri: this.args.branchURI,
        integrationType: this.args.integrationType,
        operatingEnvironment: this.args.operatingEnvironment,
        integrationName: this.args.integrationName,
        appVersion: this.args.appVersion,
        scriptVersion: this.args.scriptVersion,
        contributingDeveloperAudit:
          !this.args.contributingDeveloperId ||
          !this.args.contributingDeveloperSource ||
          !this.args.contributingDeveloperSourceName
            ? []
            : [
                {
                  contributingDeveloperId: this.args.contributingDeveloperId,
                  source: this.args.contributingDeveloperSource,
                  sourceName: this.args.contributingDeveloperSourceName,
                },
              ],
        scanType,
        toolName: SOOS_CSA_CONSTANTS.ToolName,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      soosLogger.logLineSeparator();

      soosLogger.info("Generating container file for scan");
      await this.runSyft();
      soosLogger.info("Container file generation completed successfully");
      soosLogger.info("Uploading results");
      const fileReadStream = FileSystem.createReadStream(SOOS_CSA_CONSTANTS.ResultsFilePath, {
        encoding: SOOS_CONSTANTS.FileUploads.Encoding,
      });

      const formData = new FormData();
      formData.append("file", fileReadStream);

      const containerFileUploadResponse =
        await soosAnalysisService.analysisApiClient.uploadManifestFiles({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          analysisId,
          manifestFiles: formData,
          hasMoreThanMaximumManifests: false,
        });

      soosLogger.info(
        ` Container Files: \n`,
        `  ${containerFileUploadResponse.message} \n`,
        containerFileUploadResponse.manifests
          ?.map((m) => `  ${m.name}: ${m.statusMessage}`)
          .join("\n"),
      );

      soosLogger.logLineSeparator();

      await soosAnalysisService.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId: analysisId,
        scanType,
        scanUrl: result.scanUrl,
      });

      const scanStatus = await soosAnalysisService.waitForScanToFinish({
        scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      if (this.args.outputFormat !== undefined) {
        await soosAnalysisService.generateFormattedOutput({
          clientId: this.args.clientId,
          projectHash: result.projectHash,
          projectName: this.args.projectName,
          branchHash: result.branchHash,
          scanType,
          analysisId: result.analysisId,
          outputFormat: this.args.outputFormat,
          workingDirectory: this.args.workingDirectory,
        });
      }

      const exitCode = getAnalysisExitCode(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`exit ${exitCode}`);
      exit(exitCode);
    } catch (error) {
      if (projectHash && branchHash && analysisId)
        await soosAnalysisService.analysisApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          scanId: analysisId,
          status: ScanStatus.Error,
          message: `Error while performing scan.`,
        });
      soosLogger.error(error);
      soosLogger.always("exit 1");
      exit(1);
    }
  }

  async runSyft(): Promise<void> {
    return new Promise((resolve, reject) => {
      const args = [
        this.args.targetToScan,
        `-o json=${SOOS_CSA_CONSTANTS.ResultsFilePath}`,
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
          2,
        ),
      );
      soosLogger.logLineSeparator();
      const soosCSAAnalysis = new SOOSCSAAnalysis(args);
      await soosCSAAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      soosLogger.always("exit 1");
      exit(1);
    }
  }
}

SOOSCSAAnalysis.createAndRun();
