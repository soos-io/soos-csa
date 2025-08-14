import { version } from "../package.json";
import { exit } from "process";
import { spawn } from "child_process";
import FormData from "form-data";
import {
  FileUtilities,
  getAnalysisExitCodeWithMessage,
  isScanDone,
  obfuscateCommandLine,
  obfuscateProperties,
  reassembleCommandLine,
} from "@soos-io/api-client/dist/utilities";
import {
  ScanStatus,
  ScanType,
  soosLogger,
  IntegrationName,
  IntegrationType,
  AttributionFormatEnum,
  AttributionFileTypeEnum,
} from "@soos-io/api-client";
import AnalysisService from "@soos-io/api-client/dist/services/AnalysisService";
import { SOOS_CSA_CONSTANTS } from "./constants";
import AnalysisArgumentParser, {
  IBaseScanArguments,
} from "@soos-io/api-client/dist/services/AnalysisArgumentParser";

interface SOOSCSAAnalysisArgs extends IBaseScanArguments {
  otherOptions: string;
  targetToScan: string;
}
class SOOSCSAAnalysis {
  constructor(private args: SOOSCSAAnalysisArgs) {}
  static parseArgs(): SOOSCSAAnalysisArgs {
    const analysisArgumentParser = AnalysisArgumentParser.create(
      IntegrationName.SoosCsa,
      IntegrationType.Script,
      ScanType.CSA,
      version,
    );

    analysisArgumentParser.addArgument("otherOptions", "Other Options to pass to syft.");

    analysisArgumentParser.addArgument(
      "targetToScan",
      "The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile",
      { useNoOptionKey: true },
    );

    return analysisArgumentParser.parseArguments();
  }

  async runAnalysis(): Promise<void> {
    const scanType = ScanType.CSA;
    const soosAnalysisService = AnalysisService.create(this.args.apiKey, this.args.apiURL);

    let projectHash: string | undefined;
    let branchHash: string | undefined;
    let analysisId: string | undefined;
    let scanStatusUrl: string | undefined;
    let scanStatus: ScanStatus | undefined;

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
        contributingDeveloperAudit: [
          {
            contributingDeveloperId: this.args.contributingDeveloperId,
            source: this.args.contributingDeveloperSource,
            sourceName: this.args.contributingDeveloperSourceName,
          },
        ],
        scanType,
        toolName: SOOS_CSA_CONSTANTS.ToolName,
        commandLine:
          process.argv.length > 2
            ? obfuscateCommandLine(
                reassembleCommandLine(process.argv.slice(2)),
                SOOS_CSA_CONSTANTS.ObfuscatedArguments.map((a) => `--${a}`),
              )
            : null,
      });

      projectHash = result.projectHash;
      branchHash = result.branchHash;
      analysisId = result.analysisId;
      scanStatusUrl = result.scanStatusUrl;

      soosLogger.info("Generating container file for scan");
      await this.runSyft();
      soosLogger.info("Container file generation completed successfully");

      soosLogger.info("Reading results");
      const base64FileContent = await FileUtilities.readFileToBase64Async(
        SOOS_CSA_CONSTANTS.ResultsFilePath,
      );
      const formData = new FormData();
      formData.append("file", base64FileContent, {
        knownLength: base64FileContent.length,
        filename: SOOS_CSA_CONSTANTS.ResultsFilename,
        contentType: "text/plain",
      });

      soosLogger.info("Uploading results");
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

      await soosAnalysisService.startScan({
        clientId: this.args.clientId,
        projectHash,
        analysisId: analysisId,
        scanType,
        scanUrl: result.scanUrl,
      });

      scanStatus = await soosAnalysisService.waitForScanToFinish({
        scanStatusUrl,
        scanUrl: result.scanUrl,
        scanType,
      });

      if (
        isScanDone(scanStatus) &&
        this.args.exportFormat !== AttributionFormatEnum.Unknown &&
        this.args.exportFileType !== AttributionFileTypeEnum.Unknown
      ) {
        await soosAnalysisService.generateFormattedOutput({
          clientId: this.args.clientId,
          projectHash: result.projectHash,
          projectName: this.args.projectName,
          branchHash: result.branchHash,
          analysisId: result.analysisId,
          format: this.args.exportFormat,
          fileType: this.args.exportFileType,
          workingDirectory: "/usr/src/app",
        });
      }

      const exitCodeWithMessage = getAnalysisExitCodeWithMessage(
        scanStatus,
        this.args.integrationName,
        this.args.onFailure,
      );
      soosLogger.always(`${exitCodeWithMessage.message} - exit ${exitCodeWithMessage.exitCode}`);
      exit(exitCodeWithMessage.exitCode);
    } catch (error) {
      let status = ScanStatus.Error;
      let message = "Error while performing scan.";
      if (error instanceof Error && error.message.includes("NoManifestsAccepted")) {
        status = ScanStatus.NoFiles;
        message = "No manifests were processed successfully.";
      }

      if (projectHash && branchHash && analysisId && (!scanStatus || !isScanDone(scanStatus)))
        await soosAnalysisService.analysisApiClient.updateScanStatus({
          clientId: this.args.clientId,
          projectHash,
          branchHash,
          scanType,
          scanId: analysisId,
          status,
          message,
        });
      soosLogger.error(error);
      soosLogger.always(`${error} - exit 1`);
      exit(1);
    }
  }

  async runSyft(): Promise<void> {
    return new Promise((resolve, reject) => {
      const args = [
        this.args.targetToScan,
        `-o syft-json=${SOOS_CSA_CONSTANTS.ResultsFilePath}`,
        this.args.otherOptions,
      ];
      soosLogger.info(`Running syft with args: ${args}`);
      const syftProcess = spawn("syft", args, {
        shell: true,
        stdio: "inherit",
      });

      syftProcess.on("close", (code) => {
        soosLogger.debug(`syft: child process exited with code ${code}`);
        if (code === 0) {
          resolve();
        } else {
          reject(`syft: child process exited with code ${code}`);
        }
      });
    });
  }

  static async createAndRun(): Promise<void> {
    try {
      const args = this.parseArgs();
      soosLogger.setMinLogLevel(args.logLevel);
      soosLogger.always("Starting SOOS CSA Analysis");
      soosLogger.debug(
        JSON.stringify(
          obfuscateProperties(
            args as unknown as Record<string, unknown>,
            SOOS_CSA_CONSTANTS.ObfuscatedArguments,
          ),
          null,
          2,
        ),
      );

      const soosCSAAnalysis = new SOOSCSAAnalysis(args);
      await soosCSAAnalysis.runAnalysis();
    } catch (error) {
      soosLogger.error(`Error on createAndRun: ${error}`);
      soosLogger.always(`Error on createAndRun: ${error} - exit 1`);
      exit(1);
    }
  }
}

SOOSCSAAnalysis.createAndRun();
