import { ArgumentParser } from "argparse";
import * as FileSystem from "fs";
import { exit } from "process";
import { ScanType, createScan, startAnalysisScan, uploadSBOMFiles } from "./api/api";
import { spawn } from "child_process";
import FormData from "form-data";
import { FILE_ENCODING } from "./utils/Constants";

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
  helpFormatted: boolean;
  integrationName: string;
  integrationType: string;
  logLevel: string;
  onFailure: string;
  operatingEnvironment: string;
  otherArgs: string;
  projectName: string;
  scriptVersion: string;
  targetToScan: string;
}

class SOOSCsaAnalysis {
  constructor(private args: SOOSCsaAnalysisArgs) {}

  static parseArgs(): SOOSCsaAnalysisArgs {
    const parser = new ArgumentParser({ description: "SOOS Csa" });

    parser.add_argument("-hf", "--helpFormatted", {
      help: "Print the --help command in markdown table format",
      action: "store_false",
      default: false,
      required: false,
    });

    parser.add_argument("targetToScan", {
      help: "The target to scan. Should be a docker image name or a path to a directory containing a Dockerfile",
    });
    parser.add_argument("--clientId", {
      help: "SOOS Client ID - get yours from https://app.soos.io/integrate/sca",
      required: false,
    });
    parser.add_argument("--apiKey", {
      help: "SOOS API Key - get yours from https://app.soos.io/integrate/sca",
      required: false,
    });
    parser.add_argument("--projectName", {
      help: "Project Name - this is what will be displayed in the SOOS app.",
      required: false,
    });
    parser.add_argument("--apiURL", {
      help: "SOOS API URL - Intended for internal use only, do not modify.",
      default: "https://api.soos.io/api/",
      required: false,
    });
    parser.add_argument("--logLevel", {
      help: "Minimum level to show logs: PASS, IGNORE, INFO, WARN or FAIL.",
      default: "INFO",
      required: false,
    });
    parser.add_argument("--otherArgs", {
      help: "Other arguments to pass to syft.",
      default: null,
      required: false,
    });
    parser.add_argument("--integrationName", {
      help: "Integration Name - Intended for internal use only.",
      type: String,
      nargs: "*",
      required: false,
    });
    parser.add_argument("--integrationType", {
      help: "Integration Type - Intended for internal use only.",
      type: String,
      nargs: "*",
      required: false,
    });
    parser.add_argument("--scriptVersion", {
      help: "Script Version - Intended for internal use only.",
      type: String,
      nargs: "*",
      required: false,
    });
    parser.add_argument("--appVersion", {
      help: "App Version - Intended for internal use only.",
      type: String,
      nargs: "*",
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
      nargs: "*",
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
      nargs: "*",
      required: false,
    });

    console.log("Parsing arguments");
    return parser.parse_args();
  }

  async runAnalysis(): Promise<void> {
    try {
      console.log("Starting SOOS Csa Analysis");
      console.log(`Creating scan for project '${this.args.projectName}'...`);

      const {
        projectHash,
        branchHash,
        scanId: analysisScanId,
        reportUrl,
        scanStatusUrl: reportStatusUrl,
      } = await createScan({
        baseUri: this.args.apiURL,
        apiKey: this.args.apiKey,
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
        scanType: ScanType.CSA,
      });

      console.log(`Project Hash: ${projectHash}`);
      console.log(`Branch Hash: ${branchHash}`);
      console.log(`Scan Id: ${analysisScanId}`);
      console.log(`Report Url: ${reportUrl}`);
      console.log(`Report Status Url: ${reportStatusUrl}`);
      console.log("Scan created successfully.");

      // Run syft and upload results
      console.log("Running syft");
      await this.runSyft();
      console.log("Syft completed successfully");
      console.log("Uploading results");
      // convert results.json into FormData
      const fileReadStream = FileSystem.createReadStream("./results.json", {
        encoding: FILE_ENCODING,
      });

      const formData = new FormData();

      // Read the file stream and append it to formData
      formData.append("file", fileReadStream);
      const sbomFileUploadResponse = await uploadSBOMFiles({
        baseUri: this.args.apiURL,
        apiKey: this.args.apiKey,
        clientId: this.args.clientId,
        projectHash,
        branchHash,
        analysisId: analysisScanId,
        sbomFiles: formData,
      });

      console.log(
        ` SBOM Files: \n`,
        `  ${sbomFileUploadResponse.message} \n`,
        sbomFileUploadResponse.manifests?.map((m) => `  ${m.name}: ${m.statusMessage}`).join("\n")
      );

      console.log("Starting analysis scan");
      await startAnalysisScan({
        baseUri: this.args.apiURL,
        apiKey: this.args.apiKey,
        clientId: this.args.clientId,
        projectHash,
        analysisId: analysisScanId,
      });
    } catch (error) {
      console.log(`Error: ${error}`);
      exit(1);
    }
  }

  async runSyft(): Promise<void> {
    return new Promise((resolve, reject) => {
      // Break the command into the program and the arguments
      const args = [this.args.targetToScan, this.args.otherArgs, "-o json=./results.json"];
      const command = spawn("syft", args, { shell: true });

      // Optionally, capture standard output and standard error
      command.stdout.on("data", (data) => {
        console.log(`stdout: ${data}`);
      });
      command.stderr.on("data", (data) => {
        console.error(`stderr: ${data}`);
      });

      // Resolve the promise when the command completes
      command.on("close", (code) => {
        if (code !== 0) {
          reject(new Error(`syft command exited with code ${code}`));
        } else {
          resolve();
        }
      });

      // Optionally, handle errors
      command.on("error", (error) => {
        reject(error);
      });
    });
  }

  static async createAndRun(): Promise<void> {
    try {
      const args = this.parseArgs();
      const csaAnalysis = new SOOSCsaAnalysis(args);
      await csaAnalysis.runAnalysis();
    } catch (error) {
      console.error(`Error: ${error}`);
      exit(1);
    }
  }
}

// Entry point
SOOSCsaAnalysis.createAndRun();
