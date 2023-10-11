import { JSON_CONTENT_TYPE, KILO_BYTE } from "../utils/Constants";
import axios, { AxiosError } from "axios";
import { exit } from "process";

export function isAxiosError<T = unknown, D = unknown>(e: unknown): e is AxiosError<T, D> {
  return (e as AxiosError<T, D>)?.isAxiosError === true;
}

export interface IHttpRequestParameters {
  baseUri: string;
  apiKey: string;
}

export interface IHttpClientParameters extends IHttpRequestParameters {
  clientName: string;
  errorResponseHandler?: (rejectedResponse: any) => void;
}

export interface ICodedMessageModel {
  code: string;
  message: string;
  data: Record<string, string>;
  statusCode: number;
}

export default function createHttpClient({
  baseUri,
  apiKey,
  clientName,
  errorResponseHandler,
}: IHttpClientParameters) {
  const client = axios.create({
    baseURL: baseUri,
    headers: {
      "x-soos-apikey": apiKey,
      "Content-Type": JSON_CONTENT_TYPE,
    },
    // Same as limit on api for manifests
    // Reference: https://stackoverflow.com/a/56868296
    maxBodyLength: KILO_BYTE * 5000 * 50,
    maxContentLength: KILO_BYTE * 5000 * 50,
  });

  client.interceptors.request.use(
    (request) => {
      console.log(clientName);
      console.log(clientName, `Request Url (${request.method}): ${request.url}`);
      if (request.data) {
        console.log(clientName, `Request Body: ${JSON.stringify(request.data)}`);
      }
      return request;
    },
    (rejectedRequest) => {
      console.log(clientName, "Request Error: ", rejectedRequest);
      return Promise.reject(rejectedRequest);
    }
  );

  client.interceptors.response.use(
    (response) => {
      console.log(clientName, `Response: ${response.status} (${response.statusText})`);
      console.log(clientName, `Response Body: ${JSON.stringify(response.data)}`);
      return response;
    },
    (rejectedResponse) => {
      if (rejectedResponse?.response) {
        if (errorResponseHandler) {
          errorResponseHandler(rejectedResponse);
        } else {
          console.error(
            clientName,
            `Response: ${rejectedResponse.response.status} (${rejectedResponse.response.statusText})`
          );
          console.error(clientName, `Response Body: `, rejectedResponse.response.data);
        }
      }
      if (isAxiosError<ICodedMessageModel | undefined>(rejectedResponse)) {
        switch (rejectedResponse?.response?.status) {
          case 503:
            exit();
            break;
        }
      }
      return Promise.reject(rejectedResponse);
    }
  );

  return client;
}
