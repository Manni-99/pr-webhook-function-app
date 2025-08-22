import {
  app,
  HttpRequest,
  HttpResponseInit,
  InvocationContext,
} from "@azure/functions";
import * as crypto from "crypto";
import { ServiceBusClient } from "@azure/service-bus";

// Define the expected shape of the pull_request event payload
interface PullRequestPayload {
  action: string;
  pull_request: {
    number: number;
    head: {
      ref: string;
      sha: string;
    }
    html_url: string;
    title: string;
    user: {
      login: string;
    };
  };
  repository: {
    full_name: string;
  };
}

const githubWebhook = async function (
  request: HttpRequest,
  context: InvocationContext
): Promise<HttpResponseInit> {
  // Add a logging statement to help with debugging
  context.log("GitHub webhook function received a request.");

  // Get environment variables from local.settings.json
  const webhookSecret = process.env.WEBHOOK_SECRET;
  const connectionString = process.env.SERVICE_BUS_CONNECTION_STRING;
  const queueName = process.env.SERVICE_BUS_QUEUE_NAME;

  // Check for required environment variables
  if (!webhookSecret || !connectionString || !queueName) {
    context.error("One or more required environment variables are not configured.");
    return {
      status: 500,
      body: "Required environment variables are not configured."
    };
  }

  // Verify the GitHub signature to ensure the request is from a trusted source
  const signature = request.headers.get("x-hub-signature-256");
  if (!signature) {
    context.warn("Request is missing the X-Hub-Signature-256 header.");
    return {
      status: 401,
      body: "Invalid signature"
    };
  }

  const rawBody = await request.text();
  const hmac = crypto.createHmac("sha256", webhookSecret);
  const digest = "sha256=" + hmac.update(rawBody).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature))) {
    context.error("Signature verification failed.");
    return {
      status: 401,
      body: "Invalid signature"
    };
  }

  // Check the GitHub event type from the request header
  const githubEvent = request.headers.get("x-github-event");

  context.log(`Received event: ${githubEvent}`);

  // Check if the event is a 'pull_request'
  if (githubEvent !== "pull_request") {
    context.log(`Ignoring event of type: ${githubEvent}`);
    return {
      status: 200,
      body: "Event ignored, not a pull_request event."
    };
  }

  const payload: PullRequestPayload = JSON.parse(rawBody);

  // Check if the action is 'opened'
  if (payload.action !== "opened") {
    context.log(`Ignoring pull_request action: ${payload.action}`);
    return {
      status: 200,
      body: "Event ignored, not a 'pull_request opened' action."
    };
  }

  // At this point, the request is a verified "pull_request opened" event.
  // Now, we can extract the relevant information and send it to Service Bus.
  const messageBody = {
    prNumber: payload.pull_request.number,
    branch: payload.pull_request.head.ref,
    repoFullName: payload.repository.full_name
  };

  try {
    const sbClient = new ServiceBusClient(connectionString);
    const sender = sbClient.createSender(queueName);

    context.log("Sending message to Service Bus...");
    await sender.sendMessages({ body: messageBody });
    context.log("Message sent successfully!");

    await sender.close();
    await sbClient.close();

    return {
      status: 200,
      body: `Successfully processed 'pull_request opened' event and sent message to queue.`
    };
  } catch (err) {
    context.error("Error sending message to Service Bus:", err);
    return {
      status: 500,
      body: "Error processing request"
    };
  }
};

app.http("github-webhook", {
  methods: ["POST"],
  authLevel: "anonymous",
  handler: githubWebhook,
});
