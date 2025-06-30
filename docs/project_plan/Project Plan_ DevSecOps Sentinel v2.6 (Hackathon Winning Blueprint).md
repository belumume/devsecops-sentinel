# **Project Plan & Roadmap: DevSecOps Sentinel**

Version: 2.6 (Real Implementation Blueprint)
Date: June 26, 2025
Vision: To win the AWS Lambda Hackathon by creating an automated, AI-powered DevSecOps platform that provides instant, intelligent security and quality analysis on every code change, demonstrating a masterful implementation of event-driven, serverless architecture on AWS.

## **1. Introduction**

### **1.1. Vision & Mission**

*   **Vision:** To create **DevSecOps Sentinel**, a premier, fully serverless platform that empowers development teams to "shift left" on security and code quality. By providing immediate, actionable, and intelligent feedback directly within their workflow, we aim to make secure coding practices seamless and intuitive.
*   **Mission:** To build and deliver a working, polished, and compelling DevSecOps platform for the AWS Lambda Hackathon. The mission is to solve a significant, real-world developer problem using a pure, event-driven serverless architecture that showcases the power and scalability of AWS Lambda, Step Functions, and Bedrock, thereby meeting and exceeding all judging criteria to secure first place.

### **1.2. Goals & Objectives**

*   **Primary Goal:** Win the First Place prize ($6,000) in the AWS Lambda Hackathon.
*   **Key Objectives:**
    *   **Architectural Excellence:** Design and implement a model serverless application that is event-driven, scalable, resilient, and cost-effective.
    *   **Solve a High-Value Problem:** Address the critical need for automated code security and quality analysis in the SDLC.
    *   **Demonstrate Lambda's Power:** Leverage Lambda's core strengths through a massively parallel, fan-out/fan-in processing architecture orchestrated by AWS Step Functions.
    *   **Innovate with AI:** Utilize Amazon Bedrock for a creative, high-value task: intelligent code analysis and quality review.
    *   **Deliver a Winning Submission:** Produce a robust, working end-to-end application, a polished and compelling 3-minute video demonstration, and a professional, detailed README.md.

### **1.3. Scope**

*   **In Scope (Hackathon MVP):**
    *   A serverless backend built entirely on AWS and defined via Infrastructure as Code (AWS SAM).
    *   Integration with GitHub repositories via Webhooks for Pull Request events.
    *   An AWS Step Functions workflow orchestrating the entire analysis pipeline.
    *   A fan-out architecture for parallel code analysis using AWS Lambda.
    *   **Analysis Module 1: Secret Scanning:** Detect hardcoded credentials using **real command-line tools** (e.g., trufflehog).
    *   **Analysis Module 2: Dependency Vulnerability Scanning:** Check `requirements.txt` and `package.json` using **real command-line tools** (e.g., `safety`, `npm audit`).
    *   **Analysis Module 3: AI Code Quality Review:** Use Amazon Bedrock (Claude Sonnet 4) to analyze code for bugs, anti-patterns, and best practice violations.
    *   An aggregator Lambda that consolidates all findings and posts a single, well-structured Markdown comment on the corresponding GitHub Pull Request.
    *   A DynamoDB table for logging scan results for auditing.
*   **Out of Scope (Hackathon MVP):**
    *   Support for other Git providers (e.g., GitLab, Bitbucket).
    *   A complex web-based UI with historical dashboards.
    *   User accounts or authentication.

## **2. Detailed Architecture & Technology**

### **2.1. Architecture Diagram**

graph TD
    subgraph GitHub
        A[Pull Request Event]
    end

    subgraph AWS
        A -- Webhook --> B{API Gateway};
        B --> C[WebhookHandlerFunction];
        C -- "1. Validates Signature<br>2. Starts Execution" --> D["Step Functions Workflow"];

        subgraph D
            direction LR
            E[Start] --> F{Parallel Analysis (Map State)};
            F --> G1[SecretScanner Lambda];
            F --> G2[VulnerabilityScanner Lambda];
            F --> G3[AIReviewer Lambda];
            G1 --> H{Aggregation & Reporting};
            G2 --> H;
            G3 --> H;
            H --> I[Aggregator Lambda];
            I --> J[End];
        end

        I -- "Post Comment (via API)" --> K(GitHub PR);
        I -- "Log Results" --> L[(DynamoDB Audit Table)];
    end

### **2.2. Workflow Breakdown**

The workflow is a streamlined, event-driven process:

1.  **Trigger:** A developer creates a Pull Request. A GitHub Webhook fires.
2.  **Ingestion & Validation:** An Amazon API Gateway endpoint triggers the `WebhookHandlerFunction`.
3.  **Orchestration Kick-off:** The `WebhookHandlerFunction` validates the webhook signature, then starts an AWS Step Functions execution.
4.  **Parallel Analysis (Fan-Out):** The Step Functions Map state invokes the three scanner Lambdas in parallel.
5.  **Aggregation & Reporting (Fan-In):** The `AggregatorFunction` consolidates results, posts a comment to the GitHub PR, and logs to DynamoDB.

### **2.3. Technology Stack Summary**

*   **Cloud Platform:** AWS
*   **IaC Framework:** AWS SAM CLI
*   **Core Services:** AWS Lambda, AWS Step Functions, Amazon API Gateway, Amazon DynamoDB, AWS Secrets Manager, AWS IAM
*   **AI Service:** Amazon Bedrock (Model: anthropic.claude-3-5-sonnet-20240620-v1:0)
*   **Programming Language:** Python 3.11
*   **Key Python Libraries:** boto3, requests, pytest, moto
*   **Scanning Tools:** trufflehog, safety, npm

## **3. Development Roadmap**

### **Phase 1: Core Pipeline & Refactoring (COMPLETE)**

*   **Goal:** Establish the cloud infrastructure, the event-driven flow, and a clean, maintainable codebase.
*   **Tasks:**
    *   [x] **IaC Definition:** `template.yaml` defines all core AWS resources.
    *   [x] **Webhook & Trigger:** `WebhookHandlerFunction` validates signatures and starts the workflow.
    *   [x] **End-to-End Workflow:** A live GitHub PR successfully triggers the full pipeline, which executes and posts a comment back.
    *   [x] **Code Refactoring:** Logging has been standardized, and duplicated code has been moved to a shared utility layer structure.

### **Phase 2: Real Scanner Implementation & Debugging (CURRENT PHASE)**

*   **Goal:** Replace all simulated scanner logic with real-world security tool integrations and resolve critical runtime errors.
*   **Tasks:**
    1.  **CRITICAL BUG: Resolve GitHub API Authentication:** The `SecretScannerFunction` is failing with a `401 Unauthorized` error when trying to download the repository zipball. This indicates the GitHub token being used is invalid or lacks the correct permissions. This is the **highest priority task** and blocks all other progress.
    2.  **Implement Real Vulnerability Scanner:** Rewrite the `VulnerabilityScannerFunction` to execute `safety` (for Python) and `npm audit` (for Node.js) as subprocesses and parse their JSON output.
    3.  **Implement Real Secret Scanner:** Rewrite the `SecretScannerFunction` to clone the target repository using `git` and execute `trufflehog` against the codebase.
    4.  **Create Scanner Lambda Layer:** Package the required binaries (`git`, `trufflehog`, `safety`, `npm`) into a deployable Lambda Layer. This is a critical dependency for the real scanners.

### **Phase 3: Polishing, Documentation, and Submission**

*   **Goal:** Transform the working prototype into a winning hackathon submission.
*   **Tasks:**
    1.  **Refinement & Error Handling:** Add robust error handling for the real tool executions. Polish the formatting of the GitHub comment.
    2.  **Create README.md:** Write the complete, professional README file.
    3.  **Video Production:** Script and record the ~3-minute video demonstration.
    4.  **Final Submission:** Package the code and submit on Devpost.

## **4. Security & Testing**

*   **Security:** Webhook signatures are validated. All secrets are stored in AWS Secrets Manager. IAM roles follow the principle of least privilege.
*   **Testing:** Unit tests are written with `pytest` and `moto`. End-to-end testing is performed by creating pull requests in a dedicated test repository.

## **5. AI Agent Collaboration Rules**

*   **Adherence to Plan:** The agent must follow this project plan.
*   **No Simulations:** All new code must use real integrations and tools. No more mock data or simulated logic.
*   **IaC is Law:** All infrastructure changes must be made in `template.yaml`.
*   **Incremental Execution:** All non-trivial changes must be preceded by a `<plan>` and executed one step at a time with user confirmation.
