# **DevSecOps Sentinel: Project Story**

Here are the details for each section of the Devpost project submission page.

### **About the project**

#### **Inspiration**

Our inspiration for DevSecOps Sentinel came from a common pain point in modern software development: the friction between moving fast and staying secure. Security is often seen as a roadblock, a separate step that happens late in the cycle. We wanted to build a tool that makes security a seamless, automated part of the development process itself. The goal was to create a "guardian" that empowers developers by providing immediate, easy-to-understand feedback directly in their workflow (the pull request), turning security from a chore into a collaborative effort. We were inspired by the "shift-left" philosophy and wanted to build a practical, serverless solution that embodies it.

#### **What it does**

DevSecOps Sentinel is an automated, AI-powered security assistant that integrates directly into the GitHub workflow. When a developer opens a pull request, Sentinel automatically triggers a series of security and quality scans on the code changes. It then consolidates the findings into a single, easy-to-read report and posts it as a comment on the pull request, providing immediate, actionable feedback. This helps teams "shift left" on security, catching potential issues like hardcoded secrets before they ever reach the main codebase.

#### **How we built it**

We built DevSecOps Sentinel using a pure, event-driven, serverless architecture on AWS, with all infrastructure defined as code using the AWS SAM framework.

The workflow is as follows:

1. A **GitHub Webhook** fires on a pull request event and sends a payload to our **Amazon API Gateway** endpoint.  
2. The API Gateway triggers a **Lambda function** (WebhookHandlerFunction) that securely validates the webhook's signature using a shared secret stored in **AWS Secrets Manager**.  
3. Upon successful validation, this Lambda starts an **AWS Step Functions** state machine execution, passing along the pull request details.  
4. The state machine uses a "fan-out/fan-in" pattern. A Map state invokes multiple scanner Lambda functions in parallel, allowing for scalable and efficient analysis.  
5. After the parallel scans complete, a final Lambda function (AggregatorFunction) "fans-in" the results. It fetches a GitHub API token from AWS Secrets Manager, formats a professional Markdown report, and posts the report back to the original pull request using the GitHub REST API.  
6. A summary of every scan is logged to an **Amazon DynamoDB** table for a persistent audit trail.

This architecture showcases the power of AWS Lambda for event-driven compute, orchestrated by the resilience and scalability of AWS Step Functions.

#### **Challenges we ran into**

Throughout the development process, we navigated several real-world technical challenges:

* **Webhook Security:** Initially, we struggled with webhook signature validation, leading us to simplify our architecture by integrating the validation logic directly into our primary handler function for a more robust and testable solution.  
* **Data Serialization Bugs:** We encountered a tricky TypeError where our aggregator function failed because it was receiving an already-deserialized JSON object from Step Functions, not the text string it expected. This required careful debugging of CloudWatch logs and implementing more resilient data-handling logic.  
* **Build Tooling Quirks:** We faced a recurring build error where the AWS SAM CLI would fail to find build artifacts during deployment on Windows. We resolved this by adopting a more robust, multi-step deployment process (clean, build, then deploy) to ensure consistency.

#### **Accomplishments that we're proud of**

We are incredibly proud of successfully building a complete, production-worthy, end-to-end serverless application from the ground up in a short amount of time. Specifically:

* **The Complete Feedback Loop:** Seeing our application automatically post a formatted comment back to a live GitHub pull request was a huge accomplishment. It proved our entire architectural vision was sound and functional.  
* **A Robust, Event-Driven Architecture:** We successfully implemented a sophisticated fan-out/fan-in pattern using Step Functions and Lambda, a powerful and scalable serverless design pattern.  
* **Security-First Mindset:** We are proud of building security in from the start, from validating every webhook request to securely managing all our secrets (webhook secrets and API tokens) in AWS Secrets Manager and scoping our IAM permissions to the principle of least privilege.

#### **What we learned**

This project was a deep dive into practical serverless application development. Our key learnings were:

* **The Power of Orchestration:** AWS Step Functions is an indispensable tool for managing complex, multi-step serverless workflows. It provided the resilience, error handling, and parallel processing capabilities that would have been very difficult to build manually.  
* **Infrastructure as Code is Non-Negotiable:** Using AWS SAM to define our entire stack was critical. It allowed us to iterate quickly, maintain consistency, and have a single source of truth for our architecture.  
* **Incremental, Test-Driven Development Works:** Our disciplined approach of building the "plumbing" first with simulators, then replacing them with real logic, allowed us to make steady progress and easily pinpoint issues.

#### **What's next for DevSecOps Sentinel**

The core workflow is complete, but the "brains" of the operation are still simulators. The exciting next steps, as outlined in our project plan, are to implement real intelligence:

1. **Real Secret Scanning:** We will replace the secret scanning simulator with a real implementation that uses the trufflehog binary (packaged in a Lambda Layer) to scan the actual repository code.  
2. **Vulnerability Scanning:** We will build a new scanner function that parses dependency files (like requirements.txt) and uses the safety library to check for known vulnerabilities.  
3. **AI-Powered Code Review:** This is the most innovative feature. We will implement a scanner that sends code to **Amazon Bedrock** with a carefully engineered prompt, allowing an AI model to provide intelligent feedback on code quality, potential bugs, and adherence to best practices.

### **Built With**

* aws-api-gateway  
* aws-dynamodb  
* aws-iam  
* aws-lambda  
* aws-sam  
* aws-secrets-manager  
* aws-step-functions  
* boto3  
* github  
* python  
* requests

### **Try it out links**

For this section, you should provide the links to your GitHub repositories.

* **Application Code Repository:** https://github.com/your-github-username/devsecops-sentinel  
* **Live Demo Repository (Testbed):** https://github.com/your-github-username/sentinel-testbed