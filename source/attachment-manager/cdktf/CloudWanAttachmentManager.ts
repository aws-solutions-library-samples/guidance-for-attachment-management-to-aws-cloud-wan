import { Construct } from "constructs";
import {
    TerraformStack,
    TerraformHclModule,
    Token,
    Fn,
} from "cdktf";
import { File } from "../.gen/providers/local/file";
import { AwsProvider } from "../.gen/providers/aws/provider";
import { SqsQueue } from "../.gen/providers/aws/sqs-queue";
import { SqsQueuePolicy } from "../.gen/providers/aws/sqs-queue-policy";
import { DataAwsIamPolicyDocument } from "../.gen/providers/aws/data-aws-iam-policy-document";
import { LambdaPermission } from "../.gen/providers/aws/lambda-permission";
import { LambdaEventSourceMapping } from "../.gen/providers/aws/lambda-event-source-mapping";
import { SnsTopicSubscription } from "../.gen/providers/aws/sns-topic-subscription";


export interface CloudWanAttachmentManagerConfig {
    readonly managerName: string;
    readonly snsTopicArn: string;
    readonly snsTopicRegion: string;
    readonly awsAccountReaderRoleArn: string;
    readonly snsSubscriptionAwsProvider: AwsProvider;
    sqsDelaySeconds?: number;
    coreNetworkArn?: string;
    globalNetworkId?: string;
    fullReturnTable?: string;
    segmentAddressingMap?: any;
    ignoreAwsAccounts?: string[];
    processOnlyAwsAccounts?: string[];
    performAttachmentDeletions?: boolean;
}


export class CloudWanAttachmentManager extends Construct {

    // Config Attributes
    id = "";
    parentStack = {} as TerraformStack;
    awsProvider = {} as AwsProvider;
    config = {} as CloudWanAttachmentManagerConfig;
    lambdaModule = {} as TerraformHclModule;


    constructor(scope: Construct, id: string, parentStack: TerraformStack,
        awsProvider: AwsProvider,
        config: CloudWanAttachmentManagerConfig
    ) {
        super(scope, id);
        
        // Store references to the parant stack
        this.id = id;
        this.parentStack = parentStack;
        this.awsProvider = awsProvider;
        this.config = config;
        
        
        // Process Defaults
        if (typeof this.config.sqsDelaySeconds === "undefined" ) { this.config.sqsDelaySeconds = 0; }
        if (typeof this.config.globalNetworkId === "undefined" ) { this.config.globalNetworkId = ""; }
        if (typeof this.config.fullReturnTable === "undefined" ) { this.config.fullReturnTable = ""; }
        if (typeof this.config.segmentAddressingMap === "undefined" ) { this.config.segmentAddressingMap = {}; }
        if (typeof this.config.ignoreAwsAccounts === "undefined" ) { this.config.ignoreAwsAccounts = []; }
        if (typeof this.config.processOnlyAwsAccounts === "undefined" ) { this.config.processOnlyAwsAccounts = []; }
        if (typeof this.config.performAttachmentDeletions === "undefined" ) { this.config.performAttachmentDeletions = true; }


        // Create SQS queue and supporting objects
        let sqsDeadLetter = new SqsQueue(this.parentStack, `${this.id}_sqs_dlq`, {
            provider: this.awsProvider,
            name: `${this.config.managerName}-dlq`,
            fifoQueue: false,
            contentBasedDeduplication: false,
            sqsManagedSseEnabled: true,
        });
        let sqs = new SqsQueue(this.parentStack, `${this.id}_sqs`, {
            provider: this.awsProvider,
            name: this.config.managerName,
            fifoQueue: false,
            contentBasedDeduplication: false,
            sqsManagedSseEnabled: true,
            visibilityTimeoutSeconds: 125,
            redrivePolicy: Token.asString(
                Fn.jsonencode({
                    deadLetterTargetArn: sqsDeadLetter.arn,
                    maxReceiveCount: 3,
                })
            ),
        });
        let sqsPolicy = new DataAwsIamPolicyDocument(this.parentStack, `${this.id}_sqs_policy_doc`, {
            statement: [
                { 
                    sid: "AllowSend",
                    effect: "Allow",
                    actions: ["sqs:SendMessage"],
                    principals: [
                        {
                            type: "AWS",
                            identifiers: ["*"]
                        },
                    ],
                    resources: [sqs.arn],
                    condition: [
                        {
                            test: "ArnEquals",
                            variable: "aws:SourceArn",
                            values: [this.config.snsTopicArn],
                        },
                    ],
                },
            ],
        });
        new SqsQueuePolicy(this.parentStack, `${this.id}_sqs_policy`, {
            provider: this.awsProvider,
            policy: Token.asString(sqsPolicy.json),
            queueUrl: sqs.id,
        });


        // Generate Segment Address Map file and package it with the lambda
        let vpcMapFile = new File(this.parentStack, `${this.id}_vpc_segment_address_map`, {
            filename: "../../../lib/lambda/attachment_manager/vpc_segment_address_map.yml",
            content: Token.asString(`\${
                yamlencode(${this.config.segmentAddressingMap})
            }`),
        });

        // Create lambda using vanilla terraform module
        // https://developer.hashicorp.com/terraform/cdktf/concepts/modules
        this.lambdaModule = new TerraformHclModule(this.parentStack, `${this.id}_module_attachment_manager`, {
            source: "terraform-aws-modules/lambda/aws",
            providers: [this.awsProvider],
            variables: {
                function_name: this.config.managerName,
                handler: "lambda_handler.handler",
                runtime: "python3.9",
                source_path: "../lambda/attachment_manager",
                memory_size: 128,
                timeout: 120,
                attach_policy_json: "true",
                cloudwatch_logs_retention_in_days: 3,
                hash_extra: this.config.managerName,
                environment_variables: {
                    AWS_ACCOUNT_READ_ROLE_ARN: this.config.awsAccountReaderRoleArn,
                    MANAGED_CORE_NETWORK_ARN: this.config.coreNetworkArn,
                    MANAGED_GLOBAL_NETWORK_ID: this.config.globalNetworkId,
                    MANAGED_TGW_ARN: "",
                    FULL_RETURN_TABLE: this.config.fullReturnTable,
                    SQS_URL: Token.asString(sqs.url),
                    SEGMENT_ADDRESSING_FILE: "vpc_segment_address_map.yml",
                    IGNORE_AWS_ACCOUNTS: JSON.stringify(this.config.ignoreAwsAccounts),
                    PROCESS_ONLY_AWS_ACCOUNTS: JSON.stringify(this.config.processOnlyAwsAccounts),
                    PERFORM_ATTACHMENT_DELETIONS: this.config.performAttachmentDeletions,
                    SNS_TOPIC_ARN: this.config.snsTopicArn,
                    SNS_TOPIC_REGION: this.config.snsTopicRegion,
                },
                policy_json: Token.asString(
                    Fn.jsonencode({
                        Version: "2012-10-17",
                        Statement: [
                            {
                                Effect: "Allow",
                                Action: [
                                    "networkmanager:Get*",
                                    "networkmanager:List*",
                                    "networkmanager:DeleteAttachment",
                                    "networkmanager:TagResource",
                                    "networkmanager:GetNetworkRoutes",
                                    "ec2:DescribeRegions"
                                ],
                                Resource: ["*"]
                            },
                            {
                                Effect: "Allow",
                                Action: [
                                    "sts:AssumeRole"
                                ],
                                Resource: [ this.config.awsAccountReaderRoleArn ]
                            },
                            {
                                Effect: "Allow",
                                Action: [
                                    "sqs:ReceiveMessage",
                                    "sqs:SendMessage",
                                    "sqs:DeleteMessage",
                                    "sqs:GetQueueAttributes"
                                ],
                                Resource: [ sqs.arn ]
                            },
                            {
                                Effect: "Allow",
                                Action: [
                                    "sns:Publish"
                                ],
                                Resource: ["*"]
                            }
                        ]
                    })
                ) 
            },
            dependsOn: [vpcMapFile],
        });

        // Allow lambda to read sqs
        new LambdaPermission(this.parentStack, `${this.id}_lambda_allow_sqs`, {
            provider: this.awsProvider,
            statementId: "AllowExecutionFromSQS",
            action: "lambda:InvokeFunction",
            functionName: Token.asString(this.lambdaModule.get("lambda_function_name")),
            principal: "sqs.amazonaws.com",
            sourceArn: sqs.arn,
        });

        new LambdaEventSourceMapping(this.parentStack, `${this.id}_lambda_event_mapping`, {
            provider: this.awsProvider,
            eventSourceArn: sqs.arn,
            functionName: Token.asString(this.lambdaModule.get("lambda_function_name")),
        });

        new SnsTopicSubscription(this.parentStack, `${this.id}_sqs_sns_subscription`, {
            provider: this.config.snsSubscriptionAwsProvider,
            topicArn: this.config.snsTopicArn,
            protocol: "sqs",
            endpoint: sqs.arn,
            filterPolicy: JSON.stringify({
                coreUplinkArn: [ this.config.coreNetworkArn ]
            }),  
        });
    }
}